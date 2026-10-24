//! Groups every flow on the interface by the purpose of its messages.
//!
//! Announcements are the protocols this build already understands as advertisements.
//! Everything else stays in [`TrafficPurpose::Unknown`], named by the service or
//! message type Sniffnet already recorded, until a dedicated analysis exists.

use crate::Protocol;
use crate::Service;
use crate::networking::types::address_port_pair::AddressPortPair;
use crate::networking::types::info_address_port_pair::InfoAddressPortPair;
use std::collections::HashMap;

/// Label used when a flow has no service name and no recognized message type.
pub const UNKNOWN_GROUP: &str = "Unknown";

/// Why a flow is on the interface, at the level this build can justify.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TrafficPurpose {
    /// Presence advertisements, including DNS-SD and the custom UDP 2021 notices.
    Announcement,
    /// Traffic that does not yet have its own analysis.
    Unknown,
}

/// One named slice of a purpose, such as `https` or an unparsed announcement protocol.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TrafficGroup {
    pub label: String,
    pub packets: u128,
    pub bytes: u128,
}

/// Totals for one purpose, plus the groups that do not have a richer breakdown.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PurposeReport {
    pub purpose: TrafficPurpose,
    pub packets: u128,
    pub bytes: u128,
    /// Announcements omit UDP 5353 and UDP 2021, which the instance table already shows.
    pub groups: Vec<TrafficGroup>,
}

/// UDP ports whose packets exist to advertise a name, service, or device.
fn is_announcement_udp_port(port: u16) -> bool {
    matches!(port, 5353 | 2021 | 1900 | 5355 | 137)
}

/// UDP ports whose payload is already turned into announcement instances.
fn is_parsed_announcement_udp_port(port: u16) -> bool {
    matches!(port, 5353 | 2021)
}

fn either_port(src_port: Option<u16>, dst_port: Option<u16>, pred: fn(u16) -> bool) -> bool {
    src_port.is_some_and(pred) || dst_port.is_some_and(pred)
}

/// Classify one flow. Each flow belongs to exactly one purpose.
pub fn purpose_of(key: &AddressPortPair) -> TrafficPurpose {
    if key.protocol == Protocol::Udp
        && either_port(key.src_port, key.dst_port, is_announcement_udp_port)
    {
        TrafficPurpose::Announcement
    } else {
        TrafficPurpose::Unknown
    }
}

fn is_parsed_announcement(key: &AddressPortPair) -> bool {
    key.protocol == Protocol::Udp
        && either_port(key.src_port, key.dst_port, is_parsed_announcement_udp_port)
}

fn group_label(info: &InfoAddressPortPair) -> String {
    if let Service::Name(name) = info.service {
        return name.to_string();
    }

    let mut best: Option<(usize, String)> = None;
    for (message_type, count) in &info.message_types {
        if *count == 0 {
            continue;
        }
        let label = message_type.to_string();
        if label.is_empty() || label == "?" {
            continue;
        }
        let replace = match &best {
            None => true,
            Some((best_count, best_label)) => {
                *count > *best_count || (*count == *best_count && label < *best_label)
            }
        };
        if replace {
            best = Some((*count, label));
        }
    }
    best.map_or_else(|| UNKNOWN_GROUP.to_string(), |(_, label)| label)
}

fn absorb(groups: &mut HashMap<String, TrafficGroup>, label: String, packets: u128, bytes: u128) {
    groups
        .entry(label.clone())
        .and_modify(|group| {
            group.packets += packets;
            group.bytes += bytes;
        })
        .or_insert(TrafficGroup {
            label,
            packets,
            bytes,
        });
}

fn sorted_groups(groups: HashMap<String, TrafficGroup>) -> Vec<TrafficGroup> {
    let mut groups: Vec<_> = groups.into_values().collect();
    groups.sort_by(|left, right| {
        right
            .packets
            .cmp(&left.packets)
            .then_with(|| left.label.cmp(&right.label))
    });
    groups
}

/// Count every connection once and split it into announcement and unknown.
pub fn report_traffic(map: &HashMap<AddressPortPair, InfoAddressPortPair>) -> Vec<PurposeReport> {
    let mut announcement_packets = 0;
    let mut announcement_bytes = 0;
    let mut unknown_packets = 0;
    let mut unknown_bytes = 0;
    let mut announcement_groups = HashMap::new();
    let mut unknown_groups = HashMap::new();

    for (key, info) in map {
        if purpose_of(key) == TrafficPurpose::Announcement {
            announcement_packets += info.packets;
            announcement_bytes += info.bytes;
            if !is_parsed_announcement(key) {
                absorb(
                    &mut announcement_groups,
                    group_label(info),
                    info.packets,
                    info.bytes,
                );
            }
        } else {
            unknown_packets += info.packets;
            unknown_bytes += info.bytes;
            absorb(
                &mut unknown_groups,
                group_label(info),
                info.packets,
                info.bytes,
            );
        }
    }

    vec![
        PurposeReport {
            purpose: TrafficPurpose::Announcement,
            packets: announcement_packets,
            bytes: announcement_bytes,
            groups: sorted_groups(announcement_groups),
        },
        PurposeReport {
            purpose: TrafficPurpose::Unknown,
            packets: unknown_packets,
            bytes: unknown_bytes,
            groups: sorted_groups(unknown_groups),
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::types::message_type::MessageType;
    use sniffnet_packet_parser::{IcmpType, IcmpTypeV4};
    use std::net::{IpAddr, Ipv4Addr};

    fn flow(service: Service, packets: u128, bytes: u128) -> InfoAddressPortPair {
        InfoAddressPortPair {
            service,
            packets,
            bytes,
            ..Default::default()
        }
    }

    fn udp(dst_port: u16) -> AddressPortPair {
        AddressPortPair::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(50_000),
            IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
            Some(dst_port),
            Protocol::Udp,
        )
    }

    fn tcp(dst_port: u16) -> AddressPortPair {
        AddressPortPair::new(
            IpAddr::V4(Ipv4Addr::LOCALHOST),
            Some(50_000),
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            Some(dst_port),
            Protocol::Tcp,
        )
    }

    #[test]
    fn advertisement_ports_are_announcements_and_other_flows_are_unknown() {
        assert_eq!(purpose_of(&udp(5353)), TrafficPurpose::Announcement);
        assert_eq!(purpose_of(&udp(2021)), TrafficPurpose::Announcement);
        assert_eq!(purpose_of(&udp(1900)), TrafficPurpose::Announcement);
        assert_eq!(purpose_of(&udp(5355)), TrafficPurpose::Announcement);
        assert_eq!(purpose_of(&udp(137)), TrafficPurpose::Announcement);
        assert_eq!(purpose_of(&udp(53)), TrafficPurpose::Unknown);
        assert_eq!(purpose_of(&tcp(443)), TrafficPurpose::Unknown);
        assert_eq!(purpose_of(&tcp(5353)), TrafficPurpose::Unknown);
    }

    #[test]
    fn every_flow_is_counted_once_and_parsed_announcements_are_not_listed_again() {
        let mut map = HashMap::new();
        map.insert(udp(5353), flow(Service::Name("zeroconf"), 4, 400));
        map.insert(udp(1900), flow(Service::Name("ssdp"), 2, 200));
        map.insert(tcp(443), flow(Service::Name("https"), 10, 1000));
        map.insert(tcp(9), flow(Service::Unknown, 1, 50));

        let report = report_traffic(&map);
        assert_eq!(report.len(), 2);

        let announcement = &report[0];
        assert_eq!(announcement.purpose, TrafficPurpose::Announcement);
        assert_eq!(announcement.packets, 6);
        assert_eq!(announcement.bytes, 600);
        assert_eq!(announcement.groups.len(), 1);
        assert_eq!(announcement.groups[0].label, "ssdp");
        assert_eq!(announcement.groups[0].packets, 2);

        let unknown = &report[1];
        assert_eq!(unknown.purpose, TrafficPurpose::Unknown);
        assert_eq!(unknown.packets, 11);
        assert_eq!(unknown.bytes, 1050);
        assert_eq!(unknown.groups[0].label, "https");
        assert_eq!(unknown.groups[0].packets, 10);
        assert_eq!(unknown.groups[1].label, UNKNOWN_GROUP);
        assert_eq!(unknown.groups[1].packets, 1);

        let counted = announcement.packets + unknown.packets;
        let total = map.values().map(|info| info.packets).sum::<u128>();
        assert_eq!(counted, total);
    }

    #[test]
    fn unnamed_flows_use_their_message_type_and_identical_services_merge() {
        let mut echo = flow(Service::NotApplicable, 3, 180);
        echo.message_types
            .insert(MessageType::Icmp(IcmpType::V4(IcmpTypeV4::Echo)), 3);
        let mut map = HashMap::new();
        map.insert(tcp(443), flow(Service::Name("https"), 2, 20));
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                Some(51_000),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                Some(443),
                Protocol::Tcp,
            ),
            flow(Service::Name("https"), 5, 50),
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::LOCALHOST),
                None,
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                None,
                Protocol::Icmpv4,
            ),
            echo,
        );

        let unknown = &report_traffic(&map)[1];
        assert_eq!(unknown.packets, 10);
        assert_eq!(unknown.groups.len(), 2);
        assert_eq!(unknown.groups[0].label, "https");
        assert_eq!(unknown.groups[0].packets, 7);
        assert_eq!(unknown.groups[0].bytes, 70);
        assert_eq!(unknown.groups[1].label, "Echo");
    }
}
