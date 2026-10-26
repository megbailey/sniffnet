//! Packets this computer sent or received on the capture interface.
//!
//! Each row is the other address. Columns match Discovery: instance, address,
//! protocol, traffic type, service, and packets.

use std::collections::{BTreeSet, HashMap};
use std::net::IpAddr;

use pcap::Address;

use crate::networking::announcements::{AnnouncementGroup, AnnouncementInfo, AnnouncementKey};
use crate::networking::manage_packets::{destination_traffic_type, is_my_address};
use crate::networking::types::address_port_pair::AddressPortPair;
use crate::networking::types::info_address_port_pair::InfoAddressPortPair;
use crate::networking::types::traffic_type::TrafficType;
use crate::utils::formatted_strings::mac_from_dec_to_hex;

/// One other address this computer exchanged packets with.
pub fn your_traffic(
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    announcements: &HashMap<AnnouncementKey, AnnouncementInfo>,
    local_addresses: &[Address],
    names: &HashMap<IpAddr, String>,
) -> Vec<AnnouncementGroup> {
    let advertised = advertised_identities(announcements);
    let mut grouped: HashMap<IpAddr, Acc> = HashMap::new();

    for (key, info) in map {
        let Some(remote) = other_address(key, local_addresses) else {
            continue;
        };
        let entry = grouped.entry(remote).or_default();
        entry.protocols.insert(key.protocol.to_string());
        entry.traffic.insert(
            traffic_name(destination_traffic_type(&key.dst_ip, local_addresses)).to_string(),
        );
        let service = info.service.to_string();
        if service != "?" && service != "-" {
            entry.services.insert(service);
        }
        remember_mac(
            &mut entry.macs,
            if is_my_address(&key.src_ip, local_addresses) {
                info.dst_mac
            } else {
                info.src_mac
            },
            info.packets,
        );
        entry.packets = entry.packets.saturating_add(info.packets);
        entry.bytes = entry.bytes.saturating_add(info.bytes);
    }

    let mut rows: Vec<AnnouncementGroup> = grouped
        .into_iter()
        .filter(|(_, acc)| acc.packets > 0)
        .map(|(address, mut acc)| {
            if let Some((instances, services)) = advertised.get(&address) {
                acc.instances.extend(instances.iter().cloned());
                acc.services.extend(services.iter().cloned());
            }
            if acc.instances.is_empty()
                && let Some(name) = names.get(&address)
            {
                acc.instances.insert(name.clone());
            }
            AnnouncementGroup {
                instance: joined(&acc.instances),
                service: joined(&acc.services),
                addresses: address_label(address, &acc.macs),
                protocols: joined(&acc.protocols),
                traffic: joined(&acc.traffic),
                model: String::new(),
                packets: acc.packets,
                bytes: acc.bytes,
            }
        })
        .collect();
    rows.sort_by(|left, right| {
        right
            .packets
            .cmp(&left.packets)
            .then_with(|| left.addresses.cmp(&right.addresses))
    });
    rows
}

#[derive(Default)]
struct Acc {
    protocols: BTreeSet<String>,
    traffic: BTreeSet<String>,
    services: BTreeSet<String>,
    instances: BTreeSet<String>,
    macs: HashMap<[u8; 6], u128>,
    packets: u128,
    bytes: u128,
}

fn other_address(key: &AddressPortPair, local_addresses: &[Address]) -> Option<IpAddr> {
    let src_mine = is_my_address(&key.src_ip, local_addresses);
    let dst_mine = is_my_address(&key.dst_ip, local_addresses);
    match (src_mine, dst_mine) {
        (true, false) => Some(key.dst_ip),
        (false, true) => Some(key.src_ip),
        _ => None,
    }
}

fn advertised_identities(
    announcements: &HashMap<AnnouncementKey, AnnouncementInfo>,
) -> HashMap<IpAddr, (BTreeSet<String>, BTreeSet<String>)> {
    let mut identities: HashMap<IpAddr, (BTreeSet<String>, BTreeSet<String>)> = HashMap::new();
    for (key, info) in announcements {
        remember_identity(&mut identities, key.source, &key.instance, &key.service);
        for extra in &info.extra_addresses {
            remember_identity(&mut identities, *extra, &key.instance, &key.service);
        }
    }
    identities
}

fn remember_identity(
    identities: &mut HashMap<IpAddr, (BTreeSet<String>, BTreeSet<String>)>,
    address: IpAddr,
    instance: &str,
    service: &str,
) {
    let entry = identities.entry(address).or_default();
    if !instance.is_empty() {
        entry.0.insert(instance.to_string());
    }
    if !service.is_empty() {
        entry.1.insert(service.to_string());
    }
}

fn remember_mac(macs: &mut HashMap<[u8; 6], u128>, mac: Option<[u8; 6]>, packets: u128) {
    let Some(mac) = mac else {
        return;
    };
    if mac == [0xff; 6] || mac == [0; 6] {
        return;
    }
    let seen = macs.entry(mac).or_default();
    *seen = seen.saturating_add(packets);
}

fn address_label(address: IpAddr, macs: &HashMap<[u8; 6], u128>) -> String {
    let mac = macs
        .iter()
        .max_by(|left, right| left.1.cmp(right.1).then_with(|| right.0.cmp(left.0)));
    match mac {
        Some((mac, _)) => format!("{address}, {}", mac_from_dec_to_hex(*mac)),
        None => address.to_string(),
    }
}

fn joined(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .join(", ")
}

fn traffic_name(traffic: TrafficType) -> &'static str {
    match traffic {
        TrafficType::Unicast => "unicast",
        TrafficType::Multicast => "multicast",
        TrafficType::Broadcast => "broadcast",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    use crate::Service;
    use crate::networking::announcements::AnnouncementInfo;
    use crate::networking::types::traffic_type::TrafficType;

    fn local_host() -> Vec<Address> {
        vec![Address {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            broadcast_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))),
            dst_addr: None,
        }]
    }

    fn me() -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171))
    }

    #[test]
    fn packets_to_and_from_this_computer_share_one_row() {
        let other = IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1));
        let mac = [1, 2, 3, 4, 5, 6];
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(me(), Some(50_000), other, Some(443), crate::Protocol::Tcp),
            InfoAddressPortPair {
                packets: 4,
                bytes: 400,
                service: Service::Name("https"),
                dst_mac: Some(mac),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(other, Some(443), me(), Some(50_000), crate::Protocol::Tcp),
            InfoAddressPortPair {
                packets: 3,
                bytes: 300,
                service: Service::Name("https"),
                src_mac: Some(mac),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 60)),
                Some(1),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 80)),
                Some(2),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 9,
                bytes: 90,
                ..Default::default()
            },
        );

        let rows = your_traffic(&map, &HashMap::new(), &local_host(), &HashMap::new());

        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].addresses, "1.1.1.1, 01:02:03:04:05:06");
        assert_eq!(rows[0].protocols, "TCP");
        assert_eq!(rows[0].traffic, "unicast");
        assert_eq!(rows[0].service, "https");
        assert_eq!(rows[0].packets, 7);
        assert_eq!(rows[0].bytes, 700);
        assert!(rows[0].instance.is_empty());
    }

    #[test]
    fn a_neighbor_keeps_its_announcement_and_a_multicast_send_is_listed() {
        let tv = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 50));
        let mut announcements = HashMap::new();
        announcements.insert(
            AnnouncementKey {
                instance: "Hisense Xumo TV".to_string(),
                service: "_airplay._tcp".to_string(),
                source: tv,
                traffic: TrafficType::Multicast,
            },
            AnnouncementInfo::for_tests(2, 200),
        );
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(tv, Some(7000), me(), Some(7000), crate::Protocol::Udp),
            InfoAddressPortPair {
                packets: 5,
                bytes: 500,
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                me(),
                Some(5353),
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 8,
                bytes: 800,
                service: Service::Name("mdns"),
                ..Default::default()
            },
        );
        let mut names = HashMap::new();
        names.insert(tv, "hisense.local".to_string());

        let rows = your_traffic(&map, &announcements, &local_host(), &names);

        assert_eq!(rows.len(), 2);
        let tv_row = rows
            .iter()
            .find(|row| row.addresses == "192.168.1.50")
            .unwrap();
        assert_eq!(tv_row.instance, "Hisense Xumo TV");
        assert_eq!(tv_row.service, "_airplay._tcp");
        assert_eq!(tv_row.packets, 5);
        let mdns = rows
            .iter()
            .find(|row| row.addresses == "224.0.0.251")
            .unwrap();
        assert_eq!(mdns.traffic, "multicast");
        assert_eq!(mdns.service, "mdns");
        assert_eq!(mdns.protocols, "UDP");
        assert_eq!(mdns.packets, 8);
    }
}
