//! Named devices on the local network that are advertising to it or exchanging packets with this host.
//!
//! Names come from announcement instances. Packet totals come from the flows those addresses
//! appear in, so several service rows for one device stay a single neighbor.

use std::collections::HashMap;
use std::net::IpAddr;

use pcap::Address;

use crate::networking::announcements::{AnnouncementInfo, AnnouncementKey};
use crate::networking::manage_packets::destination_traffic_type;
use crate::networking::types::address_port_pair::AddressPortPair;
use crate::networking::types::info_address_port_pair::InfoAddressPortPair;
use crate::networking::types::traffic_type::TrafficType;

/// One other device, such as `TV — Hisense Xumo TV` or `AirPlay — mb's macbook`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct KnownNeighbor {
    /// Role and instance, for example `Chromecast — Living Room`.
    pub label: String,
    /// Service types advertised by this device.
    pub services: String,
    /// Addresses observed for the device.
    pub address: String,
    /// Packets this device exchanged with the host, or advertised on the local network.
    pub packets: u128,
    /// Bytes counted alongside [`Self::packets`].
    pub bytes: u128,
}

struct Identity {
    rank: u8,
    role: String,
    instance: String,
    service: String,
    packets: u128,
    bytes: u128,
    addresses: Vec<IpAddr>,
}

/// Devices learned from announcements that are reaching this host or the local network.
pub fn known_neighbors(
    announcements: &HashMap<AnnouncementKey, AnnouncementInfo>,
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
) -> Vec<KnownNeighbor> {
    let identities = identities_of(announcements);
    let mut parent: Vec<usize> = (0..identities.len()).collect();
    for left in 0..identities.len() {
        for right in (left + 1)..identities.len() {
            if shares_address(&identities[left].addresses, &identities[right].addresses) {
                union(&mut parent, left, right);
            }
        }
    }

    let mut clusters: HashMap<usize, Vec<usize>> = HashMap::new();
    for index in 0..identities.len() {
        clusters
            .entry(find(&mut parent, index))
            .or_default()
            .push(index);
    }

    let mut neighbors = Vec::new();
    for indexes in clusters.into_values() {
        if let Some(neighbor) = neighbor_from_cluster(&identities, &indexes, map, local_addresses) {
            neighbors.push(neighbor);
        }
    }
    neighbors.sort_by(|left, right| {
        right
            .packets
            .cmp(&left.packets)
            .then_with(|| left.label.cmp(&right.label))
    });
    neighbors
}

fn identities_of(announcements: &HashMap<AnnouncementKey, AnnouncementInfo>) -> Vec<Identity> {
    announcements
        .iter()
        .filter(|(key, _)| !key.instance.is_empty())
        .map(|(key, info)| {
            let (rank, role) = role_of(&key.service, &key.instance);
            let mut addresses = vec![key.source];
            for address in &info.extra_addresses {
                if !addresses.contains(address) {
                    addresses.push(*address);
                }
            }
            Identity {
                rank,
                role,
                instance: key.instance.clone(),
                service: key.service.clone(),
                packets: info.packets,
                bytes: info.bytes,
                addresses,
            }
        })
        .collect()
}

fn neighbor_from_cluster(
    identities: &[Identity],
    indexes: &[usize],
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
) -> Option<KnownNeighbor> {
    let mut addresses = Vec::new();
    let mut services = Vec::new();
    let mut best: Option<&Identity> = None;
    let mut fallback_packets = 0;
    let mut fallback_bytes = 0;
    for index in indexes {
        let identity = &identities[*index];
        for address in &identity.addresses {
            if !addresses.contains(address) {
                addresses.push(*address);
            }
        }
        if !services.contains(&identity.service) {
            services.push(identity.service.clone());
        }
        fallback_packets = fallback_packets.max(identity.packets);
        fallback_bytes = fallback_bytes.max(identity.bytes);
        let replace = best.is_none_or(|current| {
            identity.rank < current.rank
                || (identity.rank == current.rank && identity.instance < current.instance)
        });
        if replace {
            best = Some(identity);
        }
    }
    let best = best?;
    if !is_other_device(&addresses, local_addresses) {
        return None;
    }

    let (packets, bytes, saw_flow) = traffic_with_us(map, &addresses, local_addresses);
    let (packets, bytes) = if saw_flow {
        if packets == 0 {
            return None;
        }
        (packets, bytes)
    } else {
        (fallback_packets, fallback_bytes)
    };
    if packets == 0 {
        return None;
    }

    services.sort();
    Some(KnownNeighbor {
        label: format!("{} — {}", best.role, best.instance),
        services: services.join(", "),
        address: addresses
            .iter()
            .take(3)
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join(", "),
        packets,
        bytes,
    })
}

fn traffic_with_us(
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    addresses: &[IpAddr],
    local_addresses: &[Address],
) -> (u128, u128, bool) {
    let mut packets = 0;
    let mut bytes = 0;
    let mut saw_flow = false;
    for (key, info) in map {
        let src_neighbor = addresses.contains(&key.src_ip);
        let dst_neighbor = addresses.contains(&key.dst_ip);
        if !src_neighbor && !dst_neighbor {
            continue;
        }
        saw_flow = true;
        if reaches_us(key, src_neighbor, dst_neighbor, local_addresses) {
            packets += info.packets;
            bytes += info.bytes;
        }
    }
    (packets, bytes, saw_flow)
}

fn reaches_us(
    key: &AddressPortPair,
    src_neighbor: bool,
    dst_neighbor: bool,
    local_addresses: &[Address],
) -> bool {
    let src_local = is_local(&key.src_ip, local_addresses);
    let dst_local = is_local(&key.dst_ip, local_addresses);
    if (src_local && dst_neighbor) || (dst_local && src_neighbor) {
        return true;
    }
    if src_neighbor
        && !src_local
        && matches!(
            destination_traffic_type(&key.dst_ip, local_addresses),
            TrafficType::Multicast | TrafficType::Broadcast
        )
    {
        return true;
    }
    local_addresses.is_empty() && (src_neighbor ^ dst_neighbor)
}

fn is_other_device(addresses: &[IpAddr], local_addresses: &[Address]) -> bool {
    local_addresses.is_empty()
        || addresses
            .iter()
            .any(|address| !is_local(address, local_addresses))
}

fn is_local(address: &IpAddr, local_addresses: &[Address]) -> bool {
    local_addresses.iter().any(|local| local.addr == *address)
}

fn shares_address(left: &[IpAddr], right: &[IpAddr]) -> bool {
    left.iter().any(|address| right.contains(address))
}

fn role_of(service: &str, instance: &str) -> (u8, String) {
    let service = service.to_ascii_lowercase();
    let instance = instance.to_ascii_lowercase();
    if service.contains("googlecast") {
        (0, "Chromecast".to_string())
    } else if instance.contains("tv") {
        (1, "TV".to_string())
    } else if service.contains("airplay") || service.contains("raop") {
        (2, "AirPlay".to_string())
    } else if service.contains("companion-link") {
        (3, "Continuity".to_string())
    } else if service.contains("remotepairing") || service.contains("mobdev") {
        (4, "Pairing".to_string())
    } else if service.contains("bambu") || service.contains("printer") {
        (5, "Printer".to_string())
    } else {
        (9, friendly_service(&service))
    }
}

fn friendly_service(service: &str) -> String {
    let trimmed = service.trim_start_matches('_');
    let cut = match trimmed.split("._").next() {
        Some(value) if !value.is_empty() => value,
        _ => trimmed,
    };
    let mut chars = cut.chars();
    match chars.next() {
        Some(first) => first.to_uppercase().collect::<String>() + chars.as_str(),
        None => service.to_string(),
    }
}

fn union(parent: &mut [usize], left: usize, right: usize) {
    let left = find(parent, left);
    let right = find(parent, right);
    if left != right {
        parent[right] = left;
    }
}

fn find(parent: &mut [usize], mut index: usize) -> usize {
    while parent[index] != index {
        parent[index] = parent[parent[index]];
        index = parent[index];
    }
    index
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn local_host() -> Vec<Address> {
        vec![Address {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            broadcast_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))),
            dst_addr: None,
        }]
    }

    fn announced(
        instance: &str,
        service: &str,
        source: [u8; 4],
        packets: u128,
    ) -> (AnnouncementKey, AnnouncementInfo) {
        (
            AnnouncementKey {
                instance: instance.to_string(),
                service: service.to_string(),
                source: IpAddr::V4(Ipv4Addr::from(source)),
            },
            AnnouncementInfo::for_tests(packets, packets * 100),
        )
    }

    fn flow(src: [u8; 4], dst: IpAddr, packets: u128) -> (AddressPortPair, InfoAddressPortPair) {
        (
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::from(src)),
                Some(5353),
                dst,
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets,
                bytes: packets * 80,
                ..Default::default()
            },
        )
    }

    #[test]
    fn named_advertisers_become_one_neighbor_each() {
        let mut announcements = HashMap::new();
        let (tv_key, tv_info) = announced("Hisense Xumo TV", "_airplay._tcp", [192, 168, 1, 50], 5);
        announcements.insert(tv_key, tv_info);
        let (cast_key, cast_info) =
            announced("Living Room", "_googlecast._tcp", [192, 168, 1, 51], 3);
        announcements.insert(cast_key, cast_info);
        let (mac_key, mac_info) = announced("mb's macbook", "_airplay._tcp", [192, 168, 1, 52], 8);
        announcements.insert(mac_key, mac_info);
        let (raop_key, raop_info) = announced("mb's macbook", "_raop._tcp", [192, 168, 1, 52], 8);
        announcements.insert(raop_key, raop_info);

        let mut map = HashMap::new();
        let multicast = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        let (tv_flow, tv_stat) = flow([192, 168, 1, 50], multicast, 5);
        map.insert(tv_flow, tv_stat);
        let (cast_flow, cast_stat) = flow([192, 168, 1, 51], multicast, 3);
        map.insert(cast_flow, cast_stat);
        let (mac_flow, mac_stat) = flow([192, 168, 1, 52], multicast, 8);
        map.insert(mac_flow, mac_stat);
        let (web_flow, web_stat) = flow(
            [192, 168, 1, 171],
            IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
            20,
        );
        map.insert(web_flow, web_stat);

        let neighbors = known_neighbors(&announcements, &map, &local_host());
        let labels: Vec<_> = neighbors
            .iter()
            .map(|neighbor| neighbor.label.as_str())
            .collect();
        assert_eq!(
            labels,
            vec![
                "AirPlay — mb's macbook",
                "TV — Hisense Xumo TV",
                "Chromecast — Living Room",
            ]
        );
        assert_eq!(neighbors[0].packets, 8);
        assert_eq!(neighbors[0].services, "_airplay._tcp, _raop._tcp");
        assert_eq!(neighbors[1].packets, 5);
        assert_eq!(neighbors[2].label, "Chromecast — Living Room");
    }

    #[test]
    fn direct_packets_to_the_host_are_counted_once() {
        let mut announcements = HashMap::new();
        let (key, info) = announced("Hisense Xumo TV", "_airplay._tcp", [192, 168, 1, 50], 4);
        announcements.insert(key, info);
        let (extra_key, extra_info) =
            announced("Hisense Xumo TV", "_raop._tcp", [192, 168, 1, 50], 4);
        announcements.insert(extra_key, extra_info);

        let mut map = HashMap::new();
        let (direct, stat) = flow(
            [192, 168, 1, 50],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            4,
        );
        map.insert(direct, stat);

        let neighbors = known_neighbors(&announcements, &map, &local_host());
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].label, "TV — Hisense Xumo TV");
        assert_eq!(neighbors[0].packets, 4);
    }

    #[test]
    fn traffic_between_other_devices_and_this_host_itself_are_not_neighbors() {
        let mut announcements = HashMap::new();
        let (other_key, other_info) =
            announced("Other Speaker", "_airplay._tcp", [192, 168, 1, 60], 2);
        announcements.insert(other_key, other_info);
        let (self_key, self_info) =
            announced("mb's macbook", "_airplay._tcp", [192, 168, 1, 171], 9);
        announcements.insert(self_key, self_info);

        let mut map = HashMap::new();
        let (side, side_stat) = flow(
            [192, 168, 1, 60],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 80)),
            2,
        );
        map.insert(side, side_stat);
        let multicast = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        let (own, own_stat) = flow([192, 168, 1, 171], multicast, 9);
        map.insert(own, own_stat);

        assert!(known_neighbors(&announcements, &map, &local_host()).is_empty());
    }

    #[test]
    fn a_custom_printer_announcement_is_a_printer_neighbor() {
        let mut announcements = HashMap::new();
        let (key, info) = announced(
            "tsuki-dreams-3DP",
            "urn:bambu-lab:device",
            [192, 168, 1, 149],
            6,
        );
        announcements.insert(key, info);
        let mut map = HashMap::new();
        let (printer, stat) = flow(
            [192, 168, 1, 149],
            IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
            6,
        );
        map.insert(printer, stat);

        let neighbors = known_neighbors(&announcements, &map, &local_host());
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].label, "Printer — tsuki-dreams-3DP");
        assert_eq!(neighbors[0].packets, 6);
    }
}
