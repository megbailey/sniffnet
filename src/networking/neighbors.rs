//! Local devices that originate traffic on this interface.
//!
//! A neighbor is any address on this network other than the host itself. Announcement
//! instances, hostnames, and a few well-known roles supply the label.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::IpAddr;

use pcap::Address;
use sniffnet_packet_parser::Protocol;

use crate::networking::announcements::{AnnouncementInfo, AnnouncementKey};
use crate::networking::manage_packets::{
    destination_traffic_type, is_local_connection, is_my_address,
};
use crate::networking::types::address_port_pair::AddressPortPair;
use crate::networking::types::info_address_port_pair::InfoAddressPortPair;
use crate::networking::types::traffic_type::TrafficType;
use crate::utils::formatted_strings::mac_from_dec_to_hex;

/// One other device on this network, such as `Router — 192.168.1.254` or `kikkomanpad.local`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocalNeighbor {
    /// Role and instance, for example `Chromecast — Living Room`.
    pub label: String,
    /// Service types advertised by this device.
    pub services: String,
    /// Packet protocols this device used, such as `UDP, ARP`.
    pub protocols: String,
    /// Unicast, multicast, or broadcast.
    pub traffic_types: String,
    /// Addresses observed for the device.
    pub address: String,
    /// Packets this device exchanged with the host, or advertised on the local network.
    pub packets: u128,
    /// Bytes counted alongside [`Self::packets`].
    pub bytes: u128,
}

#[derive(Default)]
struct Bucket {
    services: BTreeSet<String>,
    protocols: BTreeSet<String>,
    traffic_types: BTreeSet<String>,
    packets: u128,
    bytes: u128,
    rank: u8,
    role: String,
    instance: String,
}

impl Bucket {
    fn note_protocol(&mut self, protocol: Protocol) {
        self.protocols.insert(protocol.to_string());
    }

    fn note_traffic_type(&mut self, kind: &str) {
        if !kind.is_empty() {
            self.traffic_types.insert(kind.to_string());
        }
    }

    fn note_service(&mut self, service: &str, rank: u8, role: &str, instance: &str) {
        if !service.is_empty() {
            self.services.insert(service.to_string());
        }
        if instance.is_empty() {
            return;
        }
        let replace = self.instance.is_empty()
            || rank < self.rank
            || (rank == self.rank && instance < self.instance.as_str());
        if replace {
            self.rank = rank;
            self.role = role.to_string();
            self.instance = instance.to_string();
        }
    }

    fn add_traffic(&mut self, packets: u128, bytes: u128) {
        self.packets = self.packets.saturating_add(packets);
        self.bytes = self.bytes.saturating_add(bytes);
    }

    fn absorb(&mut self, other: &Self) {
        self.services.extend(other.services.iter().cloned());
        self.protocols.extend(other.protocols.iter().cloned());
        self.traffic_types
            .extend(other.traffic_types.iter().cloned());
        self.add_traffic(other.packets, other.bytes);
        self.note_service("", other.rank, &other.role, &other.instance);
    }
}

/// Every other device on this network that appears in the capture, including this computer.
///
/// Rows that share an IPv4 address and MAC are one neighbor, and their traffic names are joined.
/// An address that sends ARP is included with no IPv4 of its own. Repeated ARP that never gets a
/// reply stays in Discovery instead of becoming a neighbor.
/// `names` maps an address to a hostname such as `kikkomanpad.local`.
pub fn local_neighbors(
    announcements: &HashMap<AnnouncementKey, AnnouncementInfo>,
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
    names: &HashMap<IpAddr, String>,
) -> Vec<LocalNeighbor> {
    let mut rows: HashMap<(IpAddr, Option<[u8; 6]>), Bucket> = HashMap::new();
    let mut device_names: HashMap<IpAddr, HashSet<String>> = HashMap::new();
    let mut linked_addresses: HashMap<IpAddr, HashSet<IpAddr>> = HashMap::new();

    for (key, info) in announcements {
        if !is_neighbor_address(&key.source, local_addresses) {
            continue;
        }
        let (rank, role) = role_of(&key.service, &key.instance);
        let mac = key.source.is_ipv4().then(|| info.source_mac()).flatten();
        let bucket = rows.entry((key.source, mac)).or_default();
        bucket.note_service(&key.service, rank, &role, &key.instance);
        bucket.note_traffic_type(traffic_label(key.traffic));
        note_device_name(&mut device_names, key.source, &key.instance);
        for extra in &info.extra_addresses {
            note_device_name(&mut device_names, *extra, &key.instance);
            linked_addresses
                .entry(key.source)
                .or_default()
                .insert(*extra);
            linked_addresses
                .entry(*extra)
                .or_default()
                .insert(key.source);
        }
    }

    let notes = record_flows(&mut rows, map, local_addresses);
    for (address, hostname) in names {
        note_device_name(&mut device_names, *address, hostname);
    }

    let rows = fold_bare_macs(rows);
    let confirmed: HashSet<IpAddr> = notes
        .probed
        .intersection(&notes.responded)
        .copied()
        .collect();
    let rows = merge_non_ipv4(
        rows,
        &confirmed,
        &notes.frame_macs,
        &device_names,
        &linked_addresses,
    );
    let rows = fold_discovery_macs(rows);
    let mut neighbors = Vec::new();
    for ((address, mac), bucket) in rows {
        if bucket.packets == 0 {
            continue;
        }
        neighbors.push(LocalNeighbor {
            label: neighbor_label(
                &bucket.role,
                &bucket.instance,
                names.get(&address),
                &address,
                local_addresses,
            ),
            services: joined(&bucket.services),
            protocols: joined(&bucket.protocols),
            traffic_types: joined(&bucket.traffic_types),
            address: format_pair(address, mac),
            packets: bucket.packets,
            bytes: bucket.bytes,
        });
    }
    neighbors.sort_by(|left, right| {
        right
            .packets
            .cmp(&left.packets)
            .then_with(|| left.label.cmp(&right.label))
            .then_with(|| left.services.cmp(&right.services))
            .then_with(|| left.address.cmp(&right.address))
    });
    neighbors
}

struct FlowNotes {
    frame_macs: HashMap<IpAddr, HashSet<[u8; 6]>>,
    probed: HashSet<IpAddr>,
    responded: HashSet<IpAddr>,
}

fn record_flows(
    rows: &mut HashMap<(IpAddr, Option<[u8; 6]>), Bucket>,
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
) -> FlowNotes {
    let sources: HashSet<IpAddr> = map.keys().map(|key| key.src_ip).collect();
    let mut frame_macs: HashMap<IpAddr, HashSet<[u8; 6]>> = HashMap::new();
    let mut probed = HashSet::new();
    let mut responded = HashSet::new();
    for (key, info) in map {
        if key.dst_ip.is_ipv4() && is_neighbor_address(&key.dst_ip, local_addresses) {
            probed.insert(key.dst_ip);
        }
        if key.src_ip.is_ipv4() && is_neighbor_address(&key.src_ip, local_addresses) {
            responded.insert(key.src_ip);
        }
        for (address, mac) in [(key.src_ip, info.src_mac), (key.dst_ip, info.dst_mac)] {
            if let Some(mac) = mac
                && !is_discovery_mac(mac)
            {
                frame_macs.entry(address).or_default().insert(mac);
            }
            if !sources.contains(&address) || !is_neighbor_address(&address, local_addresses) {
                continue;
            }
            let mac = address.is_ipv4().then_some(mac).flatten();
            let bucket = rows.entry((address, mac)).or_default();
            bucket.add_traffic(info.packets, info.bytes);
            bucket.note_protocol(key.protocol);
            bucket.note_traffic_type(traffic_label(destination_traffic_type(
                &key.dst_ip,
                local_addresses,
            )));
        }
    }
    FlowNotes {
        frame_macs,
        probed,
        responded,
    }
}

fn joined(values: &BTreeSet<String>) -> String {
    values.iter().cloned().collect::<Vec<_>>().join(", ")
}

fn note_device_name(names: &mut HashMap<IpAddr, HashSet<String>>, address: IpAddr, name: &str) {
    if let Some(name) = normalize_device_name(name) {
        names.entry(address).or_default().insert(name);
    }
}

/// Instance and hostname compared without case or a trailing `.local`.
fn normalize_device_name(name: &str) -> Option<String> {
    let mut trimmed = name
        .trim()
        .trim_end_matches('.')
        .to_ascii_lowercase()
        .replace('\u{2019}', "'");
    if let Some(without_local) = trimmed.strip_suffix(".local") {
        trimmed = without_local.to_string();
    }
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

/// A probed IPv4 that also answered is one device. Its IPv6 and other non-IPv4 rows join that record.
fn merge_non_ipv4(
    mut rows: HashMap<(IpAddr, Option<[u8; 6]>), Bucket>,
    confirmed: &HashSet<IpAddr>,
    macs: &HashMap<IpAddr, HashSet<[u8; 6]>>,
    names: &HashMap<IpAddr, HashSet<String>>,
    linked: &HashMap<IpAddr, HashSet<IpAddr>>,
) -> HashMap<(IpAddr, Option<[u8; 6]>), Bucket> {
    let non_ipv4: Vec<_> = rows
        .keys()
        .filter(|(address, _)| !address.is_ipv4())
        .copied()
        .collect();
    for key in non_ipv4 {
        let Some(ipv4) = confirmed_match(key.0, confirmed, macs, names, linked) else {
            continue;
        };
        let Some(bucket) = rows.remove(&key) else {
            continue;
        };
        let target = discovery_key(&rows, ipv4, macs.get(&key.0));
        rows.entry(target).or_default().absorb(&bucket);
    }
    rows
}

fn confirmed_match(
    address: IpAddr,
    confirmed: &HashSet<IpAddr>,
    macs: &HashMap<IpAddr, HashSet<[u8; 6]>>,
    names: &HashMap<IpAddr, HashSet<String>>,
    linked: &HashMap<IpAddr, HashSet<IpAddr>>,
) -> Option<IpAddr> {
    let mut by_mac = Vec::new();
    let mut by_name = Vec::new();
    for ipv4 in confirmed {
        let same_mac = macs.get(&address).is_some_and(|left| {
            macs.get(ipv4)
                .is_some_and(|right| left.iter().any(|mac| right.contains(mac)))
        });
        if same_mac {
            by_mac.push(*ipv4);
            continue;
        }
        let same_name = names.get(&address).is_some_and(|left| {
            names
                .get(ipv4)
                .is_some_and(|right| left.iter().any(|name| right.contains(name)))
        });
        let same_record = linked
            .get(&address)
            .is_some_and(|others| others.contains(ipv4));
        if same_name || same_record {
            by_name.push(*ipv4);
        }
    }
    let mut found = if by_mac.is_empty() { by_name } else { by_mac };
    found.sort_by_key(|ip| match ip {
        IpAddr::V4(ip) => u32::from(*ip),
        IpAddr::V6(_) => u32::MAX,
    });
    found.first().copied()
}

fn discovery_key(
    rows: &HashMap<(IpAddr, Option<[u8; 6]>), Bucket>,
    ipv4: IpAddr,
    other_macs: Option<&HashSet<[u8; 6]>>,
) -> (IpAddr, Option<[u8; 6]>) {
    let mut keys: Vec<_> = rows
        .keys()
        .filter(|(address, _)| *address == ipv4)
        .copied()
        .collect();
    keys.sort_by_key(|(_, mac)| mac.map_or(u64::MAX, u64_from_mac));
    if let Some(macs) = other_macs
        && let Some(key) = keys
            .iter()
            .find(|(_, mac)| mac.is_some_and(|mac| macs.contains(&mac)))
    {
        return *key;
    }
    if let Some(key) = keys.iter().find(|(_, mac)| mac.is_some()) {
        return *key;
    }
    keys.first().copied().unwrap_or((ipv4, None))
}

/// Traffic seen without a MAC joins the only MAC for that IPv4 address.
fn fold_bare_macs(
    rows: HashMap<(IpAddr, Option<[u8; 6]>), Bucket>,
) -> HashMap<(IpAddr, Option<[u8; 6]>), Bucket> {
    let mut macs_for_ip: HashMap<IpAddr, Vec<[u8; 6]>> = HashMap::new();
    for (address, mac) in rows.keys() {
        if let Some(mac) = mac
            && !is_discovery_mac(*mac)
        {
            macs_for_ip.entry(*address).or_default().push(*mac);
        }
    }
    let mut folded: HashMap<(IpAddr, Option<[u8; 6]>), Bucket> = HashMap::new();
    for ((address, mac), bucket) in rows {
        let macs = macs_for_ip
            .get(&address)
            .map_or([].as_slice(), Vec::as_slice);
        if mac.is_none() && macs.len() == 1 {
            folded
                .entry((address, Some(macs[0])))
                .or_default()
                .absorb(&bucket);
        } else {
            folded.entry((address, mac)).or_default().absorb(&bucket);
        }
    }
    folded
}

fn is_discovery_mac(mac: [u8; 6]) -> bool {
    mac == [0xff; 6]
}

/// A broadcast discovery MAC is not its own device. Fold it into the named address when one exists.
fn fold_discovery_macs(
    mut rows: HashMap<(IpAddr, Option<[u8; 6]>), Bucket>,
) -> HashMap<(IpAddr, Option<[u8; 6]>), Bucket> {
    let discovery_keys: Vec<_> = rows
        .keys()
        .filter(|(_, mac)| mac.is_some_and(is_discovery_mac))
        .copied()
        .collect();
    for key in discovery_keys {
        let Some(bucket) = rows.remove(&key) else {
            continue;
        };
        let home = discovery_home(&rows, key.0).unwrap_or((key.0, None));
        rows.entry(home).or_default().absorb(&bucket);
    }
    rows
}

fn discovery_home(
    rows: &HashMap<(IpAddr, Option<[u8; 6]>), Bucket>,
    ipv4: IpAddr,
) -> Option<(IpAddr, Option<[u8; 6]>)> {
    let mut keys: Vec<_> = rows
        .keys()
        .filter(|(address, mac)| *address == ipv4 && !mac.is_some_and(is_discovery_mac))
        .copied()
        .collect();
    keys.sort_by(|left, right| {
        let left_bucket = rows.get(left);
        let right_bucket = rows.get(right);
        let left_named = left_bucket.is_some_and(|bucket| !bucket.instance.is_empty());
        let right_named = right_bucket.is_some_and(|bucket| !bucket.instance.is_empty());
        right_named.cmp(&left_named).then_with(|| {
            right_bucket
                .map_or(0, |bucket| bucket.packets)
                .cmp(&left_bucket.map_or(0, |bucket| bucket.packets))
        })
    });
    keys.first().copied()
}

/// Hostname to show for an address, ignoring values that are only the address itself.
pub fn neighbor_name(rdns: &str, domain: &str) -> Option<String> {
    [rdns, domain]
        .into_iter()
        .find(|value| !value.is_empty() && value.parse::<IpAddr>().is_err())
        .map(|value| value.trim_end_matches('.').to_string())
}

fn format_pair(address: IpAddr, mac: Option<[u8; 6]>) -> String {
    match (address, mac) {
        (IpAddr::V4(ip), Some(mac)) => format!("{ip}, {}", mac_from_dec_to_hex(mac)),
        (address, _) => address.to_string(),
    }
}

fn neighbor_label(
    role: &str,
    instance: &str,
    hostname: Option<&String>,
    address: &IpAddr,
    local_addresses: &[Address],
) -> String {
    if !instance.is_empty() {
        return format!("{role} — {instance}");
    }
    if let Some(name) = hostname {
        return label_for_hostname(name);
    }
    if is_gateway(address, local_addresses) {
        format!("Router — {address}")
    } else {
        address.to_string()
    }
}

fn label_for_hostname(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    if lower.contains("iphone") {
        format!("iPhone — {name}")
    } else if lower.contains("ipad") {
        format!("iPad — {name}")
    } else {
        name.to_string()
    }
}

pub(crate) fn on_this_network(address: &IpAddr, local_addresses: &[Address]) -> bool {
    if !is_remote_host(address, local_addresses) {
        return false;
    }
    if local_addresses.is_empty() {
        return false;
    }
    is_local_connection(address, local_addresses)
}

/// A device address worth listing, including this computer's own interface address.
fn is_neighbor_address(address: &IpAddr, local_addresses: &[Address]) -> bool {
    if address.is_loopback() {
        return false;
    }
    if is_my_address(address, local_addresses) {
        return !address.is_multicast() && !address.is_unspecified();
    }
    on_this_network(address, local_addresses)
}

fn is_remote_host(address: &IpAddr, local_addresses: &[Address]) -> bool {
    !(address.is_multicast()
        || address.is_unspecified()
        || is_my_address(address, local_addresses)
        || matches!(
            destination_traffic_type(address, local_addresses),
            TrafficType::Broadcast
        ))
}

pub(crate) fn is_gateway(address: &IpAddr, local_addresses: &[Address]) -> bool {
    let IpAddr::V4(ipv4) = address else {
        return false;
    };
    let last = ipv4.octets()[3];
    (last == 1 || last == 254) && is_local_connection(address, local_addresses)
}

fn u64_from_mac(mac: [u8; 6]) -> u64 {
    u64::from(mac[0]) << 40
        | u64::from(mac[1]) << 32
        | u64::from(mac[2]) << 24
        | u64::from(mac[3]) << 16
        | u64::from(mac[4]) << 8
        | u64::from(mac[5])
}

fn traffic_label(traffic: TrafficType) -> &'static str {
    match traffic {
        TrafficType::Unicast => "unicast",
        TrafficType::Multicast => "multicast",
        TrafficType::Broadcast => "broadcast",
    }
}

fn role_of(service: &str, instance: &str) -> (u8, String) {
    let service = service.to_ascii_lowercase();
    let instance = instance.to_ascii_lowercase();
    if service.contains("googlecast") {
        (0, "Chromecast".to_string())
    } else if instance.contains("tv") {
        (1, "TV".to_string())
    } else if instance.contains("iphone")
        || service.contains("remotepairing")
        || service.contains("mobdev")
    {
        (2, "iPhone".to_string())
    } else if service.contains("airplay") || service.contains("raop") {
        (3, "AirPlay".to_string())
    } else if service.contains("companion-link") {
        (4, "Continuity".to_string())
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
                traffic: crate::networking::types::traffic_type::TrafficType::Multicast,
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

        let neighbors = local_neighbors(&announcements, &map, &local_host(), &HashMap::new());
        let labels: Vec<_> = neighbors
            .iter()
            .map(|neighbor| neighbor.label.as_str())
            .collect();
        assert_eq!(
            labels,
            vec![
                "192.168.1.171",
                "AirPlay — mb's macbook",
                "TV — Hisense Xumo TV",
                "Chromecast — Living Room",
            ]
        );
        let macbook = neighbors
            .iter()
            .find(|neighbor| neighbor.address == "192.168.1.52")
            .unwrap();
        assert_eq!(macbook.packets, 8);
        assert_eq!(macbook.services, "_airplay._tcp, _raop._tcp");
        assert_eq!(macbook.protocols, "UDP");
        assert_eq!(macbook.traffic_types, "multicast");
        assert_eq!(neighbors[2].packets, 5);
        assert_eq!(neighbors[3].label, "Chromecast — Living Room");
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

        let neighbors = local_neighbors(&announcements, &map, &local_host(), &HashMap::new());
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].label, "TV — Hisense Xumo TV");
        assert_eq!(neighbors[0].packets, 4);
        assert_eq!(neighbors[0].services, "_airplay._tcp, _raop._tcp");
        assert_eq!(neighbors[0].protocols, "UDP");
        assert_eq!(neighbors[0].traffic_types, "multicast, unicast");
    }

    #[test]
    fn lan_peers_and_this_host_are_listed() {
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

        let neighbors = local_neighbors(&announcements, &map, &local_host(), &HashMap::new());
        let labels: Vec<_> = neighbors
            .iter()
            .map(|neighbor| neighbor.label.as_str())
            .collect();
        assert_eq!(
            labels,
            vec!["AirPlay — mb's macbook", "AirPlay — Other Speaker"]
        );
        assert!(
            neighbors
                .iter()
                .any(|neighbor| neighbor.address == "192.168.1.171")
        );
    }

    #[test]
    fn hostnames_and_gateways_are_local_neighbors() {
        let mut map = HashMap::new();
        let (pad, pad_stat) = flow(
            [192, 168, 1, 40],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            3,
        );
        map.insert(pad, pad_stat);
        let (router, router_stat) = flow(
            [192, 168, 1, 254],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            7,
        );
        map.insert(router, router_stat);
        let (phone, phone_stat) = flow(
            [192, 168, 1, 87],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            2,
        );
        map.insert(phone, phone_stat);

        let mut names = HashMap::new();
        names.insert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 40)),
            "kikkomanpad.local".to_string(),
        );
        names.insert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 87)),
            "megan-iphone.local".to_string(),
        );

        let neighbors = local_neighbors(&HashMap::new(), &map, &local_host(), &names);
        let labels: Vec<_> = neighbors
            .iter()
            .map(|neighbor| neighbor.label.as_str())
            .collect();
        assert_eq!(
            labels,
            vec![
                "Router — 192.168.1.254",
                "kikkomanpad.local",
                "iPhone — megan-iphone.local",
            ]
        );
        assert_eq!(neighbors[0].packets, 7);
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

        let neighbors = local_neighbors(&announcements, &map, &local_host(), &HashMap::new());
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].label, "Printer — tsuki-dreams-3DP");
        assert_eq!(neighbors[0].packets, 6);
    }

    #[test]
    fn one_device_keeps_every_address_together() {
        let mut announcements = HashMap::new();
        let (v4_key, v4_info) =
            announced("mb's macbook", "_companion-link._tcp", [192, 168, 1, 52], 4);
        announcements.insert(v4_key, v4_info);
        let link_local = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 4));
        announcements.insert(
            AnnouncementKey {
                instance: "mb's macbook".to_string(),
                service: "_companion-link._tcp".to_string(),
                source: link_local,
                traffic: crate::networking::types::traffic_type::TrafficType::Multicast,
            },
            AnnouncementInfo::for_tests(4, 400),
        );

        let mut map = HashMap::new();
        let multicast = IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251));
        let (v4_flow, v4_stat) = flow([192, 168, 1, 52], multicast, 4);
        map.insert(v4_flow, v4_stat);
        map.insert(
            AddressPortPair::new(
                link_local,
                Some(5353),
                multicast,
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 3,
                bytes: 240,
                ..Default::default()
            },
        );
        let (named, named_stat) = flow(
            [192, 168, 1, 53],
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            2,
        );
        map.insert(named, named_stat);

        let mut local = local_host();
        local.push(Address {
            addr: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            netmask: Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            broadcast_addr: None,
            dst_addr: None,
        });
        let mut names = HashMap::new();
        names.insert(
            IpAddr::V4(Ipv4Addr::new(192, 168, 1, 53)),
            "mb's macbook.local".to_string(),
        );

        let neighbors = local_neighbors(&announcements, &map, &local, &names);
        assert_eq!(neighbors.len(), 3);
        let continuity = neighbors
            .iter()
            .find(|neighbor| neighbor.address == "192.168.1.52")
            .unwrap();
        assert_eq!(continuity.label, "Continuity — mb's macbook");
        assert_eq!(continuity.services, "_companion-link._tcp");
        assert_eq!(continuity.protocols, "UDP");
        assert_eq!(continuity.traffic_types, "multicast");
        assert_eq!(continuity.packets, 4);
        let hostname = neighbors
            .iter()
            .find(|neighbor| neighbor.address == "192.168.1.53")
            .unwrap();
        assert_eq!(hostname.label, "mb's macbook.local");
        assert_eq!(hostname.packets, 2);
        assert!(
            neighbors
                .iter()
                .any(|neighbor| neighbor.address.contains("fe80::") && neighbor.packets == 3)
        );
    }

    #[test]
    fn a_neighbor_pairs_one_ipv4_with_its_mac_per_service() {
        let mut announcements = HashMap::new();
        let (airplay_key, airplay_info) =
            announced("mb's macbook", "_airplay._tcp", [192, 168, 1, 52], 4);
        announcements.insert(airplay_key, airplay_info);
        let (raop_key, raop_info) = announced("mb's macbook", "_raop._tcp", [192, 168, 1, 52], 4);
        announcements.insert(raop_key, raop_info);

        let mut map = HashMap::new();
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 52)),
                Some(5353),
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 4,
                bytes: 320,
                src_mac: Some(mac),
                ..Default::default()
            },
        );

        let neighbors = local_neighbors(&announcements, &map, &local_host(), &HashMap::new());
        assert_eq!(neighbors.len(), 1);
        assert_eq!(neighbors[0].address, "192.168.1.52, aa:bb:cc:dd:ee:ff");
        assert_eq!(neighbors[0].packets, 4);
        assert_eq!(neighbors[0].services, "_airplay._tcp, _raop._tcp");
        assert_eq!(neighbors[0].protocols, "UDP");
        assert_eq!(neighbors[0].traffic_types, "multicast");
    }

    #[test]
    fn a_probe_and_reply_merge_the_non_ipv4_record() {
        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x11];
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                Some(5353),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 52)),
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 1,
                bytes: 40,
                dst_mac: Some(mac),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 52)),
                Some(5353),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 4,
                bytes: 200,
                src_mac: Some(mac),
                ..Default::default()
            },
        );
        let link_local = IpAddr::V6(std::net::Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 4));
        map.insert(
            AddressPortPair::new(
                link_local,
                Some(5353),
                IpAddr::V4(Ipv4Addr::new(224, 0, 0, 251)),
                Some(5353),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 3,
                bytes: 90,
                src_mac: Some(mac),
                ..Default::default()
            },
        );

        let mut local = local_host();
        local.push(Address {
            addr: IpAddr::V6(std::net::Ipv6Addr::LOCALHOST),
            netmask: Some(IpAddr::V6(std::net::Ipv6Addr::new(
                0xffff, 0xffff, 0xffff, 0xffff, 0, 0, 0, 0,
            ))),
            broadcast_addr: None,
            dst_addr: None,
        });
        let neighbors = local_neighbors(&HashMap::new(), &map, &local, &HashMap::new());
        assert!(
            neighbors
                .iter()
                .all(|neighbor| !neighbor.address.contains("fe80"))
        );
        let device = neighbors
            .iter()
            .find(|neighbor| neighbor.address.starts_with("192.168.1.52"))
            .unwrap();
        assert_eq!(device.address, "192.168.1.52, aa:bb:cc:dd:ee:11");
        assert_eq!(device.packets, 8);
    }

    #[test]
    fn a_discovery_mac_folds_into_the_named_neighbor_and_a_silent_probe_is_omitted() {
        let real = [0x20, 0x0d, 0x3d, 0xfc, 0xcf, 0xcb];
        let discovery = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut announcements = HashMap::new();
        let (key, info) = announced(
            "tsuki-dreams-3DP",
            "urn:bambu-lab:device",
            [192, 168, 1, 149],
            6,
        );
        announcements.insert(key, info);

        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 149)),
                Some(2021),
                IpAddr::V4(Ipv4Addr::new(255, 255, 255, 255)),
                Some(2021),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 6,
                bytes: 240,
                src_mac: Some(real),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(9),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 149)),
                Some(9),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 2,
                bytes: 80,
                dst_mac: Some(discovery),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(9),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 180)),
                Some(9),
                crate::Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 1,
                bytes: 40,
                dst_mac: Some(discovery),
                ..Default::default()
            },
        );

        let neighbors = local_neighbors(&announcements, &map, &local_host(), &HashMap::new());
        let printer = neighbors
            .iter()
            .find(|neighbor| neighbor.label == "Printer — tsuki-dreams-3DP")
            .unwrap();
        assert_eq!(printer.address, "192.168.1.149, 20:0d:3d:fc:cf:cb");
        assert_eq!(printer.packets, 8);
        assert!(!printer.address.contains("ff:ff:ff:ff:ff:ff"));
        assert!(
            neighbors
                .iter()
                .any(|neighbor| neighbor.address == "192.168.1.171")
        );
    }

    #[test]
    fn an_arp_reply_without_ipv4_is_a_neighbor_and_a_one_shot_probe_is_not() {
        use crate::networking::types::message_type::MessageType;
        use crate::utils::types::timestamp::Timestamp;
        use sniffnet_packet_parser::ArpType;

        let mac = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10];
        let mut map = HashMap::new();
        let mut reply_types = HashMap::new();
        reply_types.insert(MessageType::Arp(ArpType::Reply), 2);
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                None,
                crate::Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 2,
                bytes: 84,
                src_mac: Some(mac),
                message_types: reply_types,
                ..Default::default()
            },
        );
        let mut asked_once = HashMap::new();
        asked_once.insert(MessageType::Arp(ArpType::Request), 1);
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 180)),
                None,
                crate::Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 1,
                bytes: 42,
                message_types: asked_once,
                initial_timestamp: Timestamp::new(10, 0),
                final_timestamp: Timestamp::new(10, 0),
                ..Default::default()
            },
        );
        let mut kept_asking = HashMap::new();
        kept_asking.insert(MessageType::Arp(ArpType::Request), 4);
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 166)),
                None,
                crate::Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 4,
                bytes: 168,
                dst_mac: Some([0xff; 6]),
                message_types: kept_asking,
                initial_timestamp: Timestamp::new(5, 0),
                final_timestamp: Timestamp::new(45, 0),
                ..Default::default()
            },
        );

        let neighbors = local_neighbors(&HashMap::new(), &map, &local_host(), &HashMap::new());
        let reply = neighbors
            .iter()
            .find(|neighbor| neighbor.address.starts_with("192.168.1.101"))
            .unwrap();
        assert_eq!(reply.address, "192.168.1.101, aa:bb:cc:dd:ee:10");
        assert_eq!(reply.packets, 2);
        assert_eq!(reply.protocols, "ARP");
        assert_eq!(reply.traffic_types, "unicast");
        assert!(reply.services.is_empty());
        assert!(
            neighbors
                .iter()
                .all(|neighbor| !neighbor.address.contains("192.168.1.166"))
        );
        assert!(
            neighbors
                .iter()
                .all(|neighbor| !neighbor.address.contains("192.168.1.180"))
        );
        assert!(
            neighbors
                .iter()
                .all(|neighbor| !neighbor.address.contains("192.168.1.171"))
        );
    }
}
