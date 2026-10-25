//! Attempts sent to local addresses that never answer.
//!
//! A sweep target is an address on this network that appears only as a destination.
//! The gateway stays a neighbor even when the capture has not yet seen it speak.

use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, Ipv4Addr};
use std::time::{Duration, Instant};

use pcap::Address;

use crate::Protocol;
use crate::networking::manage_packets::destination_traffic_type;
use crate::networking::neighbors::{is_gateway, on_this_network};
use crate::networking::types::address_port_pair::AddressPortPair;
use crate::networking::types::info_address_port_pair::InfoAddressPortPair;
use crate::networking::types::traffic_type::TrafficType;
use crate::utils::formatted_strings::mac_from_dec_to_hex;
use crate::utils::types::timestamp::Timestamp;

/// How long an address must keep appearing before it is treated as occupied.
const MIN_OCCUPIED: Duration = Duration::from_secs(30);
/// How long an address can stay quiet before it is free again.
const MAX_IDLE: Duration = Duration::from_secs(60);

/// One packet flow aimed at a local address that did not reply.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepAttempt {
    /// Address that sent the attempt.
    pub source: String,
    /// Address that was probed.
    pub target: String,
    /// Service name and destination port, when either is known.
    pub detail: String,
    /// Packets in this flow.
    pub packets: u128,
}

/// Counts for the network sweep summary.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SweepReport {
    /// Distinct local addresses that were the destination of a packet.
    pub investigated: u128,
    /// Investigated addresses that never sent a packet, excluding the gateway.
    pub no_reply: u128,
    /// Usable IPv4 host addresses on the interface subnets.
    pub possible: u128,
    /// IPv4 addresses on those subnets that are still in use.
    pub occupied: u128,
    /// Occupied IPv4 addresses, lowest first.
    pub occupied_ips: Vec<String>,
    /// Seen IPv4 addresses that are not currently occupied.
    pub free_ips: Vec<String>,
    /// Subnet labels those possible addresses belong to, such as `192.168.1.0/24`.
    pub network: String,
    /// The unanswered attempts themselves.
    pub attempts: Vec<SweepAttempt>,
}

/// True when `address` was only ever a destination on this network, and is not the gateway.
pub fn is_unanswered(
    address: &IpAddr,
    sources: &HashSet<IpAddr>,
    local_addresses: &[Address],
) -> bool {
    on_this_network(address, local_addresses)
        && !sources.contains(address)
        && !is_gateway(address, local_addresses)
}

/// Summarize unanswered local probes in `map`.
pub fn sweep_report(
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
) -> SweepReport {
    let sources: HashSet<IpAddr> = map.keys().map(|key| key.src_ip).collect();
    let mut investigated = HashSet::new();
    let mut no_reply = HashSet::new();
    let mut attempts = Vec::new();

    for (key, info) in map {
        if !on_this_network(&key.dst_ip, local_addresses) {
            continue;
        }
        investigated.insert(key.dst_ip);
        if !is_unanswered(&key.dst_ip, &sources, local_addresses) {
            continue;
        }
        no_reply.insert(key.dst_ip);
        attempts.push(SweepAttempt {
            source: key.src_ip.to_string(),
            target: key.dst_ip.to_string(),
            detail: attempt_detail(&info.service.to_string(), key.dst_port),
            packets: info.packets,
        });
    }

    attempts.sort_by(|left, right| {
        left.target
            .cmp(&right.target)
            .then_with(|| left.source.cmp(&right.source))
            .then_with(|| left.detail.cmp(&right.detail))
    });

    let networks = counted_ipv4_networks(local_addresses);
    let possible = networks.iter().map(|network| network.usable).sum();
    let network = network_labels(&networks);
    let (occupied_ips, free_ips) = live_addresses(map, local_addresses, &networks, Instant::now());
    SweepReport {
        investigated: u128::try_from(investigated.len()).unwrap_or(0),
        no_reply: u128::try_from(no_reply.len()).unwrap_or(0),
        possible,
        occupied: u128::try_from(occupied_ips.len()).unwrap_or(0),
        occupied_ips,
        free_ips,
        network,
        attempts,
    }
}

struct Presence {
    first: Timestamp,
    last: Timestamp,
    seen: Instant,
}

/// Occupied addresses have been active for [`MIN_OCCUPIED`] and were seen within [`MAX_IDLE`].
/// This host stays occupied. Anything seen on the subnet that fails that test is free.
fn live_addresses(
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
    networks: &[CountedNetwork],
    now: Instant,
) -> (Vec<String>, Vec<String>) {
    let mut presence: HashMap<Ipv4Addr, Presence> = HashMap::new();
    for (key, info) in map {
        for address in [key.src_ip, key.dst_ip] {
            let IpAddr::V4(ip) = address else {
                continue;
            };
            if !is_usable_host(ip, networks) {
                continue;
            }
            let entry = presence.entry(ip).or_insert(Presence {
                first: info.initial_timestamp,
                last: info.final_timestamp,
                seen: info.final_instant,
            });
            if info.initial_timestamp < entry.first {
                entry.first = info.initial_timestamp;
            }
            if info.final_timestamp > entry.last {
                entry.last = info.final_timestamp;
            }
            if info.final_instant > entry.seen {
                entry.seen = info.final_instant;
            }
        }
    }

    let mut ours = HashSet::new();
    let mut occupied = Vec::new();
    for address in local_addresses {
        if let IpAddr::V4(ip) = address.addr
            && is_usable_host(ip, networks)
            && ours.insert(ip)
        {
            occupied.push(ip);
        }
    }
    let mut free = Vec::new();
    for (ip, seen) in presence {
        if ours.contains(&ip) {
            continue;
        }
        if held_long_enough(&seen) && still_present(&seen, now) {
            occupied.push(ip);
        } else {
            free.push(ip);
        }
    }
    occupied.sort_by_key(|ip| u32::from(*ip));
    free.sort_by_key(|ip| u32::from(*ip));
    (
        occupied.iter().map(ToString::to_string).collect(),
        free.iter().map(ToString::to_string).collect(),
    )
}

fn held_long_enough(presence: &Presence) -> bool {
    let Some(first) = presence.first.to_usecs() else {
        return false;
    };
    let Some(last) = presence.last.to_usecs() else {
        return false;
    };
    let Some(span) = last.checked_sub(first) else {
        return false;
    };
    span >= i64::try_from(MIN_OCCUPIED.as_micros()).unwrap_or(i64::MAX)
}

fn still_present(presence: &Presence, now: Instant) -> bool {
    now.saturating_duration_since(presence.seen) <= MAX_IDLE
}

fn is_usable_host(ip: Ipv4Addr, networks: &[CountedNetwork]) -> bool {
    let bits = u32::from(ip);
    networks.iter().any(|network| {
        let broadcast = network.network | !network.mask;
        bits & network.mask == network.network && bits != network.network && bits != broadcast
    })
}

struct CountedNetwork {
    network: u32,
    mask: u32,
    prefix: u32,
    usable: u128,
}

fn counted_ipv4_networks(local_addresses: &[Address]) -> Vec<CountedNetwork> {
    let mut seen = HashSet::new();
    let mut networks = Vec::new();
    for address in local_addresses {
        let IpAddr::V4(ip) = address.addr else {
            continue;
        };
        let Some(IpAddr::V4(mask)) = address.netmask else {
            continue;
        };
        let mask_bits = u32::from(mask);
        let host_bits = mask_bits.trailing_zeros();
        if !(2..=16).contains(&host_bits) {
            continue;
        }
        let prefix = 32 - host_bits;
        let network = u32::from(ip) & mask_bits;
        if !seen.insert((network, prefix)) {
            continue;
        }
        networks.push(CountedNetwork {
            network,
            mask: mask_bits,
            prefix,
            usable: (1u128 << host_bits) - 2,
        });
    }
    networks
}

fn network_labels(networks: &[CountedNetwork]) -> String {
    let mut labels: Vec<_> = networks
        .iter()
        .map(|network| format!("{}/{}", Ipv4Addr::from(network.network), network.prefix))
        .collect();
    labels.sort();
    labels.join(", ")
}

/// One discovery probe sent to a local address. Replies are not required.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiscoveryPing {
    /// Address that was probed.
    pub target: String,
    /// Service name and destination port, when either is known.
    pub detail: String,
    /// Packet protocols used by the probes.
    pub protocols: String,
    /// Unicast, multicast, or broadcast.
    pub traffic: String,
    /// Packets in the probes to this address.
    pub packets: u128,
    /// Bytes of those probes.
    pub bytes: u128,
    /// Repeated ARP aimed at this address, with no reply.
    pub arp: bool,
    /// Addresses that sent those ARP requests.
    pub askers: String,
}

const DISCOVERY_MAC: [u8; 6] = [0xff; 6];

#[derive(Default)]
struct PingAcc {
    details: BTreeSet<String>,
    protocols: BTreeSet<String>,
    traffic_types: BTreeSet<String>,
    askers: BTreeSet<String>,
    packets: u128,
    bytes: u128,
    /// A non-ARP discovery probe was also sent to this address.
    swept: bool,
}

/// Local probes sent with the broadcast discovery MAC, whether or not the address replied.
///
/// Repeated ARP to the same address is included only when that address never replies. A single
/// ARP probe, and ARP to an address that does reply, are left out.
pub fn discovery_pings(
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
) -> Vec<DiscoveryPing> {
    let sources: HashSet<IpAddr> = map.keys().map(|key| key.src_ip).collect();
    let mut grouped: HashMap<IpAddr, PingAcc> = HashMap::new();
    for (key, info) in map {
        if key.protocol == Protocol::Arp {
            continue;
        }
        if info.dst_mac != Some(DISCOVERY_MAC) || !on_this_network(&key.dst_ip, local_addresses) {
            continue;
        }
        let entry = grouped.entry(key.dst_ip).or_default();
        entry
            .details
            .insert(attempt_detail(&info.service.to_string(), key.dst_port));
        entry.protocols.insert(key.protocol.to_string());
        entry.traffic_types.insert(
            traffic_name(destination_traffic_type(&key.dst_ip, local_addresses)).to_string(),
        );
        entry.packets = entry.packets.saturating_add(info.packets);
        entry.bytes = entry.bytes.saturating_add(info.bytes);
        entry.swept = true;
    }
    for probe in repeated_arp_without_reply(map, local_addresses, &sources) {
        let entry = grouped.entry(probe.target).or_default();
        entry.protocols.insert("ARP".to_string());
        entry.traffic_types.extend(probe.traffic);
        entry.askers.extend(probe.askers);
        entry.packets = entry.packets.saturating_add(probe.packets);
        entry.bytes = entry.bytes.saturating_add(probe.bytes);
    }
    let mut pings: Vec<_> = grouped
        .into_iter()
        .map(|(target, acc)| {
            let protocols = acc.protocols.into_iter().collect::<Vec<_>>().join(", ");
            DiscoveryPing {
                arp: !acc.swept && protocols == "ARP",
                target: target.to_string(),
                detail: acc.details.into_iter().collect::<Vec<_>>().join(", "),
                protocols,
                traffic: acc.traffic_types.into_iter().collect::<Vec<_>>().join(", "),
                packets: acc.packets,
                bytes: acc.bytes,
                askers: acc.askers.into_iter().collect::<Vec<_>>().join(", "),
            }
        })
        .collect();
    pings.sort_by(|left, right| {
        right
            .packets
            .cmp(&left.packets)
            .then_with(|| left.target.cmp(&right.target))
    });
    pings
}

struct RepeatedArp {
    target: IpAddr,
    packets: u128,
    bytes: u128,
    traffic: BTreeSet<String>,
    askers: BTreeSet<String>,
}

struct ArpAsk {
    first: Timestamp,
    last: Timestamp,
    packets: u128,
    bytes: u128,
    traffic: BTreeSet<String>,
    askers: BTreeSet<String>,
}

/// ARP aimed at one local address, with no packet back from that address, across at least 30 seconds.
fn repeated_arp_without_reply(
    map: &HashMap<AddressPortPair, InfoAddressPortPair>,
    local_addresses: &[Address],
    sources: &HashSet<IpAddr>,
) -> Vec<RepeatedArp> {
    let mut asks: HashMap<IpAddr, ArpAsk> = HashMap::new();
    for (key, info) in map {
        if key.protocol != Protocol::Arp
            || sources.contains(&key.dst_ip)
            || !on_this_network(&key.dst_ip, local_addresses)
        {
            continue;
        }
        let traffic = traffic_name(destination_traffic_type(&key.dst_ip, local_addresses));
        let asker = asker_label(key.src_ip, info.src_mac);
        asks.entry(key.dst_ip)
            .and_modify(|seen| {
                if info.initial_timestamp < seen.first {
                    seen.first = info.initial_timestamp;
                }
                if info.final_timestamp > seen.last {
                    seen.last = info.final_timestamp;
                }
                seen.packets = seen.packets.saturating_add(info.packets);
                seen.bytes = seen.bytes.saturating_add(info.bytes);
                seen.traffic.insert(traffic.to_string());
                seen.askers.insert(asker.clone());
            })
            .or_insert(ArpAsk {
                first: info.initial_timestamp,
                last: info.final_timestamp,
                packets: info.packets,
                bytes: info.bytes,
                traffic: BTreeSet::from([traffic.to_string()]),
                askers: BTreeSet::from([asker]),
            });
    }
    asks.into_iter()
        .filter(|(_, seen)| spans_exchange(seen.first, seen.last))
        .map(|(target, seen)| RepeatedArp {
            target,
            packets: seen.packets,
            bytes: seen.bytes,
            traffic: seen.traffic,
            askers: seen.askers,
        })
        .collect()
}

fn asker_label(source: IpAddr, mac: Option<[u8; 6]>) -> String {
    match mac {
        Some(mac) if mac != [0xff; 6] => {
            format!("{source}, {}", mac_from_dec_to_hex(mac))
        }
        _ => source.to_string(),
    }
}

fn traffic_name(traffic: TrafficType) -> &'static str {
    match traffic {
        TrafficType::Unicast => "unicast",
        TrafficType::Multicast => "multicast",
        TrafficType::Broadcast => "broadcast",
    }
}

fn spans_exchange(first: Timestamp, last: Timestamp) -> bool {
    let Some(start) = first.to_usecs() else {
        return false;
    };
    let Some(end) = last.to_usecs() else {
        return false;
    };
    let Some(span) = end.checked_sub(start) else {
        return false;
    };
    span >= i64::try_from(MIN_OCCUPIED.as_micros()).unwrap_or(i64::MAX)
}

fn attempt_detail(service: &str, port: Option<u16>) -> String {
    let named = !service.is_empty() && service != "?" && service != "-";
    match (named, port) {
        (true, Some(port)) => format!("{service} {port}"),
        (true, None) => service.to_string(),
        (false, Some(port)) => port.to_string(),
        (false, None) => "—".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{Duration, Instant};

    use crate::Protocol;
    use crate::networking::types::info_address_port_pair::InfoAddressPortPair;
    use crate::utils::types::timestamp::Timestamp;

    fn locals() -> Vec<Address> {
        vec![Address {
            addr: IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
            netmask: Some(IpAddr::V4(Ipv4Addr::new(255, 255, 255, 0))),
            broadcast_addr: Some(IpAddr::V4(Ipv4Addr::new(192, 168, 1, 255))),
            dst_addr: None,
        }]
    }

    fn probe(dst: u8, packets: u128) -> (AddressPortPair, InfoAddressPortPair) {
        (
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(50_000),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, dst)),
                Some(80),
                Protocol::Tcp,
            ),
            InfoAddressPortPair {
                packets,
                bytes: packets * 40,
                ..Default::default()
            },
        )
    }

    #[test]
    fn a_silent_range_is_a_sweep_and_a_reply_is_not() {
        let mut map = HashMap::new();
        for host in 100..=102 {
            let (key, info) = probe(host, 1);
            map.insert(key, info);
        }
        let (phone, phone_info) = probe(87, 4);
        map.insert(phone, phone_info);
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 87)),
                Some(80),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(50_000),
                Protocol::Tcp,
            ),
            InfoAddressPortPair {
                packets: 4,
                bytes: 80,
                ..Default::default()
            },
        );
        let (router, router_info) = probe(254, 2);
        map.insert(router, router_info);

        let report = sweep_report(&map, &locals());
        assert_eq!(report.investigated, 5);
        assert_eq!(report.no_reply, 3);
        assert_eq!(report.possible, 254);
        assert_eq!(report.occupied, 1);
        assert_eq!(report.occupied_ips, vec!["192.168.1.171".to_string()]);
        assert!(report.free_ips.iter().any(|ip| ip == "192.168.1.100"));
        assert!(report.free_ips.iter().any(|ip| ip == "192.168.1.87"));
        assert_eq!(report.network, "192.168.1.0/24");
        assert_eq!(report.attempts.len(), 3);
        assert_eq!(report.attempts[0].target, "192.168.1.100");
        assert_eq!(report.attempts[2].target, "192.168.1.102");
        assert!(report.attempts.iter().all(|attempt| attempt.packets == 1));

        let neighbors = crate::networking::neighbors::local_neighbors(
            &HashMap::new(),
            &map,
            &locals(),
            &HashMap::new(),
        );
        let labels: Vec<_> = neighbors
            .iter()
            .map(|neighbor| neighbor.label.as_str())
            .collect();
        assert!(labels.iter().all(|label| !label.contains("Router")));
        assert!(labels.iter().all(|label| !label.contains("192.168.1.10")));
    }

    #[test]
    fn public_destinations_are_not_part_of_the_sweep() {
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(50_000),
                IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1)),
                Some(443),
                Protocol::Tcp,
            ),
            InfoAddressPortPair {
                packets: 10,
                ..Default::default()
            },
        );
        let report = sweep_report(&map, &locals());
        assert_eq!(report.investigated, 0);
        assert_eq!(report.no_reply, 0);
        assert_eq!(report.occupied, 1);
        assert!(report.attempts.is_empty());
    }

    #[test]
    fn a_short_or_stale_address_is_free_and_a_settled_one_is_occupied() {
        let now = Instant::now();
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 87)),
                Some(80),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(50_000),
                Protocol::Tcp,
            ),
            InfoAddressPortPair {
                packets: 20,
                initial_timestamp: Timestamp::new(1_000, 0),
                final_timestamp: Timestamp::new(1_045, 0),
                final_instant: now,
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 80)),
                Some(80),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(50_000),
                Protocol::Tcp,
            ),
            InfoAddressPortPair {
                packets: 2,
                initial_timestamp: Timestamp::new(1_000, 0),
                final_timestamp: Timestamp::new(1_005, 0),
                final_instant: now,
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 66)),
                Some(80),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(50_000),
                Protocol::Tcp,
            ),
            InfoAddressPortPair {
                packets: 20,
                initial_timestamp: Timestamp::new(1_000, 0),
                final_timestamp: Timestamp::new(1_045, 0),
                final_instant: now.checked_sub(Duration::from_secs(90)).unwrap_or(now),
                ..Default::default()
            },
        );

        let report = sweep_report(&map, &locals());
        assert!(report.occupied_ips.iter().any(|ip| ip == "192.168.1.87"));
        assert!(report.occupied_ips.iter().any(|ip| ip == "192.168.1.171"));
        assert!(report.free_ips.iter().any(|ip| ip == "192.168.1.80"));
        assert!(report.free_ips.iter().any(|ip| ip == "192.168.1.66"));
        assert!(!report.occupied_ips.iter().any(|ip| ip == "192.168.1.80"));
        assert!(!report.occupied_ips.iter().any(|ip| ip == "192.168.1.66"));
    }

    #[test]
    fn discovery_pings_include_replies_and_silence() {
        let discovery = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff];
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(9),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 149)),
                Some(9),
                Protocol::Udp,
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
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 149)),
                Some(9),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(9),
                Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 2,
                bytes: 80,
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 171)),
                Some(9),
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 180)),
                Some(9),
                Protocol::Udp,
            ),
            InfoAddressPortPair {
                packets: 1,
                bytes: 40,
                dst_mac: Some(discovery),
                ..Default::default()
            },
        );

        let pings = discovery_pings(&map, &locals());
        assert_eq!(pings.len(), 2);
        assert_eq!(pings[0].target, "192.168.1.149");
        assert_eq!(pings[0].packets, 2);
        assert_eq!(pings[1].target, "192.168.1.180");
        assert_eq!(pings[1].packets, 1);
        assert!(!pings[0].arp);
        assert!(!pings[1].arp);
    }

    #[test]
    fn repeated_arp_without_a_reply_stays_a_discovery_ping() {
        let mut map = HashMap::new();
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 166)),
                None,
                Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 4,
                bytes: 168,
                dst_mac: Some([0xff; 6]),
                initial_timestamp: Timestamp::new(5, 0),
                final_timestamp: Timestamp::new(45, 0),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 180)),
                None,
                Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 1,
                bytes: 42,
                dst_mac: Some([0xff; 6]),
                initial_timestamp: Timestamp::new(10, 0),
                final_timestamp: Timestamp::new(10, 0),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                None,
                Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 3,
                bytes: 126,
                dst_mac: Some([0xff; 6]),
                initial_timestamp: Timestamp::new(5, 0),
                final_timestamp: Timestamp::new(50, 0),
                ..Default::default()
            },
        );
        map.insert(
            AddressPortPair::new(
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 101)),
                None,
                IpAddr::V4(Ipv4Addr::new(192, 168, 1, 254)),
                None,
                Protocol::Arp,
            ),
            InfoAddressPortPair {
                packets: 2,
                bytes: 84,
                initial_timestamp: Timestamp::new(5, 0),
                final_timestamp: Timestamp::new(50, 0),
                ..Default::default()
            },
        );

        let pings = discovery_pings(&map, &locals());
        assert_eq!(pings.len(), 1);
        assert_eq!(pings[0].target, "192.168.1.166");
        assert_eq!(pings[0].protocols, "ARP");
        assert_eq!(pings[0].traffic, "unicast");
        assert_eq!(pings[0].detail, "");
        assert_eq!(pings[0].askers, "192.168.1.254");
        assert_eq!(pings[0].packets, 4);
        assert!(pings[0].arp);
    }
}
