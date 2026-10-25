//! Grouped DNS-SD and UDP 2021 advertisements.

use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use pcap::Address;

use crate::networking::manage_packets::destination_traffic_type;
use crate::networking::types::info_traffic::InfoTraffic;
use crate::networking::types::traffic_type::TrafficType;
use crate::utils::formatted_strings::mac_from_dec_to_hex;

const MDNS_PORT: u16 = 5353;
const CUSTOM_BROADCAST_PORT: u16 = 2021;
const DNS_PTR: u16 = 12;
const DNS_TXT: u16 = 16;
const DNS_A: u16 = 1;
const DNS_AAAA: u16 = 28;
const DNS_SRV: u16 = 33;
const DNS_CLASS_IN: u16 = 1;

/// One announcement row after addresses for the same instance and service are combined.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AnnouncementGroup {
    /// DNS-SD instance or device name.
    pub instance: String,
    /// Service type.
    pub service: String,
    /// One IPv4 address and the MAC from the frame that sent it, when both are known.
    pub addresses: String,
    /// Packet protocols, such as `UDP` or `ARP`.
    pub protocols: String,
    /// Comma-separated traffic kinds observed for this identity.
    pub traffic: String,
    /// Optional model string from TXT or a vendor header.
    pub model: String,
    /// Advertisement packets folded into this row.
    pub packets: u128,
    /// Bytes of those packets.
    pub bytes: u128,
}

/// One advertised identity: service type, instance name, and the address that sent it.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct AnnouncementKey {
    /// DNS-SD instance or device name, such as `Hisense Xumo TV`.
    pub instance: String,
    /// Service type, such as `_airplay._tcp` or a NOTIFY `NT` value.
    pub service: String,
    /// Address that transmitted the advertisement.
    pub source: IpAddr,
    /// Whether this advertisement was unicast, multicast, or broadcast.
    pub traffic: TrafficType,
}

/// Packets accumulated for one [`AnnouncementKey`].
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AnnouncementInfo {
    /// Number of advertisement packets folded into this row.
    pub packets: u128,
    /// Bytes of those packets.
    pub bytes: u128,
    /// Optional model string from TXT or a vendor header.
    pub model: String,
    /// Extra addresses learned from A or AAAA records.
    pub extra_addresses: Vec<IpAddr>,
    /// Source MAC of the frame that carried an IPv4 advertisement.
    src_mac: Option<[u8; 6]>,
}

/// A single identity found inside one datagram, before it is counted.
#[derive(Debug, Clone, PartialEq, Eq)]
struct ObservedAnnouncement {
    instance: String,
    service: String,
    model: String,
    extra_addresses: Vec<IpAddr>,
}

impl AnnouncementInfo {
    /// Fold another interval's counts into this row.
    pub fn absorb(&mut self, other: &Self) {
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes = self.bytes.saturating_add(other.bytes);
        if self.model.is_empty() {
            self.model.clone_from(&other.model);
        }
        for address in &other.extra_addresses {
            self.push_address(*address);
        }
        if self.src_mac.is_none() {
            self.src_mac = other.src_mac;
        }
    }

    /// MAC from the frame that sent this IPv4 advertisement.
    pub(crate) fn source_mac(&self) -> Option<[u8; 6]> {
        self.src_mac
    }

    /// Counts used by tests in other modules.
    #[cfg(test)]
    pub fn for_tests(packets: u128, bytes: u128) -> Self {
        Self {
            packets,
            bytes,
            ..Self::default()
        }
    }

    fn push_address(&mut self, address: IpAddr) {
        if self.extra_addresses.len() < 3 && !self.extra_addresses.contains(&address) {
            self.extra_addresses.push(address);
        }
    }
}

/// Headers needed to count one UDP datagram as an announcement.
pub struct AnnouncementDatagram<'a> {
    /// UDP payload.
    pub payload: &'a [u8],
    /// Source port.
    pub src_port: u16,
    /// Destination port.
    pub dst_port: u16,
    /// Source address, which becomes the row's source.
    pub src_ip: IpAddr,
    /// Destination address, used to classify unicast, multicast, or broadcast.
    pub dst_ip: IpAddr,
    /// Full packet length counted against the row.
    pub packet_bytes: u128,
    /// Local interface addresses, used to recognize directed broadcasts.
    pub interface_addresses: &'a [Address],
    /// Source MAC from the link layer, paired with an IPv4 source.
    pub src_mac: Option<[u8; 6]>,
}

/// Combine rows that share an instance, service, and traffic type.
///
/// The address column is one IPv4 address and the MAC from the frame that sent it.
pub fn grouped_announcements(
    announcements: &HashMap<AnnouncementKey, AnnouncementInfo>,
) -> Vec<AnnouncementGroup> {
    let mut buckets: HashMap<(String, String, TrafficType), AnnouncementBucket> = HashMap::new();
    for (key, info) in announcements {
        let bucket = buckets
            .entry((key.instance.clone(), key.service.clone(), key.traffic))
            .or_default();
        bucket.pairs.push((key.source, info.src_mac, info.packets));
        bucket.packets = bucket.packets.saturating_add(info.packets);
        bucket.bytes = bucket.bytes.saturating_add(info.bytes);
        if bucket.model.is_empty() {
            bucket.model.clone_from(&info.model);
        }
    }

    let mut groups = buckets
        .into_iter()
        .map(|((instance, service, traffic), bucket)| AnnouncementGroup {
            instance,
            service,
            addresses: choose_pair(&bucket.pairs),
            protocols: "UDP".to_string(),
            traffic: traffic_name(traffic).to_string(),
            model: bucket.model,
            packets: bucket.packets,
            bytes: bucket.bytes,
        })
        .collect::<Vec<_>>();
    groups.sort_by(|left, right| {
        right
            .packets
            .cmp(&left.packets)
            .then_with(|| left.instance.cmp(&right.instance))
            .then_with(|| left.service.cmp(&right.service))
            .then_with(|| left.traffic.cmp(&right.traffic))
    });
    groups
}

#[derive(Default)]
struct AnnouncementBucket {
    pairs: Vec<(IpAddr, Option<[u8; 6]>, u128)>,
    model: String,
    packets: u128,
    bytes: u128,
}

fn traffic_name(traffic: TrafficType) -> &'static str {
    match traffic {
        TrafficType::Unicast => "unicast",
        TrafficType::Multicast => "multicast",
        TrafficType::Broadcast => "broadcast",
    }
}

/// The busiest IPv4 source in the group, with its own MAC. Other addresses stay off this row.
fn choose_pair(pairs: &[(IpAddr, Option<[u8; 6]>, u128)]) -> String {
    let mut chosen: Vec<_> = pairs
        .iter()
        .filter(|(address, _, _)| address.is_ipv4())
        .collect();
    if chosen.is_empty() {
        chosen = pairs.iter().collect();
    }
    chosen.sort_by(|left, right| {
        right
            .2
            .cmp(&left.2)
            .then_with(|| address_order(&left.0).cmp(&address_order(&right.0)))
    });
    let Some((address, mac, _)) = chosen.first() else {
        return String::new();
    };
    match (address, mac) {
        (IpAddr::V4(ip), Some(mac)) => {
            format!("{ip}, {}", mac_from_dec_to_hex(*mac))
        }
        (address, _) => address.to_string(),
    }
}

fn address_order(address: &IpAddr) -> (u8, u128) {
    match address {
        IpAddr::V4(ip) => (0, u128::from(u32::from(*ip))),
        IpAddr::V6(ip) => (1 + u8::from(ip.is_unicast_link_local()), u128::from(*ip)),
    }
}

/// Parse a UDP payload when either port is 5353 or 2021, and count it on its identity rows.
pub fn observe_announcements(info_traffic: &mut InfoTraffic, datagram: &AnnouncementDatagram<'_>) {
    let observed = if datagram.src_port == MDNS_PORT || datagram.dst_port == MDNS_PORT {
        parse_mdns(datagram.payload)
    } else if datagram.src_port == CUSTOM_BROADCAST_PORT
        || datagram.dst_port == CUSTOM_BROADCAST_PORT
    {
        parse_notify(datagram.payload).into_iter().collect()
    } else {
        return;
    };

    let traffic_type = destination_traffic_type(&datagram.dst_ip, datagram.interface_addresses);
    for item in observed {
        let key = AnnouncementKey {
            instance: item.instance,
            service: item.service,
            source: datagram.src_ip,
            traffic: traffic_type,
        };
        let entry = info_traffic.announcements.entry(key).or_default();
        entry.packets = entry.packets.saturating_add(1);
        entry.bytes = entry.bytes.saturating_add(datagram.packet_bytes);
        if entry.src_mac.is_none() && datagram.src_ip.is_ipv4() {
            entry.src_mac = datagram.src_mac;
        }
        if entry.model.is_empty() {
            entry.model = item.model;
        }
        for address in item.extra_addresses {
            entry.push_address(address);
        }
    }
}

fn parse_notify(payload: &[u8]) -> Option<ObservedAnnouncement> {
    let text = std::str::from_utf8(payload).ok()?;
    let mut lines = text.split("\r\n");
    let request = lines.next()?;
    if !request.starts_with("NOTIFY ") {
        return None;
    }

    let mut service = None;
    let mut instance = None;
    let mut model = String::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        let Some((name, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        if name.eq_ignore_ascii_case("NT") {
            service = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("DevName.bambu.com") {
            instance = Some(value.to_string());
        } else if name.eq_ignore_ascii_case("DevModel.bambu.com") {
            model = value.to_string();
        }
    }

    Some(ObservedAnnouncement {
        instance: instance?,
        service: service?,
        model,
        extra_addresses: Vec::new(),
    })
}

fn parse_mdns(payload: &[u8]) -> Vec<ObservedAnnouncement> {
    if payload.len() < 12 {
        return Vec::new();
    }
    let questions = u16::from_be_bytes([payload[4], payload[5]]) as usize;
    let answers = u16::from_be_bytes([payload[6], payload[7]]) as usize;
    let authorities = u16::from_be_bytes([payload[8], payload[9]]) as usize;
    let additionals = u16::from_be_bytes([payload[10], payload[11]]) as usize;

    let mut pos = 12;
    for _ in 0..questions {
        let Some((_, next)) = read_name(payload, pos) else {
            return Vec::new();
        };
        if next + 4 > payload.len() {
            return Vec::new();
        }
        pos = next + 4;
    }

    let mut ptrs = Vec::new();
    let mut services = Vec::new();
    let mut models = Vec::new();
    let mut addresses = Vec::new();
    for _ in 0..answers + authorities + additionals {
        let Some((name, next)) = read_name(payload, pos) else {
            return Vec::new();
        };
        if next + 10 > payload.len() {
            return Vec::new();
        }
        let rtype = u16::from_be_bytes([payload[next], payload[next + 1]]);
        let class = u16::from_be_bytes([payload[next + 2], payload[next + 3]]) & 0x7FFF;
        let rdlength = u16::from_be_bytes([payload[next + 8], payload[next + 9]]) as usize;
        let rdata_at = next + 10;
        if rdata_at + rdlength > payload.len() {
            return Vec::new();
        }
        pos = rdata_at + rdlength;
        if class != DNS_CLASS_IN {
            continue;
        }
        match rtype {
            DNS_PTR => {
                if let Some((target, _)) = read_name(payload, rdata_at)
                    && let Some(identity) = ptr_identity(&name, &target)
                {
                    ptrs.push(identity);
                }
            }
            DNS_SRV => {
                if rdlength >= 6
                    && let Some(identity) = instance_service(&name)
                    && let Some((target, _)) = read_name(payload, rdata_at + 6)
                {
                    services.push((identity.0, identity.1, target.join(".")));
                }
            }
            DNS_TXT => {
                if let Some((instance, service)) = instance_service(&name) {
                    models.push((
                        instance,
                        service,
                        txt_model(&payload[rdata_at..rdata_at + rdlength]),
                    ));
                }
            }
            DNS_A if rdlength == 4 => {
                let octets: [u8; 4] = payload[rdata_at..rdata_at + 4].try_into().unwrap_or([0; 4]);
                addresses.push((
                    name.join(".").to_ascii_lowercase(),
                    IpAddr::V4(Ipv4Addr::from(octets)),
                ));
            }
            DNS_AAAA if rdlength == 16 => {
                let octets: [u8; 16] = payload[rdata_at..rdata_at + 16]
                    .try_into()
                    .unwrap_or([0; 16]);
                addresses.push((
                    name.join(".").to_ascii_lowercase(),
                    IpAddr::V6(Ipv6Addr::from(octets)),
                ));
            }
            _ => {}
        }
    }

    assemble(ptrs, services, models, &addresses)
}

fn assemble(
    ptrs: Vec<(String, String)>,
    services: Vec<(String, String, String)>,
    models: Vec<(String, String, String)>,
    addresses: &[(String, IpAddr)],
) -> Vec<ObservedAnnouncement> {
    let mut rows: HashMap<(String, String), ObservedAnnouncement> = HashMap::new();
    let ensure =
        |instance: String, service: String, rows: &mut HashMap<_, ObservedAnnouncement>| {
            rows.entry((instance.clone(), service.clone()))
                .or_insert_with(|| ObservedAnnouncement {
                    instance,
                    service,
                    model: String::new(),
                    extra_addresses: Vec::new(),
                });
        };

    for (instance, service) in ptrs {
        ensure(instance, service, &mut rows);
    }
    let mut targets = HashMap::new();
    for (instance, service, target) in services {
        ensure(instance.clone(), service.clone(), &mut rows);
        targets.insert((instance, service), target);
    }
    for (instance, service, model) in models {
        ensure(instance.clone(), service.clone(), &mut rows);
        if let Some(row) = rows.get_mut(&(instance, service))
            && row.model.is_empty()
        {
            row.model = model;
        }
    }
    for ((instance, service), target) in targets {
        let Some(row) = rows.get_mut(&(instance, service)) else {
            continue;
        };
        let target = target.to_ascii_lowercase();
        for (name, address) in addresses {
            if name == &target && row.extra_addresses.len() < 3 {
                row.extra_addresses.push(*address);
            }
        }
    }
    rows.into_values().collect()
}

fn ptr_identity(owner: &[String], target: &[String]) -> Option<(String, String)> {
    if owner.first().is_some_and(|label| label == "_services") {
        return None;
    }
    if let Some(service) = service_type(owner)
        && target.len() > owner.len()
        && target[target.len() - owner.len()..] == owner[..]
    {
        let instance_labels = &target[..target.len() - owner.len()];
        if !instance_labels.is_empty()
            && instance_labels.iter().all(|label| !label.starts_with('_'))
        {
            return Some((instance_labels.join("."), service));
        }
    }
    instance_service(target)
}

fn service_type(name: &[String]) -> Option<String> {
    if name.len() >= 3
        && name
            .last()
            .is_some_and(|label| label.eq_ignore_ascii_case("local"))
        && name[0].starts_with('_')
    {
        Some(name[..name.len() - 1].join("."))
    } else {
        None
    }
}

fn instance_service(name: &[String]) -> Option<(String, String)> {
    if !name
        .last()
        .is_some_and(|label| label.eq_ignore_ascii_case("local"))
    {
        return None;
    }
    let body = &name[..name.len() - 1];
    let index = body.iter().position(|label| label.starts_with('_'))?;
    if index == 0 {
        return None;
    }
    let instance = body[..index].join(".");
    let service = body[index..].join(".");
    if instance.is_empty() || service.is_empty() {
        None
    } else {
        Some((instance, service))
    }
}

fn txt_model(rdata: &[u8]) -> String {
    let mut pos = 0;
    while pos < rdata.len() {
        let len = rdata[pos] as usize;
        pos += 1;
        if pos + len > rdata.len() {
            break;
        }
        if let Ok(text) = std::str::from_utf8(&rdata[pos..pos + len])
            && let Some(model) = text.strip_prefix("model=")
        {
            return model.to_string();
        }
        pos += len;
    }
    String::new()
}

fn read_name(msg: &[u8], start: usize) -> Option<(Vec<String>, usize)> {
    let mut labels = Vec::new();
    let mut pos = start;
    let mut end = start;
    let mut jumped = false;
    let mut hops = 0;
    loop {
        if pos >= msg.len() || hops > 16 {
            return None;
        }
        let len = msg[pos];
        if len == 0 {
            if !jumped {
                end = pos + 1;
            }
            break;
        }
        if len & 0xC0 == 0xC0 {
            if pos + 1 >= msg.len() {
                return None;
            }
            if !jumped {
                end = pos + 2;
                jumped = true;
            }
            pos = (usize::from(len & 0x3F) << 8) | usize::from(msg[pos + 1]);
            hops += 1;
            continue;
        }
        if len & 0xC0 != 0 {
            return None;
        }
        let label_end = pos + 1 + usize::from(len);
        if label_end > msg.len() {
            return None;
        }
        labels.push(
            std::str::from_utf8(&msg[pos + 1..label_end])
                .ok()?
                .to_string(),
        );
        pos = label_end;
        if !jumped {
            end = pos;
        }
    }
    Some((labels, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::networking::types::info_traffic::InfoTraffic;

    fn label(name: &str) -> Vec<u8> {
        let mut out = Vec::new();
        for part in name.split('.') {
            out.push(u8::try_from(part.len()).unwrap());
            out.extend(part.as_bytes());
        }
        out.push(0);
        out
    }

    fn ptr_message(owner: &str, target: &str) -> Vec<u8> {
        let owner = label(owner);
        let target = label(target);
        let rdlength = u16::try_from(target.len()).unwrap();
        let mut msg = vec![0, 0, 0x84, 0, 0, 0, 0, 1, 0, 0, 0, 0];
        msg.extend(owner);
        msg.extend([0, 12, 0, 1, 0, 0, 0, 120]);
        msg.extend(rdlength.to_be_bytes());
        msg.extend(target);
        msg
    }

    fn observe(
        info: &mut InfoTraffic,
        payload: &[u8],
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
    ) {
        observe_announcements(
            info,
            &AnnouncementDatagram {
                payload,
                src_port: sport,
                dst_port: dport,
                src_ip: IpAddr::V4(Ipv4Addr::from(src)),
                dst_ip: IpAddr::V4(Ipv4Addr::from(dst)),
                packet_bytes: 100,
                interface_addresses: &[],
                src_mac: None,
            },
        );
    }

    #[test]
    fn mdns_groups_instances_and_ignores_service_enumeration() {
        let mut info = InfoTraffic::default();
        let airplay = ptr_message("_airplay._tcp.local", "Hisense Xumo TV._airplay._tcp.local");
        observe(
            &mut info,
            &airplay,
            [192, 168, 1, 50],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        observe(
            &mut info,
            &airplay,
            [192, 168, 1, 50],
            [192, 168, 1, 171],
            5353,
            5353,
        );
        let mac = ptr_message("_airplay._tcp.local", "mb's macbook._airplay._tcp.local");
        observe(
            &mut info,
            &mac,
            [192, 168, 1, 20],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        let cast = ptr_message(
            "_googlecast._tcp.local",
            "Chromecast-8a3b._googlecast._tcp.local",
        );
        observe(
            &mut info,
            &cast,
            [192, 168, 1, 30],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        let phone = ptr_message(
            "_companion-link._tcp.local",
            "iPhone._companion-link._tcp.local",
        );
        observe(
            &mut info,
            &phone,
            [192, 168, 1, 87],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        let browse = ptr_message("_services._dns-sd._udp.local", "_airplay._tcp.local");
        observe(
            &mut info,
            &browse,
            [192, 168, 1, 50],
            [224, 0, 0, 251],
            5353,
            5353,
        );

        assert_eq!(info.announcements.len(), 5);
        let tv: Vec<_> = info
            .announcements
            .iter()
            .filter(|(key, _)| key.instance == "Hisense Xumo TV")
            .collect();
        assert_eq!(tv.len(), 2);
        assert!(
            tv.iter()
                .all(|(key, info)| { key.service == "_airplay._tcp" && info.packets == 1 })
        );
        assert!(
            tv.iter()
                .any(|(key, _)| key.traffic == TrafficType::Unicast)
        );
        assert!(
            tv.iter()
                .any(|(key, _)| key.traffic == TrafficType::Multicast)
        );
        assert!(
            info.announcements
                .keys()
                .any(|key| key.instance == "mb's macbook" && key.service == "_airplay._tcp")
        );
        assert!(
            info.announcements
                .keys()
                .any(|key| key.service == "_googlecast._tcp")
        );
        assert!(
            info.announcements
                .keys()
                .any(|key| key.service == "_companion-link._tcp")
        );
    }

    #[test]
    fn query_without_answers_and_short_payload_add_no_rows() {
        let mut info = InfoTraffic::default();
        let mut query = vec![0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0];
        query.extend(label("_airplay._tcp.local"));
        query.extend([0, 12, 0, 1]);
        observe(
            &mut info,
            &query,
            [192, 168, 1, 171],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        observe(
            &mut info,
            &[0, 1, 2],
            [192, 168, 1, 171],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        assert!(info.announcements.is_empty());
    }

    #[test]
    fn udp_2021_notify_groups_repeated_broadcasts() {
        let payload = b"NOTIFY * HTTP/1.1\r\nHost: 239.255.255.250:1990\r\nNT: urn:bambulab-com:device:3dprinter:1\r\nDevModel.bambu.com: O1S\r\nDevName.bambu.com: tsuki-dreams-3DP-9798\r\n\r\n";
        let mut info = InfoTraffic::default();
        for _ in 0..13 {
            observe(
                &mut info,
                payload,
                [192, 168, 1, 149],
                [255, 255, 255, 255],
                2021,
                2021,
            );
        }
        assert_eq!(info.announcements.len(), 1);
        let (key, value) = info.announcements.iter().next().unwrap();
        assert_eq!(key.instance, "tsuki-dreams-3DP-9798");
        assert_eq!(key.service, "urn:bambulab-com:device:3dprinter:1");
        assert_eq!(value.model, "O1S");
        assert_eq!(value.packets, 13);
        assert_eq!(key.traffic, TrafficType::Broadcast);
    }

    #[test]
    fn other_ports_are_ignored() {
        let mut info = InfoTraffic::default();
        observe(
            &mut info,
            b"NOTIFY * HTTP/1.1\r\nNT: x\r\nDevName.bambu.com: y\r\n",
            [192, 168, 1, 149],
            [255, 255, 255, 255],
            1900,
            1900,
        );
        assert!(info.announcements.is_empty());
    }

    #[test]
    fn refresh_adds_interval_counts() {
        let mut total = InfoTraffic::default();
        let mut lookup = None;
        let mut first = InfoTraffic::default();
        observe(
            &mut first,
            &ptr_message("_airplay._tcp.local", "Hisense Xumo TV._airplay._tcp.local"),
            [192, 168, 1, 50],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        total.refresh(&mut first, &mut lookup);
        let mut second = InfoTraffic::default();
        observe(
            &mut second,
            &ptr_message("_airplay._tcp.local", "Hisense Xumo TV._airplay._tcp.local"),
            [192, 168, 1, 50],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        total.refresh(&mut second, &mut lookup);
        assert_eq!(total.announcements.values().next().unwrap().packets, 2);
    }

    #[test]
    fn same_instance_and_service_join_their_addresses() {
        let mut info = InfoTraffic::default();
        let airplay = ptr_message("_airplay._tcp.local", "mb's macbook._airplay._tcp.local");
        observe(
            &mut info,
            &airplay,
            [192, 168, 1, 53],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        observe(
            &mut info,
            &airplay,
            [192, 168, 1, 52],
            [224, 0, 0, 251],
            5353,
            5353,
        );
        let companion = ptr_message(
            "_companion-link._tcp.local",
            "mb's macbook._companion-link._tcp.local",
        );
        observe(
            &mut info,
            &companion,
            [192, 168, 1, 52],
            [224, 0, 0, 251],
            5353,
            5353,
        );

        let groups = grouped_announcements(&info.announcements);
        assert_eq!(groups.len(), 2);
        let airplay_row = groups
            .iter()
            .find(|row| row.service == "_airplay._tcp")
            .unwrap();
        assert_eq!(airplay_row.instance, "mb's macbook");
        assert_eq!(airplay_row.traffic, "multicast");
        assert_eq!(airplay_row.addresses, "192.168.1.52");
        assert_eq!(airplay_row.packets, 2);
        assert_eq!(
            groups
                .iter()
                .find(|row| row.service == "_companion-link._tcp")
                .unwrap()
                .addresses,
            "192.168.1.52"
        );
    }

    #[test]
    fn ipv4_is_paired_with_its_mac_and_traffic_types_stay_apart() {
        let mac_a = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let mac_b = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66];
        let v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 52));
        let other = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 53));
        let v6 = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 4));
        let mut announcements = HashMap::new();
        announcements.insert(
            AnnouncementKey {
                instance: "mb's macbook".to_string(),
                service: "_airplay._tcp".to_string(),
                source: v4,
                traffic: TrafficType::Multicast,
            },
            AnnouncementInfo {
                packets: 5,
                bytes: 500,
                extra_addresses: vec![v6],
                src_mac: Some(mac_a),
                ..AnnouncementInfo::default()
            },
        );
        announcements.insert(
            AnnouncementKey {
                instance: "mb's macbook".to_string(),
                service: "_airplay._tcp".to_string(),
                source: other,
                traffic: TrafficType::Multicast,
            },
            AnnouncementInfo {
                packets: 1,
                bytes: 100,
                src_mac: Some(mac_b),
                ..AnnouncementInfo::default()
            },
        );
        announcements.insert(
            AnnouncementKey {
                instance: "mb's macbook".to_string(),
                service: "_airplay._tcp".to_string(),
                source: v4,
                traffic: TrafficType::Unicast,
            },
            AnnouncementInfo {
                packets: 2,
                bytes: 200,
                src_mac: Some(mac_a),
                ..AnnouncementInfo::default()
            },
        );

        let groups = grouped_announcements(&announcements);
        assert_eq!(groups.len(), 2);
        let multicast = groups
            .iter()
            .find(|row| row.traffic == "multicast")
            .unwrap();
        assert_eq!(multicast.addresses, "192.168.1.52, aa:bb:cc:dd:ee:ff");
        assert_eq!(multicast.packets, 6);
        assert!(!multicast.addresses.contains("fe80"));
        assert!(!multicast.addresses.contains("192.168.1.53"));
        let unicast = groups.iter().find(|row| row.traffic == "unicast").unwrap();
        assert_eq!(unicast.addresses, "192.168.1.52, aa:bb:cc:dd:ee:ff");
        assert_eq!(unicast.packets, 2);
    }
}
