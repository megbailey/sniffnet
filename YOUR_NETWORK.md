# Your network

Rules for the Your network tab. The saved page name is `NetworkSweep`. The label is "Your network". Saved names `Analysis`, `Announcements`, and `YourTraffic` open this tab.

Tab order is Overview, Inspect, Your network, Notifications.

The page has one filter, then three regions:

1. Overheard Neighbors, full width.
2. A summary on the lower left: Size of subnet, with the Router under it, and the Neighbors list beside that.
3. Discovery on the lower right.

The filter text is shared by every region. It is cleared when a capture resets and is not saved. Matching is a case-insensitive substring of the visible text in that region. The placeholder is "Your network".

A link-local address is shown with the suffix `(link-local)`.

Column sort state stays on the running capture. It is not saved and is not cleared on reset. Choosing a new column starts at descending. Choosing it again cycles to ascending, then neutral. Neutral keeps the order the tables were built in. An IP column sorts by the numeric value of the first IPv4 address. An address that is not IPv4 sorts after every IPv4. The MAC column sorts as text.

## What counts as this network

An address is on this network when it is a remote host on the capture interface's subnet. Multicast, unspecified, this computer, and broadcast addresses are excluded from that test.

This computer's own interface addresses are listed in Overheard Neighbors. Discovery probes use the "on this network" test, so they do not treat this computer as a probe target.

A gateway IPv4 is a local address whose last octet is 1 or 254. The gateway becomes an Overheard Neighbor or a Neighbors-list address only by the rules in those sections.

## Overheard Neighbors

One row per device that sent traffic. Columns are Neighbor, IP address, MAC address, Protocol, Traffic, Service, and Packets. The card header shows the packet and byte totals of the visible rows. Rows that share an address contribute their totals once, using the larger count.

A row is created for an address that appears as a packet source and is either this computer or on this network. A destination that never sends has no row. A row with no packets is dropped.

### IP address and MAC

The IP address column lists every IPv4 and IPv6 address of the device: IPv4 first, then global IPv6, then link-local. The MAC column is separate. A row with no device MAC shows a dash.

The broadcast MAC `ff:ff:ff:ff:ff:ff` folds into another row for the same IPv4. A row with an announced name is preferred, then the row with more packets. Traffic with no MAC joins the only real MAC already recorded for that IPv4.

### One device from several addresses

An IPv4 that was both a destination and a source is a confirmed device. IPv6 and other non-IPv4 rows join that IPv4 when any of these is true:

- They share a real MAC. A shared MAC wins over a shared name.
- Their normalized resolved hostnames match. An mDNS instance or SRV target is not a name.
- An announcement attached the addresses to each other.

If more than one IPv4 matches, the lowest IPv4 is kept. Names are compared after trimming, lowercasing, turning a curly apostrophe into a straight one, and removing a trailing `.local`.

### Neighbor

The label is a resolved hostname from any of the device's addresses. A name learned on a link-local IPv6 address stays when an IPv4 address of the same device is present. A value that is empty or only an IP is ignored. A trailing dot is removed. When no hostname is known, the label is an address of the device.

mDNS still identifies the sender as a neighbor and counts its packets, protocols, and services. The instance name and SRV target inside that mDNS are not the neighbor's name. A query is included in that traffic. Records carried in the query stay with the device that responds.

The label is the name alone, with no role prefix.

Service names on the row are joined with commas. Protocols and traffic values are joined the same way. The Traffic column is unicast, multicast, or broadcast, taken from the destination of each flow.

### Clicking a row

Clicking a row opens Inspect. Both address filters are set to every IP address on the row. A packet matches when any of those addresses is the source or the destination. Editing or clearing a filter turns that either-address match off.

## Size of subnet

The number is the count of usable IPv4 host addresses on the capture interface. For each IPv4 address with a netmask, the host portion must be 2 to 16 bits. The network address and the broadcast address are excluded, so a `/24` is 254. The label under the number is the subnet, such as `192.168.1.0/24`. Several subnets are joined with commas.

## Neighbors list

The Neighbors list is every IPv4 address of an Overheard Neighbor. The heading is `Neighbors (count)`.

An address is listed when it appears on an Overheard Neighbors row. Sending any traffic on that device is enough. The address does not have to be the source of an ARP packet, and it does not have to span 30 seconds. A probe target that never sends stays out, because it is not an Overheard Neighbor. The list is sorted by numeric IPv4.

## Router

The Router section sits under Size of subnet. It shows the IPv4 and IPv6 of the identified gateway.

The gateway is a local IPv4 whose last octet is 1 or 254 and that appears in the capture. If more than one qualifies, the one that sent the most packets wins. A tie goes to the one seen in the most packets, then to the lower address. If none has been seen, the section says "No router identified."

IPv6 addresses are those that use a MAC belonging to that gateway and are either link-local or inside a local IPv6 subnet on the capture interface. This computer's own addresses, multicast, and unspecified addresses are excluded. The gateway MAC is the source MAC of packets the gateway sent, or the destination MAC of packets sent to it. All-zero, broadcast, IPv6 multicast (`33:33`), and IPv4 multicast (`01:00:5e`) MACs are ignored.

A public address forwarded by the router shares the gateway MAC and is left out. Global on-link addresses are listed before link-local ones.

## Discovery

Columns are Instance, Address, Protocol, Traffic, Service, and Packets. Traffic is unicast, multicast, or broadcast. The card header adds packet and byte totals for parsed announcements and for the probes below.

### Parsed announcements

UDP payloads are parsed when either port is 5353 (DNS-SD / mDNS) or 2021 (Bambu notify). An mDNS query is not an announcement. Records in a query are names the sender already knows, so they stay with the device that responds rather than the device that asked. Rows are grouped by instance, service, and traffic type. The address column is the busiest IPv4 source in the group and the MAC from the frame that sent it, written as `address, mac`. If the group has no IPv4, the busiest other address is shown. Protocols are UDP.

The instance is the DNS-SD instance, the name before the service type. For remote pairing that is often a UUID. The SRV target is stored with that announcement. A and AAAA records are attached when their owner name equals the SRV target, after lowercasing, up to three addresses. Those extra addresses link the device's other addresses in Overheard Neighbors. They do not supply the neighbor's name. The Discovery address column stays the busiest source.

A Bambu notify uses the device name and model from the payload. It has no SRV target.

### Probes

A non-ARP packet whose destination MAC is the broadcast address, and whose destination is on this network, is a sweep probe. It is listed whether or not anyone answered. The instance is "Sweep". The address is the target. The service column is the known service and port, the port alone, or a dash.

Repeated ARP aimed at a local address that never sends a packet is listed when the packet timestamps span at least 30 seconds. The instance is the asker, shown as `address, mac` when a real MAC is known. A single ARP request is omitted. ARP to an address that replies is omitted. The reply makes the sender an Overheard Neighbor.

### Not parsed yet

UDP 1900 (SSDP), 5355 (LLMNR), and 137 (NBNS) are announcement traffic. Their payloads stay in the "Not parsed yet" group under Discovery, with Service, Packets, and Bytes. Ports 5353 and 2021 are omitted from that group because they already have instance rows.
