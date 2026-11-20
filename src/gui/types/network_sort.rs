//! Column sort choices for Your network.

use std::cmp::Ordering;
use std::net::Ipv4Addr;

use crate::report::types::sort_type::SortType;

/// Which network table the click applies to.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetworkSort {
    /// Overheard Neighbors table.
    Neighbor(NeighborColumn),
    /// Discovery table. Columns match Overheard Neighbors.
    Announcement(NeighborColumn),
    /// Unparsed announcement groups.
    Group(GroupColumn),
    /// Occupied address list.
    Occupied,
}

/// Columns of the Overheard Neighbors table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NeighborColumn {
    /// Device label.
    Neighbor,
    /// IPv4 and IPv6 addresses.
    Address,
    /// Device MAC.
    Mac,
    /// Joined service names.
    Traffic,
    /// Packet protocols, such as UDP or ARP.
    Protocol,
    /// Unicast, multicast, or broadcast.
    TrafficType,
    /// Packet count.
    Packets,
}

/// Columns of an unparsed traffic group.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GroupColumn {
    /// Group label.
    Service,
    /// Packet count.
    Packets,
    /// Byte count.
    Bytes,
}

/// Arrow state to draw for one header.
pub fn shown_order<C: PartialEq>(active: &C, order: SortType, column: &C) -> SortType {
    if active == column {
        order
    } else {
        SortType::Neutral
    }
}

/// Choose `column`, or advance the order when it is already selected.
pub fn select_column<C: Copy + PartialEq>(current: &mut (C, SortType), column: C) {
    if current.0 == column {
        current.1 = current.1.next_sort();
    } else {
        *current = (column, SortType::Descending);
    }
}

/// Apply ascending or descending to a comparison. Neutral keeps the original direction.
pub fn directed(order: SortType, cmp: Ordering) -> Ordering {
    match order {
        SortType::Descending => cmp.reverse(),
        SortType::Ascending | SortType::Neutral => cmp,
    }
}

/// Numeric order of an IPv4 address, ignoring a trailing MAC.
pub fn ipv4_order(address: &str) -> u32 {
    let ip = address.split([',', ' ']).next().unwrap_or(address);
    ip.parse::<Ipv4Addr>().map_or(u32::MAX, u32::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_new_column_starts_descending_and_the_same_column_cycles() {
        let mut sort = (NeighborColumn::Packets, SortType::Neutral);
        select_column(&mut sort, NeighborColumn::Address);
        assert_eq!(sort, (NeighborColumn::Address, SortType::Descending));
        select_column(&mut sort, NeighborColumn::Address);
        assert_eq!(sort, (NeighborColumn::Address, SortType::Ascending));
        select_column(&mut sort, NeighborColumn::Address);
        assert_eq!(sort, (NeighborColumn::Address, SortType::Neutral));
    }

    #[test]
    fn ipv4_order_ignores_a_trailing_mac() {
        assert!(ipv4_order("192.168.1.9") < ipv4_order("192.168.1.66, aa:bb:cc:dd:ee:ff"));
        assert!(ipv4_order("192.168.1.100") > ipv4_order("192.168.1.20"));
    }
}
