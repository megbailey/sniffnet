use iced::widget::scrollable::Direction;
use iced::widget::text::Wrapping;
use iced::widget::tooltip::Position;
use iced::widget::{Column, Container, Row, Scrollable, Text, TextInput, Tooltip, button};
use iced::{Alignment, Element, Length, Padding};

use crate::gui::components::ellipsized_text::EllipsizedText;
use crate::gui::components::tab::get_pages_tabs;
use crate::gui::styles::container::ContainerType;
use crate::gui::styles::rule::RuleType;
use crate::gui::styles::scrollbar::ScrollbarType;
use crate::gui::styles::style_constants::{FONT_SIZE_FOOTER, FONT_SIZE_TITLE, TOOLTIP_DELAY};
use crate::gui::styles::text::TextType;
use crate::gui::styles::text_input::TextInputType;
use crate::gui::types::message::Message;
use crate::gui::types::network_sort::{
    AnnouncementColumn, GroupColumn, NeighborColumn, NetworkSort, directed, ipv4_order, shown_order,
};
use crate::gui::types::settings::Settings;
use crate::networking::analysis::{
    PurposeReport, TrafficGroup, TrafficPurpose, UNKNOWN_GROUP, report_traffic,
};
use crate::networking::announcements::{AnnouncementGroup, grouped_announcements};
use crate::networking::neighbors::LocalNeighbor;
use crate::networking::sweep::discovery_pings;
use crate::networking::types::data_representation::DataRepr;
use crate::report::types::sort_type::SortType;
use crate::translations::translations::{
    address_translation, bytes_translation, packets_translation,
};
use crate::translations::translations_3::service_translation;
use crate::translations::translations_6::{
    analysis_translation, announcements_translation, instance_translation,
    local_neighbors_translation, model_translation, neighbor_translation,
    no_announcements_translation, no_local_neighbors_translation, no_other_traffic_translation,
    not_parsed_yet_translation, sweep_ping_translation, traffic_translation,
    traffic_type_translation, unknown_purpose_translation,
};
use crate::{RunningPage, Sniffer, StyleType};

/// Body of the analysis page, to the right of Inspect.
pub fn analysis_page(sniffer: &Sniffer) -> Container<'_, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let tabs = get_pages_tabs(
        RunningPage::Analysis,
        language,
        sniffer.unread_notifications,
    );
    let report = report_traffic(&sniffer.info_traffic.map);
    let unknown = report
        .iter()
        .find(|item| item.purpose == TrafficPurpose::Unknown);
    let filter = TextInput::new(analysis_translation(language), &sniffer.announcement_filter)
        .on_input(Message::AnnouncementFilter)
        .padding([2, 5])
        .size(FONT_SIZE_FOOTER)
        .width(Length::Fill)
        .class(if sniffer.announcement_filter.is_empty() {
            TextInputType::Standard
        } else {
            TextInputType::Badge
        });

    let body = Column::new()
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .spacing(10)
        .push(filter)
        .push(
            Row::new()
                .spacing(10)
                .height(Length::Fill)
                .push(unknown_card(sniffer, unknown)),
        );

    Container::new(Column::new().push(tabs).push(body)).height(Length::Fill)
}

pub(crate) fn announcements_card<'a>(
    sniffer: &'a Sniffer,
    report: Option<&PurposeReport>,
) -> Container<'a, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let unparsed = visible_groups(sniffer, report.map_or(&[], |item| item.groups.as_slice()));
    let rows = visible_rows(sniffer);
    let pings = visible_pings(sniffer);
    let packets = report
        .map(|item| item.packets)
        .unwrap_or_default()
        .saturating_add(pings.iter().map(|ping| ping.packets).sum());
    let bytes = report
        .map(|item| item.bytes)
        .unwrap_or_default()
        .saturating_add(pings.iter().map(|ping| ping.bytes).sum());

    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if rows.is_empty() && pings.is_empty() && unparsed.is_empty() {
        listed = listed.push(
            Text::new(no_announcements_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else if !rows.is_empty() || !pings.is_empty() {
        listed = listed
            .push(announcement_header(language, sniffer.announcement_sort))
            .push(RuleType::Standard.horizontal(5));
        let mut combined = rows;
        combined.extend(pings);
        sort_announcements(&mut combined, sniffer.announcement_sort);
        for row in combined {
            listed = listed.push(announcement_row(&row));
        }
    }
    if !unparsed.is_empty() {
        listed = listed.push(
            Text::new(not_parsed_yet_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Subtitle),
        );
        let mut unparsed = unparsed;
        sort_groups(&mut unparsed, sniffer.group_sort);
        listed = listed
            .push(sorted_group_header(language, sniffer.group_sort))
            .push(RuleType::Standard.horizontal(5));
        for group in unparsed {
            listed = listed.push(group_row(language, group));
        }
    }

    card(
        announcements_translation(language),
        packets,
        bytes,
        Scrollable::with_direction(listed, Direction::Vertical(ScrollbarType::properties()))
            .width(Length::Fill)
            .height(Length::Fill),
        Length::FillPortion(3),
    )
}

pub(crate) fn neighbors_card<'a>(
    sniffer: &'a Sniffer,
    neighbors: &[LocalNeighbor],
) -> Container<'a, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let visible = visible_neighbors(sniffer, neighbors);
    let (packets, bytes) = neighbor_totals(&visible);

    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if visible.is_empty() {
        listed = listed.push(
            Text::new(no_local_neighbors_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else {
        listed = listed
            .push(neighbor_header(language, sniffer.neighbor_sort))
            .push(RuleType::Standard.horizontal(5));
        for neighbor in visible {
            listed = listed.push(neighbor_row(neighbor));
        }
    }

    card(
        local_neighbors_translation(language),
        packets,
        bytes,
        Scrollable::with_direction(listed, Direction::Vertical(ScrollbarType::properties()))
            .width(Length::Fill)
            .height(Length::Fill),
        Length::Fill,
    )
}

fn neighbor_totals(neighbors: &[&LocalNeighbor]) -> (u128, u128) {
    let mut seen = std::collections::HashMap::<&str, (u128, u128)>::new();
    for neighbor in neighbors {
        let entry = seen.entry(neighbor.address.as_str()).or_insert((0, 0));
        entry.0 = entry.0.max(neighbor.packets);
        entry.1 = entry.1.max(neighbor.bytes);
    }
    seen.values().fold((0, 0), |total, (packets, bytes)| {
        (
            total.0.saturating_add(*packets),
            total.1.saturating_add(*bytes),
        )
    })
}

fn unknown_card<'a>(
    sniffer: &'a Sniffer,
    report: Option<&PurposeReport>,
) -> Container<'a, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let packets = report.map(|item| item.packets).unwrap_or_default();
    let bytes = report.map(|item| item.bytes).unwrap_or_default();
    let groups = visible_groups(sniffer, report.map_or(&[], |item| item.groups.as_slice()));

    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if groups.is_empty() {
        listed = listed.push(
            Text::new(no_other_traffic_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else {
        listed = listed
            .push(group_header(language))
            .push(RuleType::Standard.horizontal(5));
        for group in groups {
            listed = listed.push(group_row(language, group));
        }
    }

    card(
        unknown_purpose_translation(language),
        packets,
        bytes,
        Scrollable::with_direction(listed, Direction::Vertical(ScrollbarType::properties()))
            .width(Length::Fill)
            .height(Length::Fill),
        Length::Fill,
    )
}

fn card<'a>(
    title: &'a str,
    packets: u128,
    bytes: u128,
    body: impl Into<Element<'a, Message, StyleType>>,
    width: Length,
) -> Container<'a, Message, StyleType> {
    let header = Row::new()
        .height(45)
        .align_y(Alignment::Center)
        .push(
            Text::new(title)
                .class(TextType::Title)
                .size(FONT_SIZE_TITLE)
                .width(Length::Fill),
        )
        .push(
            Text::new(format!(
                "{packets}    {}",
                DataRepr::bytes(false).formatted_string(bytes)
            ))
            .size(FONT_SIZE_FOOTER)
            .class(TextType::Subtitle),
        );

    Container::new(
        Column::new()
            .push(header)
            .push(body)
            .width(Length::Fill)
            .height(Length::Fill),
    )
    .width(width)
    .height(Length::Fill)
    .padding(Padding::new(7.0).top(0))
    .class(ContainerType::BorderedRound)
}

fn visible_pings(sniffer: &Sniffer) -> Vec<AnnouncementGroup> {
    let Settings { language, .. } = sniffer.conf.settings;
    let filter = filter_needle(sniffer);
    discovery_pings(
        &sniffer.info_traffic.map,
        sniffer.capture_source.get_addresses(),
    )
    .into_iter()
    .filter(|ping| {
        filter.is_empty()
            || sweep_ping_translation(language)
                .to_ascii_lowercase()
                .contains(&filter)
            || ping.detail.to_ascii_lowercase().contains(&filter)
            || ping.target.to_ascii_lowercase().contains(&filter)
    })
    .map(|ping| AnnouncementGroup {
        instance: sweep_ping_translation(language).to_string(),
        service: ping.detail,
        addresses: ping.target,
        traffic: "unicast".to_string(),
        model: String::new(),
        packets: ping.packets,
        bytes: ping.bytes,
    })
    .collect()
}

fn visible_rows(sniffer: &Sniffer) -> Vec<AnnouncementGroup> {
    let filter = filter_needle(sniffer);
    grouped_announcements(&sniffer.info_traffic.announcements)
        .into_iter()
        .filter(|row| {
            filter.is_empty()
                || row.instance.to_ascii_lowercase().contains(&filter)
                || row.service.to_ascii_lowercase().contains(&filter)
                || row.model.to_ascii_lowercase().contains(&filter)
                || row.addresses.to_ascii_lowercase().contains(&filter)
        })
        .collect()
}

fn visible_groups<'a>(sniffer: &Sniffer, groups: &'a [TrafficGroup]) -> Vec<&'a TrafficGroup> {
    let filter = filter_needle(sniffer);
    groups
        .iter()
        .filter(|group| filter.is_empty() || group.label.to_ascii_lowercase().contains(&filter))
        .collect()
}

fn filter_needle(sniffer: &Sniffer) -> String {
    sniffer.announcement_filter.trim().to_ascii_lowercase()
}

fn visible_neighbors<'a>(
    sniffer: &Sniffer,
    neighbors: &'a [LocalNeighbor],
) -> Vec<&'a LocalNeighbor> {
    let filter = filter_needle(sniffer);
    let mut visible: Vec<_> = neighbors
        .iter()
        .filter(|neighbor| {
            filter.is_empty()
                || neighbor.label.to_ascii_lowercase().contains(&filter)
                || neighbor.services.to_ascii_lowercase().contains(&filter)
                || neighbor.address.to_ascii_lowercase().contains(&filter)
        })
        .collect();
    sort_neighbors(&mut visible, sniffer.neighbor_sort);
    visible
}

fn sort_neighbors(rows: &mut [&LocalNeighbor], sort: (NeighborColumn, SortType)) {
    if sort.1 == SortType::Neutral {
        return;
    }
    rows.sort_by(|left, right| {
        let cmp = match sort.0 {
            NeighborColumn::Neighbor => left.label.cmp(&right.label),
            NeighborColumn::Address => ipv4_order(&left.address)
                .cmp(&ipv4_order(&right.address))
                .then_with(|| left.address.cmp(&right.address)),
            NeighborColumn::Traffic => left.services.cmp(&right.services),
            NeighborColumn::Packets => left.packets.cmp(&right.packets),
        };
        directed(sort.1, cmp)
    });
}

fn sort_announcements(rows: &mut [AnnouncementGroup], sort: (AnnouncementColumn, SortType)) {
    if sort.1 == SortType::Neutral {
        return;
    }
    rows.sort_by(|left, right| {
        let cmp = match sort.0 {
            AnnouncementColumn::Instance => left.instance.cmp(&right.instance),
            AnnouncementColumn::Traffic => left.service.cmp(&right.service),
            AnnouncementColumn::Address => ipv4_order(&left.addresses)
                .cmp(&ipv4_order(&right.addresses))
                .then_with(|| left.addresses.cmp(&right.addresses)),
            AnnouncementColumn::TrafficType => left.traffic.cmp(&right.traffic),
            AnnouncementColumn::Model => left.model.cmp(&right.model),
            AnnouncementColumn::Packets => left.packets.cmp(&right.packets),
        };
        directed(sort.1, cmp)
    });
}

fn sort_groups(rows: &mut [&TrafficGroup], sort: (GroupColumn, SortType)) {
    if sort.1 == SortType::Neutral {
        return;
    }
    rows.sort_by(|left, right| {
        let cmp = match sort.0 {
            GroupColumn::Service => left.label.cmp(&right.label),
            GroupColumn::Packets => left.packets.cmp(&right.packets),
            GroupColumn::Bytes => left.bytes.cmp(&right.bytes),
        };
        directed(sort.1, cmp)
    });
}

fn neighbor_header<'a>(
    language: crate::Language,
    sort: (NeighborColumn, SortType),
) -> Row<'a, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .align_y(Alignment::Center)
        .push(header_cell(
            neighbor_translation(language).to_string(),
            3,
            shown_order(&sort.0, sort.1, &NeighborColumn::Neighbor),
            Message::NetworkAnalysisSort(NetworkSort::Neighbor(NeighborColumn::Neighbor)),
        ))
        .push(header_cell(
            address_translation(language).to_string(),
            4,
            shown_order(&sort.0, sort.1, &NeighborColumn::Address),
            Message::NetworkAnalysisSort(NetworkSort::Neighbor(NeighborColumn::Address)),
        ))
        .push(header_cell(
            traffic_translation(language).to_string(),
            3,
            shown_order(&sort.0, sort.1, &NeighborColumn::Traffic),
            Message::NetworkAnalysisSort(NetworkSort::Neighbor(NeighborColumn::Traffic)),
        ))
        .push(header_cell(
            packets_translation(language).to_string(),
            1,
            shown_order(&sort.0, sort.1, &NeighborColumn::Packets),
            Message::NetworkAnalysisSort(NetworkSort::Neighbor(NeighborColumn::Packets)),
        ))
}

fn neighbor_row(neighbor: &LocalNeighbor) -> Row<'static, Message, StyleType> {
    let services = if neighbor.services.is_empty() {
        "—".to_string()
    } else {
        neighbor.services.clone()
    };
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .align_y(Alignment::Center)
        .push(cell(neighbor.label.clone(), 3, false))
        .push(cell(neighbor.address.clone(), 4, false))
        .push(cell(services, 3, false))
        .push(cell(neighbor.packets.to_string(), 1, false))
}

fn announcement_header<'a>(
    language: crate::Language,
    sort: (AnnouncementColumn, SortType),
) -> Row<'a, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .align_y(Alignment::Center)
        .push(header_cell(
            instance_translation(language).to_string(),
            3,
            shown_order(&sort.0, sort.1, &AnnouncementColumn::Instance),
            Message::NetworkAnalysisSort(NetworkSort::Announcement(AnnouncementColumn::Instance)),
        ))
        .push(header_cell(
            traffic_translation(language).to_string(),
            3,
            shown_order(&sort.0, sort.1, &AnnouncementColumn::Traffic),
            Message::NetworkAnalysisSort(NetworkSort::Announcement(AnnouncementColumn::Traffic)),
        ))
        .push(header_cell(
            address_translation(language).to_string(),
            3,
            shown_order(&sort.0, sort.1, &AnnouncementColumn::Address),
            Message::NetworkAnalysisSort(NetworkSort::Announcement(AnnouncementColumn::Address)),
        ))
        .push(header_cell(
            traffic_type_translation(language).to_string(),
            2,
            shown_order(&sort.0, sort.1, &AnnouncementColumn::TrafficType),
            Message::NetworkAnalysisSort(NetworkSort::Announcement(
                AnnouncementColumn::TrafficType,
            )),
        ))
        .push(header_cell(
            model_translation(language).to_string(),
            2,
            shown_order(&sort.0, sort.1, &AnnouncementColumn::Model),
            Message::NetworkAnalysisSort(NetworkSort::Announcement(AnnouncementColumn::Model)),
        ))
        .push(header_cell(
            packets_translation(language).to_string(),
            1,
            shown_order(&sort.0, sort.1, &AnnouncementColumn::Packets),
            Message::NetworkAnalysisSort(NetworkSort::Announcement(AnnouncementColumn::Packets)),
        ))
}

fn announcement_row(row: &AnnouncementGroup) -> Row<'static, Message, StyleType> {
    let model = if row.model.is_empty() {
        "—".to_string()
    } else {
        row.model.clone()
    };
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(row.instance.clone(), 3, false))
        .push(cell(row.service.clone(), 3, false))
        .push(cell(row.addresses.clone(), 3, false))
        .push(cell(row.traffic.clone(), 2, false))
        .push(cell(model, 2, false))
        .push(cell(row.packets.to_string(), 1, false))
}

fn sorted_group_header<'a>(
    language: crate::Language,
    sort: (GroupColumn, SortType),
) -> Row<'a, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .align_y(Alignment::Center)
        .push(header_cell(
            service_translation(language).to_string(),
            3,
            shown_order(&sort.0, sort.1, &GroupColumn::Service),
            Message::NetworkAnalysisSort(NetworkSort::Group(GroupColumn::Service)),
        ))
        .push(header_cell(
            packets_translation(language).to_string(),
            1,
            shown_order(&sort.0, sort.1, &GroupColumn::Packets),
            Message::NetworkAnalysisSort(NetworkSort::Group(GroupColumn::Packets)),
        ))
        .push(header_cell(
            bytes_translation(language).to_string(),
            2,
            shown_order(&sort.0, sort.1, &GroupColumn::Bytes),
            Message::NetworkAnalysisSort(NetworkSort::Group(GroupColumn::Bytes)),
        ))
}

fn group_header<'a>(language: crate::Language) -> Row<'a, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(service_translation(language).to_string(), 3, true))
        .push(cell(packets_translation(language).to_string(), 1, true))
        .push(cell(bytes_translation(language).to_string(), 2, true))
}

fn group_row(language: crate::Language, group: &TrafficGroup) -> Row<'static, Message, StyleType> {
    let label = if group.label == UNKNOWN_GROUP {
        unknown_purpose_translation(language).to_string()
    } else {
        group.label.clone()
    };
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(label, 3, false))
        .push(cell(group.packets.to_string(), 1, false))
        .push(cell(
            DataRepr::bytes(false).formatted_string(group.bytes),
            2,
            false,
        ))
}

fn header_cell<'a>(
    label: String,
    portion: u16,
    order: SortType,
    message: Message,
) -> Element<'a, Message, StyleType> {
    Row::new()
        .width(Length::FillPortion(portion))
        .align_y(Alignment::Center)
        .spacing(2)
        .push(Container::new(clipped_label(label, true)).width(Length::Fill))
        .push(sort_button(order, message))
        .into()
}

fn sort_button<'a>(order: SortType, message: Message) -> Element<'a, Message, StyleType> {
    button(order.icon())
        .class(order.button_type())
        .padding(0)
        .on_press(message)
        .into()
}

fn cell<'a>(label: String, portion: u16, title: bool) -> Element<'a, Message, StyleType> {
    Container::new(clipped_label(label, title))
        .width(Length::FillPortion(portion))
        .into()
}

fn clipped_label<'a>(label: String, title: bool) -> Element<'a, Message, StyleType> {
    let mut shown = EllipsizedText::new(label.clone())
        .size(FONT_SIZE_FOOTER)
        .width(Length::Fill)
        .wrapping(Wrapping::None);
    if title {
        shown = shown.class(TextType::Title);
    }
    let full = Container::new(
        Text::new(label)
            .size(FONT_SIZE_FOOTER)
            .wrapping(Wrapping::WordOrGlyph)
            .width(Length::Fixed(320.0)),
    )
    .padding(8)
    .width(Length::Fixed(336.0));
    let clipped = Container::new(shown).width(Length::Fill).clip(true);
    Tooltip::new(clipped, full, Position::FollowCursor)
        .gap(8)
        .class(ContainerType::Tooltip)
        .delay(TOOLTIP_DELAY)
        .into()
}
