use iced::widget::scrollable::Direction;
use iced::widget::{Column, Container, Row, Scrollable, Space, Text, TextInput};
use iced::{Alignment, Element, Length, Padding};

use crate::gui::components::tab::get_pages_tabs;
use crate::gui::styles::container::ContainerType;
use crate::gui::styles::rule::RuleType;
use crate::gui::styles::scrollbar::ScrollbarType;
use crate::gui::styles::style_constants::{FONT_SIZE_FOOTER, FONT_SIZE_TITLE};
use crate::gui::styles::text::TextType;
use crate::gui::styles::text_input::TextInputType;
use crate::gui::types::message::Message;
use crate::gui::types::settings::Settings;
use crate::networking::analysis::{
    PurposeReport, TrafficGroup, TrafficPurpose, UNKNOWN_GROUP, report_traffic,
};
use crate::networking::announcements::AnnouncementKey;
use crate::networking::neighbors::{KnownNeighbor, known_neighbors};
use crate::networking::types::data_representation::DataRepr;
use crate::translations::translations::{
    address_translation, bytes_translation, packets_translation,
};
use crate::translations::translations_3::service_translation;
use crate::translations::translations_6::{
    analysis_translation, announcements_translation, instance_translation,
    known_neighbors_translation, model_translation, neighbor_translation,
    no_announcements_translation, no_known_neighbors_translation, no_other_traffic_translation,
    not_parsed_yet_translation, traffic_translation, unknown_purpose_translation,
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
    let announcements = report
        .iter()
        .find(|item| item.purpose == TrafficPurpose::Announcement);
    let unknown = report
        .iter()
        .find(|item| item.purpose == TrafficPurpose::Unknown);
    let neighbors = known_neighbors(
        &sniffer.info_traffic.announcements,
        &sniffer.info_traffic.map,
        sniffer.capture_source.get_addresses(),
    );
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
                .push(neighbors_card(sniffer, &neighbors))
                .push(announcements_card(sniffer, announcements))
                .push(unknown_card(sniffer, unknown)),
        );

    Container::new(Column::new().push(tabs).push(body)).height(Length::Fill)
}

fn announcements_card<'a>(
    sniffer: &'a Sniffer,
    report: Option<&PurposeReport>,
) -> Container<'a, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let packets = report.map(|item| item.packets).unwrap_or_default();
    let bytes = report.map(|item| item.bytes).unwrap_or_default();
    let unparsed = visible_groups(sniffer, report.map_or(&[], |item| item.groups.as_slice()));
    let rows = visible_rows(sniffer);

    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if rows.is_empty() && unparsed.is_empty() {
        listed = listed.push(
            Text::new(no_announcements_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else if !rows.is_empty() {
        listed = listed
            .push(announcement_header(language))
            .push(RuleType::Standard.horizontal(5));
        for (key, info) in rows {
            listed = listed.push(announcement_row(key, info));
        }
    }
    if !unparsed.is_empty() {
        listed = listed.push(
            Text::new(not_parsed_yet_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Subtitle),
        );
        listed = listed
            .push(group_header(language))
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
        3,
    )
}

fn neighbors_card<'a>(
    sniffer: &'a Sniffer,
    neighbors: &[KnownNeighbor],
) -> Container<'a, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let packets = neighbors.iter().map(|neighbor| neighbor.packets).sum();
    let bytes = neighbors.iter().map(|neighbor| neighbor.bytes).sum();
    let visible = visible_neighbors(sniffer, neighbors);

    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if visible.is_empty() {
        listed = listed.push(
            Text::new(no_known_neighbors_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else {
        listed = listed
            .push(neighbor_header(language))
            .push(RuleType::Standard.horizontal(5));
        for neighbor in visible {
            listed = listed.push(neighbor_row(neighbor));
        }
    }

    card(
        known_neighbors_translation(language),
        packets,
        bytes,
        Scrollable::with_direction(listed, Direction::Vertical(ScrollbarType::properties()))
            .width(Length::Fill)
            .height(Length::Fill),
        3,
    )
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
        2,
    )
}

fn card<'a>(
    title: &'a str,
    packets: u128,
    bytes: u128,
    body: impl Into<Element<'a, Message, StyleType>>,
    portion: u16,
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
    .width(Length::FillPortion(portion))
    .height(Length::Fill)
    .padding(Padding::new(7.0).top(0))
    .class(ContainerType::BorderedRound)
}

fn visible_rows(
    sniffer: &Sniffer,
) -> Vec<(
    &AnnouncementKey,
    &crate::networking::announcements::AnnouncementInfo,
)> {
    let filter = filter_needle(sniffer);
    let mut rows: Vec<_> = sniffer
        .info_traffic
        .announcements
        .iter()
        .filter(|(key, info)| announcement_matches(&filter, key, info))
        .collect();
    rows.sort_by(|left, right| {
        right
            .1
            .packets
            .cmp(&left.1.packets)
            .then_with(|| left.0.instance.cmp(&right.0.instance))
            .then_with(|| left.0.service.cmp(&right.0.service))
    });
    rows
}

fn announcement_matches(
    filter: &str,
    key: &AnnouncementKey,
    info: &crate::networking::announcements::AnnouncementInfo,
) -> bool {
    filter.is_empty()
        || key.instance.to_ascii_lowercase().contains(filter)
        || key.service.to_ascii_lowercase().contains(filter)
        || info.model.to_ascii_lowercase().contains(filter)
        || key.source.to_string().contains(filter)
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
    neighbors: &'a [KnownNeighbor],
) -> Vec<&'a KnownNeighbor> {
    let filter = filter_needle(sniffer);
    neighbors
        .iter()
        .filter(|neighbor| {
            filter.is_empty()
                || neighbor.label.to_ascii_lowercase().contains(&filter)
                || neighbor.services.to_ascii_lowercase().contains(&filter)
                || neighbor.address.to_ascii_lowercase().contains(&filter)
        })
        .collect()
}

fn neighbor_header<'a>(language: crate::Language) -> Row<'a, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(neighbor_translation(language).to_string(), 3, true))
        .push(cell(address_translation(language).to_string(), 3, true))
        .push(cell(service_translation(language).to_string(), 3, true))
        .push(cell(packets_translation(language).to_string(), 1, true))
}

fn neighbor_row(neighbor: &KnownNeighbor) -> Row<'static, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(neighbor.label.clone(), 3, false))
        .push(cell(neighbor.address.clone(), 3, false))
        .push(cell(neighbor.services.clone(), 3, false))
        .push(cell(neighbor.packets.to_string(), 1, false))
}

fn announcement_header<'a>(language: crate::Language) -> Row<'a, Message, StyleType> {
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(instance_translation(language).to_string(), 3, true))
        .push(cell(service_translation(language).to_string(), 3, true))
        .push(cell(address_translation(language).to_string(), 3, true))
        .push(cell(traffic_translation(language).to_string(), 2, true))
        .push(cell(model_translation(language).to_string(), 2, true))
        .push(cell(packets_translation(language).to_string(), 1, true))
}

fn announcement_row(
    key: &AnnouncementKey,
    info: &crate::networking::announcements::AnnouncementInfo,
) -> Row<'static, Message, StyleType> {
    let model = if info.model.is_empty() {
        "—".to_string()
    } else {
        info.model.clone()
    };
    Row::new()
        .width(Length::Fill)
        .spacing(8)
        .push(cell(key.instance.clone(), 3, false))
        .push(cell(key.service.clone(), 3, false))
        .push(cell(info.address_label(key.source), 3, false))
        .push(cell(info.traffic_label(), 2, false))
        .push(cell(model, 2, false))
        .push(cell(info.packets.to_string(), 1, false))
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

fn cell<'a>(label: String, portion: u16, title: bool) -> Element<'a, Message, StyleType> {
    let text = Text::new(label).size(FONT_SIZE_FOOTER);
    let text = if title {
        text.class(TextType::Title)
    } else {
        text
    };
    Row::new()
        .width(Length::FillPortion(portion))
        .push(text)
        .push(Space::new().width(Length::Fill))
        .into()
}
