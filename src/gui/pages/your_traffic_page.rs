//! Packets this computer sent or received.

use iced::Length;
use iced::widget::scrollable::Direction;
use iced::widget::{Column, Container, Scrollable, Text, TextInput};

use super::analysis_page::{announcement_row, card, device_header, sort_announcements};
use crate::gui::components::tab::get_pages_tabs;
use crate::gui::styles::rule::RuleType;
use crate::gui::styles::scrollbar::ScrollbarType;
use crate::gui::styles::style_constants::FONT_SIZE_FOOTER;
use crate::gui::styles::text::TextType;
use crate::gui::styles::text_input::TextInputType;
use crate::gui::types::message::Message;
use crate::gui::types::network_sort::NetworkSort;
use crate::gui::types::settings::Settings;
use crate::networking::announcements::AnnouncementGroup;
use crate::networking::host_traffic::your_traffic;
use crate::networking::neighbors::neighbor_name;
use crate::translations::translations_6::{
    instance_translation, no_your_traffic_translation, your_traffic_translation,
};
use crate::{RunningPage, Sniffer, StyleType};

/// Body of the Your traffic page.
pub fn your_traffic_page(sniffer: &Sniffer) -> Container<'_, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let tabs = get_pages_tabs(
        RunningPage::YourTraffic,
        language,
        sniffer.unread_notifications,
    );
    let filter = TextInput::new(
        your_traffic_translation(language),
        &sniffer.announcement_filter,
    )
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
        .push(traffic_card(sniffer));

    Container::new(Column::new().push(tabs).push(body)).height(Length::Fill)
}

fn traffic_card(sniffer: &Sniffer) -> Container<'_, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let rows = visible_rows(sniffer);
    let packets = rows.iter().map(|row| row.packets).sum();
    let bytes = rows.iter().map(|row| row.bytes).sum();
    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if rows.is_empty() {
        listed = listed.push(
            Text::new(no_your_traffic_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else {
        listed = listed
            .push(device_header(
                language,
                sniffer.your_traffic_sort,
                instance_translation(language),
                |column| Message::NetworkAnalysisSort(NetworkSort::YourTraffic(column)),
            ))
            .push(RuleType::Standard.horizontal(5));
        for row in &rows {
            listed = listed.push(announcement_row(row));
        }
    }

    card(
        your_traffic_translation(language),
        packets,
        bytes,
        Scrollable::with_direction(listed, Direction::Vertical(ScrollbarType::properties()))
            .width(Length::Fill)
            .height(Length::Fill),
        Length::Fill,
    )
}

fn visible_rows(sniffer: &Sniffer) -> Vec<AnnouncementGroup> {
    let names = sniffer
        .addresses_resolved
        .iter()
        .filter_map(|(address, (rdns, host))| {
            neighbor_name(rdns, &host.domain).map(|name| (*address, name))
        })
        .collect();
    let filter = sniffer.announcement_filter.trim().to_ascii_lowercase();
    let mut rows = your_traffic(
        &sniffer.info_traffic.map,
        &sniffer.info_traffic.announcements,
        sniffer.capture_source.get_addresses(),
        &names,
    )
    .into_iter()
    .filter(|row| row_matches(row, &filter))
    .collect::<Vec<_>>();
    sort_announcements(&mut rows, sniffer.your_traffic_sort);
    rows
}

fn row_matches(row: &AnnouncementGroup, filter: &str) -> bool {
    filter.is_empty()
        || row.instance.to_ascii_lowercase().contains(filter)
        || row.service.to_ascii_lowercase().contains(filter)
        || row.protocols.to_ascii_lowercase().contains(filter)
        || row.traffic.to_ascii_lowercase().contains(filter)
        || row.addresses.to_ascii_lowercase().contains(filter)
}
