use iced::widget::scrollable::Direction;
use iced::widget::{Column, Container, Row, Scrollable, Text, TextInput, button};
use iced::{Alignment, Length, Padding};

use super::analysis_page::{announcements_card, neighbors_card};
use crate::gui::components::tab::get_pages_tabs;
use crate::gui::styles::container::ContainerType;
use crate::gui::styles::scrollbar::ScrollbarType;
use crate::gui::styles::style_constants::{FONT_SIZE_FOOTER, FONT_SIZE_TITLE};
use crate::gui::styles::text::TextType;
use crate::gui::styles::text_input::TextInputType;
use crate::gui::types::message::Message;
use crate::gui::types::network_sort::{NetworkSort, directed, ipv4_order};
use crate::gui::types::settings::Settings;
use crate::networking::analysis::{TrafficPurpose, report_traffic};
use crate::networking::neighbors::{local_neighbors, neighbor_name};
use crate::networking::sweep::sweep_report;
use crate::report::types::sort_type::SortType;
use crate::translations::translations_6::{
    analysis_translation, free_ips_translation, investigated_translation, no_free_ips_translation,
    no_occupied_ips_translation, no_reply_translation, occupied_ips_translation,
    occupied_translation, of_translation, possible_addresses_translation,
};
use crate::{RunningPage, Sniffer, StyleType};

/// Body of the network sweep page, to the right of Analysis.
pub fn network_sweep_page(sniffer: &Sniffer) -> Container<'_, Message, StyleType> {
    let Settings { language, .. } = sniffer.conf.settings;
    let tabs = get_pages_tabs(
        RunningPage::NetworkSweep,
        language,
        sniffer.unread_notifications,
    );
    let report = sweep_report(
        &sniffer.info_traffic.map,
        sniffer.capture_source.get_addresses(),
    );
    let traffic = report_traffic(&sniffer.info_traffic.map);
    let announcements = traffic
        .iter()
        .find(|item| item.purpose == TrafficPurpose::Announcement);
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

    let names = sniffer
        .addresses_resolved
        .iter()
        .filter_map(|(address, (rdns, host))| {
            neighbor_name(rdns, &host.domain).map(|name| (*address, name))
        })
        .collect();
    let neighbors = local_neighbors(
        &sniffer.info_traffic.announcements,
        &sniffer.info_traffic.map,
        sniffer.capture_source.get_addresses(),
        &names,
    );
    let sweep = Column::new()
        .width(Length::FillPortion(2))
        .height(Length::Fill)
        .push(investigated_section(
            language,
            &report,
            sniffer.occupied_sort,
            sniffer.free_sort,
        ));

    let body = Column::new()
        .width(Length::Fill)
        .height(Length::Fill)
        .padding(10)
        .spacing(10)
        .push(filter)
        .push(neighbors_card(sniffer, &neighbors))
        .push(
            Row::new()
                .spacing(10)
                .height(Length::Fill)
                .push(sweep)
                .push(announcements_card(sniffer, announcements)),
        );

    Container::new(Column::new().push(tabs).push(body)).height(Length::Fill)
}

fn investigated_section(
    language: crate::Language,
    report: &crate::networking::sweep::SweepReport,
    occupied_sort: SortType,
    free_sort: SortType,
) -> Container<'static, Message, StyleType> {
    let mut stats = Column::new()
        .spacing(14)
        .width(Length::Fill)
        .push(stat(
            investigated_translation(language),
            report.investigated,
        ))
        .push(stat(no_reply_translation(language), report.no_reply))
        .push(stat(
            possible_addresses_translation(language),
            report.possible,
        ))
        .push(stat(occupied_translation(language), report.occupied));
    if report.possible > 0 {
        stats = stats.push(
            Text::new(format!(
                "{} {} {}",
                report.occupied,
                of_translation(language),
                report.possible
            ))
            .size(FONT_SIZE_FOOTER)
            .class(TextType::Dimmed),
        );
    }
    if !report.network.is_empty() {
        stats = stats.push(
            Text::new(report.network.clone())
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    }

    let lists = Column::new()
        .width(Length::Fill)
        .height(Length::Fill)
        .spacing(8)
        .push(
            ip_list(
                occupied_ips_translation(language),
                no_occupied_ips_translation(language),
                &report.occupied_ips,
                occupied_sort,
                NetworkSort::Occupied,
            )
            .height(Length::FillPortion(1)),
        )
        .push(
            ip_list(
                free_ips_translation(language),
                no_free_ips_translation(language),
                &report.free_ips,
                free_sort,
                NetworkSort::Free,
            )
            .height(Length::FillPortion(1)),
        );

    Container::new(
        Row::new()
            .spacing(12)
            .height(Length::Fill)
            .push(stats.width(Length::FillPortion(1)).height(Length::Fill))
            .push(lists.width(Length::FillPortion(1))),
    )
    .width(Length::Fill)
    .height(Length::Fill)
    .padding(Padding::new(12.0))
    .class(ContainerType::BorderedRound)
}

fn ip_list(
    title: &'static str,
    empty: &'static str,
    addresses: &[String],
    order: SortType,
    target: NetworkSort,
) -> Column<'static, Message, StyleType> {
    let mut addresses = addresses.to_vec();
    if order != SortType::Neutral {
        addresses.sort_by(|left, right| directed(order, ipv4_order(left).cmp(&ipv4_order(right))));
    }
    let mut listed = Column::new().spacing(2).width(Length::Fill);
    if addresses.is_empty() {
        listed = listed.push(
            Text::new(empty)
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else {
        for address in addresses {
            listed = listed.push(Text::new(address).size(FONT_SIZE_FOOTER));
        }
    }
    Column::new()
        .height(Length::Fill)
        .spacing(4)
        .push(
            Row::new()
                .align_y(Alignment::Center)
                .spacing(4)
                .push(
                    Text::new(title)
                        .class(TextType::Title)
                        .size(FONT_SIZE_TITLE),
                )
                .push(
                    button(order.icon())
                        .class(order.button_type())
                        .padding(0)
                        .on_press(Message::NetworkAnalysisSort(target)),
                ),
        )
        .push(
            Scrollable::with_direction(listed, Direction::Vertical(ScrollbarType::properties()))
                .width(Length::Fill)
                .height(Length::Fill),
        )
}

fn stat(label: &str, value: u128) -> Column<'_, Message, StyleType> {
    Column::new()
        .spacing(2)
        .push(
            Text::new(label)
                .class(TextType::Title)
                .size(FONT_SIZE_TITLE),
        )
        .push(Text::new(value.to_string()).size(28))
}
