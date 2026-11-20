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
use crate::networking::sweep::{RouterIdentity, identified_router, sweep_report};
use crate::report::types::sort_type::SortType;
use crate::translations::translations_6::{
    ipv4_translation, ipv6_translation, link_local_suffix_translation, network_sweep_translation,
    no_occupied_ips_translation, no_router_translation, occupied_ips_translation,
    possible_addresses_translation, router_translation,
};
use crate::utils::formatted_strings::label_link_local;
use crate::{RunningPage, Sniffer, StyleType};

/// Body of the Your network page.
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
    let filter = TextInput::new(
        network_sweep_translation(language),
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
    let router = identified_router(
        &sniffer.info_traffic.map,
        sniffer.capture_source.get_addresses(),
    );
    let sweep = Column::new()
        .width(Length::FillPortion(2))
        .height(Length::Fill)
        .push(investigated_section(
            language,
            &report,
            sniffer.occupied_sort,
            &router,
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
    router: &RouterIdentity,
) -> Container<'static, Message, StyleType> {
    let mut stats = Column::new().spacing(14).width(Length::Fill).push(stat(
        possible_addresses_translation(language),
        report.possible,
    ));
    if !report.network.is_empty() {
        stats = stats.push(
            Text::new(report.network.clone())
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    }
    stats = stats.push(router_section(language, router));

    Container::new(
        Row::new()
            .spacing(12)
            .height(Length::Fill)
            .push(stats.width(Length::FillPortion(1)).height(Length::Fill))
            .push(
                ip_list(
                    occupied_ips_translation(language),
                    no_occupied_ips_translation(language),
                    &report.occupied_ips,
                    occupied_sort,
                    NetworkSort::Occupied,
                    link_local_suffix_translation(language),
                )
                .width(Length::FillPortion(1)),
            ),
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
    link_local: &str,
) -> Column<'static, Message, StyleType> {
    let count = addresses.len();
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
            listed = listed
                .push(Text::new(label_link_local(&address, link_local)).size(FONT_SIZE_FOOTER));
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
                    Text::new(format!("{title} ({count})"))
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

fn router_section(
    language: crate::Language,
    router: &RouterIdentity,
) -> Column<'static, Message, StyleType> {
    let body = if router.ipv4.is_empty() {
        Column::new().push(
            Text::new(no_router_translation(language))
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        )
    } else {
        Column::new()
            .spacing(8)
            .push(address_family(
                ipv4_translation(language),
                &router.ipv4,
                link_local_suffix_translation(language),
            ))
            .push(address_family(
                ipv6_translation(language),
                &router.ipv6,
                link_local_suffix_translation(language),
            ))
    };
    Column::new()
        .height(Length::Fill)
        .spacing(4)
        .push(
            Text::new(router_translation(language))
                .class(TextType::Title)
                .size(FONT_SIZE_TITLE),
        )
        .push(
            Scrollable::with_direction(body, Direction::Vertical(ScrollbarType::properties()))
                .width(Length::Fill)
                .height(Length::Fill),
        )
}

fn address_family(
    label: &'static str,
    addresses: &[String],
    link_local: &str,
) -> Column<'static, Message, StyleType> {
    let mut family = Column::new().spacing(2).push(
        Text::new(label)
            .class(TextType::Subtitle)
            .size(FONT_SIZE_FOOTER),
    );
    if addresses.is_empty() {
        family = family.push(
            Text::new("—")
                .size(FONT_SIZE_FOOTER)
                .class(TextType::Dimmed),
        );
    } else {
        for address in addresses {
            family = family
                .push(Text::new(label_link_local(address, link_local)).size(FONT_SIZE_FOOTER));
        }
    }
    family
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
