use std::collections::HashMap;
use std::fs;
use std::process::Command;
use std::time::{Duration, Instant};

use eframe::egui::{self, RichText, Ui};
use euphoria_plugins::{PluginHost, UiEvent, Widget, default_dir};

use crate::table::{self, Column, fill, fixed};
use crate::{tabs, theme};

const TICK: Duration = Duration::from_secs(1);
const LOCAL: [Column; 6] = [
    fill("Plugin"),
    fixed("Version", 90.0),
    fixed("Author", 150.0),
    fixed("Extra access", 130.0),
    fixed("State", 110.0),
    fixed("", 110.0),
];

#[derive(Clone, Copy, PartialEq)]
enum Section {
    Marketplace,
    Local,
}

pub struct PluginPage {
    pub host: PluginHost,
    section: Section,
    selected: Option<usize>,
    confirm: Option<usize>,
    queued: HashMap<(usize, usize), Vec<UiEvent>>,
    last_tick: Instant,
    message: Option<String>,
}

impl Default for PluginPage {
    fn default() -> Self {
        Self {
            host: PluginHost::open(default_dir()),
            section: Section::Marketplace,
            selected: None,
            confirm: None,
            queued: HashMap::new(),
            last_tick: Instant::now(),
            message: None,
        }
    }
}

impl PluginPage {
    pub fn poll(&mut self, ctx: &egui::Context) {
        if !self.host.wants_ticks() {
            return;
        }
        if self.last_tick.elapsed() >= TICK {
            self.last_tick = Instant::now();
            self.host.tick();
        }
        ctx.request_repaint_after(TICK);
    }

    fn open_folder(&mut self) {
        let dir = self.host.dir().to_path_buf();
        if let Err(error) = fs::create_dir_all(&dir) {
            self.message = Some(error.to_string());
            return;
        }
        let opener = if cfg!(windows) {
            "explorer"
        } else if cfg!(target_os = "macos") {
            "open"
        } else {
            "xdg-open"
        };
        if let Err(error) = Command::new(opener).arg(&dir).spawn() {
            self.message = Some(error.to_string());
        }
    }

    pub fn confirm_dialog(&mut self, ctx: &egui::Context) {
        let Some(index) = self.confirm else {
            return;
        };
        let Some(entry) = self.host.entries().get(index) else {
            self.confirm = None;
            return;
        };

        let name = entry.meta.name.clone();
        let permissions = entry.meta.permissions.join(", ");
        let mut choice = None;
        egui::Modal::new(egui::Id::unique("plugin_enable")).show(ctx, |ui| {
            ui.set_max_width(480.0);
            ui.label(RichText::new(format!("Turn on {name}?")).size(16.0));
            ui.add_space(8.0);
            ui.label(
                "Plugins run Lua code inside Euphoria. They can read the file you have open and \
                 add tabs, but they cannot touch your files or the network on their own.",
            );
            if !permissions.is_empty() {
                ui.add_space(6.0);
                ui.label(
                    RichText::new(format!("This plugin also asks for: {permissions}"))
                        .color(theme::NUMBER),
                );
            }
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button("Turn on").clicked() {
                    choice = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    choice = Some(false);
                }
            });
        });

        if let Some(enable) = choice {
            if enable {
                self.host.set_enabled(index, true);
            }
            self.confirm = None;
        }
    }
}

pub fn show(ui: &mut Ui, page: &mut PluginPage) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                for (section, title) in [
                    (Section::Marketplace, "Marketplace"),
                    (Section::Local, "Local"),
                ] {
                    let fill = if page.section == section {
                        theme::PILL
                    } else {
                        egui::Color32::TRANSPARENT
                    };
                    if ui.add(egui::Button::new(title).fill(fill)).clicked() {
                        page.section = section;
                    }
                }
            });
        });

    match page.section {
        Section::Marketplace => marketplace(ui),
        Section::Local => local(ui, page),
    }
}

fn marketplace(ui: &mut Ui) {
    ui.vertical_centered(|ui| {
        ui.add_space(ui.available_height() / 2.0 - 50.0);
        ui.label(
            RichText::new("The marketplace is not connected yet")
                .color(theme::MUTED)
                .size(20.0),
        );
        ui.add_space(6.0);
        ui.label(
            RichText::new(
                "It will list plugins from the Euphoria GitHub repo. Nothing is contacted for now.",
            )
            .color(theme::MUTED),
        );
    });
}

fn local(ui: &mut Ui, page: &mut PluginPage) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 2))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                if ui.button("Refresh").clicked() {
                    page.host.refresh();
                }
                if ui.button("Add examples").clicked() {
                    page.message = Some(match page.host.install_examples() {
                        Ok(added) => format!("Added {added} example plugins"),
                        Err(error) => error.to_string(),
                    });
                }
                if ui.button("Open folder").clicked() {
                    page.open_folder();
                }
                if let Some(message) = &page.message {
                    ui.label(RichText::new(message).color(theme::ACCENT));
                }
                let dir = page.host.dir().display().to_string();
                ui.add(
                    egui::Label::new(RichText::new(&dir).font(theme::mono()).color(theme::MUTED))
                        .truncate(),
                )
                .on_hover_text(&dir);
            });
        });
    ui.add_space(8.0);

    let count = page.host.entries().len();
    if count == 0 {
        tabs::no_results(
            ui,
            "No plugins yet. Add the examples or drop a .lua file in the folder.",
        );
        return;
    }

    if let Some(entry) = page
        .selected
        .and_then(|index| page.host.entries().get(index))
    {
        let description = entry.meta.description.clone();
        let error = entry.error.clone();
        let log = entry.log();
        egui::Panel::bottom("plugin_details")
            .default_size(170.0)
            .frame(
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .inner_margin(egui::Margin::symmetric(12, 8)),
            )
            .show(ui, |ui| {
                egui::ScrollArea::vertical()
                    .id_salt("plugin_log")
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.label(description);
                        if let Some(error) = error {
                            ui.label(RichText::new(error).color(theme::ERROR));
                        }
                        for line in log {
                            ui.label(RichText::new(line).font(theme::mono()).color(theme::MUTED));
                        }
                    });
            });
    }

    let mut toggle = None;
    let selected = &mut page.selected;
    let host = &page.host;
    table::show(
        ui,
        "plugins_local",
        &LOCAL,
        count,
        None,
        |ui, range, widths| {
            ui.spacing_mut().button_padding.y = 2.0;
            ui.spacing_mut().interact_size.y = 20.0;
            for index in range {
                let entry = &host.entries()[index];
                let row = table::row(ui, widths, *selected == Some(index));
                if row.response.clicked() {
                    *selected = Some(index);
                }

                let (state, color) = if entry.error.is_some() {
                    ("Stopped", theme::ERROR)
                } else if entry.is_running() {
                    ("On", theme::ACCENT)
                } else {
                    ("Off", theme::MUTED)
                };
                let access = entry.meta.permissions.join(", ");
                table::text(
                    ui,
                    row.cells[0],
                    &entry.meta.name,
                    theme::TEXT,
                    theme::body(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &entry.meta.version,
                    theme::MUTED,
                    theme::body(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &entry.meta.author,
                    theme::MUTED,
                    theme::body(),
                );
                table::text(ui, row.cells[3], &access, theme::NUMBER, theme::body());
                table::text(ui, row.cells[4], state, color, theme::body());

                let title = if entry.is_running() {
                    "Turn off"
                } else {
                    "Turn on"
                };
                let button = row.cells[5].shrink2(egui::vec2(6.0, 3.0));
                if ui.put(button, egui::Button::new(title)).clicked() {
                    toggle = Some((index, entry.is_running()));
                }
            }
        },
    );

    match toggle {
        Some((index, true)) => page.host.set_enabled(index, false),
        Some((index, false)) => page.confirm = Some(index),
        None => {}
    }
}

// Draws a tab a plugin added. Returns false when the plugin has stopped.
pub fn plugin_tab(ui: &mut Ui, page: &mut PluginPage, plugin: usize, tab: usize) -> bool {
    let events = page.queued.remove(&(plugin, tab)).unwrap_or_default();
    let Some(widgets) = page.host.draw(plugin, tab, events) else {
        return false;
    };

    let mut next = Vec::new();
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(16, 12))
        .show(ui, |ui| {
            egui::ScrollArea::vertical()
                .id_salt(("plugin_tab", plugin, tab))
                .auto_shrink(false)
                .show(ui, |ui| render(ui, &widgets, &mut next));
        });

    if !next.is_empty() {
        page.queued.insert((plugin, tab), next);
        ui.ctx().request_repaint();
    }
    true
}

fn render(ui: &mut Ui, widgets: &[Widget], events: &mut Vec<UiEvent>) {
    for (position, widget) in widgets.iter().enumerate() {
        match widget {
            Widget::Heading(text) => {
                ui.label(RichText::new(text).size(18.0));
            }
            Widget::Label(text) => {
                ui.label(text);
            }
            Widget::Mono(text) => {
                ui.label(RichText::new(text).font(theme::mono()));
            }
            Widget::Separator => {
                ui.separator();
            }
            Widget::Button { id, text } => {
                if ui.button(text).clicked() {
                    events.push(UiEvent::Clicked(*id));
                }
            }
            Widget::Input { key, hint, value } => {
                let mut text = value.clone();
                let field = egui::TextEdit::singleline(&mut text)
                    .id_salt(("plugin_input", key))
                    .hint_text(hint)
                    .desired_width(420.0);
                if ui.add(field).changed() {
                    events.push(UiEvent::Text {
                        key: key.clone(),
                        value: text,
                    });
                }
            }
            Widget::Checkbox { key, text, value } => {
                let mut checked = *value;
                if ui.checkbox(&mut checked, text).changed() {
                    events.push(UiEvent::Toggled {
                        key: key.clone(),
                        value: checked,
                    });
                }
            }
            Widget::Row(children) => {
                ui.horizontal(|ui| render(ui, children, events));
            }
            Widget::Table { headers, rows } => {
                egui::Grid::new(("plugin_table", position))
                    .striped(true)
                    .spacing(egui::vec2(24.0, 6.0))
                    .show(ui, |ui| {
                        for header in headers {
                            ui.label(RichText::new(header).color(theme::MUTED));
                        }
                        ui.end_row();
                        for row in rows {
                            for cell in row {
                                ui.label(RichText::new(cell).font(theme::mono()));
                            }
                            ui.end_row();
                        }
                    });
            }
        }
    }
}
