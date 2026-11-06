use std::collections::BTreeMap;
use std::path::PathBuf;

use eframe::egui::{self, Align, Color32, Layout, RichText, Stroke, StrokeKind, Vec2};

use crate::samples;
use crate::theme;

const CARD_WIDTH: f32 = 400.0;
const CARD_GAP: f32 = 14.0;

struct Step {
    anchor: Option<&'static str>,
    title: &'static str,
    body: &'static str,
}

const STEPS: [Step; 6] = [
    Step {
        anchor: Some("logo"),
        title: "The Euphoria menu",
        body: "Everything starts here: open a binary, attach to a running process, or replay this tour.",
    },
    Step {
        anchor: Some("open"),
        title: "Open something to inspect",
        body: "Type a path or use Browse. Euphoria decodes PE, ELF, Mach-O, APK, and its own .euph datasets.",
    },
    Step {
        anchor: Some("tab_listing"),
        title: "Listing",
        body: "The disassembly. Click a line to select it, press Space for the graph, or right-click a line for quick patches.",
    },
    Step {
        anchor: Some("tab_debugger"),
        title: "Debugger",
        body: "Run a binary with F9, step with F7 and F8, pause with F3, and edit memory or registers while stopped.",
    },
    Step {
        anchor: Some("tab_advanced"),
        title: "Advanced",
        body: "Byte-pattern search, XOR recovery, SQL, and the APK analyzer live behind this switch.",
    },
    Step {
        anchor: None,
        title: "Try a sample",
        body: "These files are bundled so you can explore without hunting for a target. Each one is safe to open.",
    },
];

#[derive(Default, serde::Serialize, serde::Deserialize)]
struct Marker {
    toured: bool,
}

pub enum GuideAction {
    None,
    Open(PathBuf),
}

pub struct Guide {
    anchors: BTreeMap<&'static str, egui::Rect>,
    open: bool,
    welcome: bool,
    step: usize,
}

impl Default for Guide {
    fn default() -> Self {
        Self {
            anchors: BTreeMap::new(),
            open: false,
            welcome: true,
            step: 0,
        }
    }
}

impl Guide {
    pub fn load(has_file: bool) -> Self {
        let toured = marker_path()
            .and_then(|path| std::fs::read_to_string(path).ok())
            .and_then(|text| serde_json::from_str::<Marker>(&text).ok())
            .is_some_and(|marker| marker.toured);
        Self {
            welcome: !toured && !has_file,
            ..Self::default()
        }
    }

    pub fn start(&mut self) {
        self.open = true;
        self.welcome = false;
        self.step = 0;
    }

    pub fn is_open(&self) -> bool {
        self.open || self.welcome
    }

    pub fn record(&mut self, anchor: &'static str, rect: egui::Rect) {
        self.anchors.insert(anchor, rect);
    }

    fn persist(&self) {
        let Some(path) = marker_path() else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        if let Ok(text) = serde_json::to_string_pretty(&Marker { toured: true }) {
            let _ = std::fs::write(path, text);
        }
    }

    pub fn show(&mut self, ctx: &egui::Context) -> GuideAction {
        if self.welcome {
            return match self.welcome_modal(ctx) {
                Welcome::None => GuideAction::None,
                Welcome::Start => {
                    self.start();
                    GuideAction::None
                }
                Welcome::Skip => {
                    self.welcome = false;
                    self.persist();
                    GuideAction::None
                }
                Welcome::Sample(path) => {
                    self.welcome = false;
                    self.persist();
                    GuideAction::Open(path)
                }
            };
        }
        if self.open {
            return self.tour(ctx);
        }
        GuideAction::None
    }

    fn welcome_modal(&mut self, ctx: &egui::Context) -> Welcome {
        let mut choice = Welcome::None;
        let response = egui::Modal::new(egui::Id::unique("guide_welcome")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.label(RichText::new("Welcome to Euphoria").size(24.0).strong());
            ui.add_space(6.0);
            ui.label(
                RichText::new(
                    "A workbench for disassembly, decompilation, patching, and live process \
                     inspection.",
                )
                .color(theme::MUTED),
            );
            ui.add_space(12.0);
            for line in [
                "Decode PE, ELF, Mach-O, APK, and .euph datasets",
                "Decompile routines and follow cross-references",
                "Patch bytes, registers, and running processes",
            ] {
                ui.label(RichText::new(format!("•  {line}")).color(theme::TEXT));
            }
            ui.add_space(14.0);
            ui.label(RichText::new("Want a quick guided tour?").strong());
            ui.label(
                RichText::new(
                    "It highlights the main controls step by step. You can stop it at any time.",
                )
                .color(theme::MUTED),
            );
            ui.add_space(12.0);

            let found = samples::locate();
            if !found.is_empty() {
                ui.label(RichText::new("Bundled samples").color(theme::MUTED));
                ui.horizontal_wrapped(|ui| {
                    for sample in &found {
                        if ui
                            .button(sample.title)
                            .on_hover_text(sample.blurb)
                            .clicked()
                        {
                            choice = Welcome::Sample(sample.path.clone());
                        }
                    }
                });
                ui.add_space(10.0);
            }

            ui.horizontal(|ui| {
                if ui
                    .add(
                        egui::Button::new(
                            RichText::new("Take the quick tour").color(theme::BACKGROUND),
                        )
                        .fill(theme::ACCENT),
                    )
                    .clicked()
                {
                    choice = Welcome::Start;
                }
                if ui.button("Skip for now").clicked() {
                    choice = Welcome::Skip;
                }
                ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                    ui.label(
                        RichText::new("Replay it later from the logo menu").color(theme::MUTED),
                    );
                });
            });
        });
        if response.should_close() && matches!(choice, Welcome::None) {
            choice = Welcome::Skip;
        }
        choice
    }

    fn tour(&mut self, ctx: &egui::Context) -> GuideAction {
        self.step = self.step.min(STEPS.len() - 1);
        let step = &STEPS[self.step];
        let screen = ctx.content_rect();
        let anchor = step.anchor.and_then(|key| self.anchors.get(key).copied());

        let mut action = GuideAction::None;
        let mut close = false;
        let mut back = false;
        let mut next = false;

        egui::Area::new(egui::Id::unique("guide_dim"))
            .order(egui::Order::Foreground)
            .fixed_pos(screen.min)
            .interactable(true)
            .show(ctx, |ui| {
                let response = ui.allocate_response(screen.size(), egui::Sense::click());
                let painter = ui.painter();
                let dim = Color32::from_black_alpha(180);
                if let Some(rect) = anchor {
                    let hole = rect.expand(4.0);
                    for area in [
                        egui::Rect::from_min_max(screen.min, egui::pos2(screen.max.x, hole.min.y)),
                        egui::Rect::from_min_max(egui::pos2(screen.min.x, hole.max.y), screen.max),
                        egui::Rect::from_min_max(
                            egui::pos2(screen.min.x, hole.min.y),
                            egui::pos2(hole.min.x, hole.max.y),
                        ),
                        egui::Rect::from_min_max(
                            egui::pos2(hole.max.x, hole.min.y),
                            egui::pos2(screen.max.x, hole.max.y),
                        ),
                    ] {
                        painter.rect_filled(area, 0.0, dim);
                    }
                    painter.rect_stroke(
                        hole,
                        8.0,
                        Stroke::new(2.0, theme::ACCENT),
                        StrokeKind::Outside,
                    );
                } else {
                    painter.rect_filled(screen, 0.0, dim);
                }
                let _ = response;
            });
        if ctx.input(|input| input.key_pressed(egui::Key::Escape)) {
            close = true;
        }

        let size = Vec2::new(CARD_WIDTH, 240.0);
        let position = card_position(screen, anchor, size);
        egui::Area::new(egui::Id::unique("guide_card"))
            .order(egui::Order::Tooltip)
            .fixed_pos(position)
            .constrain(true)
            .show(ctx, |ui| {
                egui::Frame::new()
                    .fill(theme::SURFACE)
                    .stroke(Stroke::new(1.0, theme::BORDER))
                    .inner_margin(egui::Margin::same(16))
                    .corner_radius(10)
                    .show(ui, |ui| {
                        ui.set_width(CARD_WIDTH);
                        ui.horizontal(|ui| {
                            ui.label(
                                RichText::new(format!("Step {} of {}", self.step + 1, STEPS.len()))
                                    .color(theme::ACCENT)
                                    .font(theme::mono()),
                            );
                            ui.with_layout(Layout::right_to_left(Align::Center), |ui| {
                                if ui.small_button("Skip").clicked() {
                                    close = true;
                                }
                            });
                        });
                        ui.add_space(4.0);
                        ui.label(RichText::new(step.title).size(18.0).strong());
                        ui.add_space(4.0);
                        ui.label(RichText::new(step.body).color(theme::MUTED));
                        if step.anchor.is_none() {
                            ui.add_space(10.0);
                            for sample in samples::locate() {
                                if ui
                                    .button(sample.title)
                                    .on_hover_text(sample.blurb)
                                    .clicked()
                                {
                                    action = GuideAction::Open(sample.path);
                                    close = true;
                                }
                            }
                        }
                        ui.add_space(12.0);
                        ui.horizontal(|ui| {
                            if ui
                                .add_enabled(self.step > 0, egui::Button::new("Back"))
                                .clicked()
                            {
                                back = true;
                            }
                            let last = self.step + 1 == STEPS.len();
                            let label = if last { "Finish" } else { "Next" };
                            if ui
                                .add(
                                    egui::Button::new(
                                        RichText::new(label).color(theme::BACKGROUND),
                                    )
                                    .fill(theme::ACCENT),
                                )
                                .clicked()
                            {
                                next = true;
                            }
                        });
                    });
            });

        if close {
            self.open = false;
            self.persist();
        } else if back {
            self.step = self.step.saturating_sub(1);
        } else if next {
            if self.step + 1 == STEPS.len() {
                self.open = false;
                self.persist();
            } else {
                self.step += 1;
            }
        }
        action
    }
}

enum Welcome {
    None,
    Start,
    Skip,
    Sample(PathBuf),
}

fn card_position(screen: egui::Rect, anchor: Option<egui::Rect>, size: Vec2) -> egui::Pos2 {
    let Some(anchor) = anchor else {
        return egui::pos2(
            (screen.center().x - CARD_WIDTH / 2.0).max(12.0),
            (screen.center().y - 120.0).max(12.0),
        );
    };
    let below = anchor.center().y < screen.center().y;
    let y = if below {
        anchor.max.y + CARD_GAP
    } else {
        anchor.min.y - CARD_GAP - 240.0
    };
    let x = (anchor.center().x - CARD_WIDTH / 2.0)
        .clamp(12.0, (screen.max.x - CARD_WIDTH - 12.0).max(12.0));
    egui::pos2(x, y.clamp(12.0, (screen.max.y - size.y - 12.0).max(12.0)))
}

fn marker_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("Euphoria").join("guide.json"))
}
