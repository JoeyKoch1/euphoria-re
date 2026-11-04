use std::sync::Arc;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, RichText, Sense, Stroke, Ui};
use euphoria_engine::{
    Analysis, Confidence, PACKED_ENTROPY, XorHit, entropy, entropy_label, parse_hex, scan_xor, xor,
};

use crate::table::{self, Column, fill, fixed};
use crate::tabs::{self, Action};
use crate::{Project, theme};

const MAX_ENTROPY: f32 = 8.0;
const BAR_WIDTH: f32 = 220.0;
const DEFAULT_XOR_LEN: &str = "256";
const MAX_PREVIEW_BYTES: usize = 4096;

const SECTIONS: [Column; 5] = [
    fixed("Section", 160.0),
    fixed("Starts", 170.0),
    fixed("Bytes", 110.0),
    fixed("Entropy", 110.0),
    fill("Randomness"),
];
const HITS: [Column; 3] = [
    fixed("Found at", 170.0),
    fixed("Key", 80.0),
    fill("Reads as"),
];

fn entropy_color(value: f32) -> egui::Color32 {
    if value >= PACKED_ENTROPY {
        theme::ERROR
    } else if value >= 6.5 {
        theme::NUMBER
    } else {
        theme::ACCENT
    }
}

pub fn card(ui: &mut Ui, add: impl FnOnce(&mut Ui)) {
    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(14, 12))
        .show(ui, add);
}

// Hands an address to the default browser. Nothing in Euphoria signs in or uploads by itself.
pub fn open_external(target: &str) {
    let opener = if cfg!(windows) {
        "explorer"
    } else if cfg!(target_os = "macos") {
        "open"
    } else {
        "xdg-open"
    };
    let _ = std::process::Command::new(opener).arg(target).spawn();
}

pub fn overview(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let report = &project.inspection;
    let base64 = project
        .listing
        .strings
        .iter()
        .filter(|entry| entry.base64.is_some())
        .count();

    card(ui, |ui| {
        ui.horizontal(|ui| {
            ui.vertical(|ui| {
                ui.label(RichText::new("Entropy").color(theme::MUTED));
                ui.label(
                    RichText::new(format!("{:.2} / 8.00", report.entropy))
                        .size(26.0)
                        .color(entropy_color(report.entropy)),
                )
                .on_hover_text(
                    "How random the bytes are, from 0.0 to 8.0. Near 8.0 usually means packed, \
                     compressed, or encrypted data. It measures randomness, not how strong any \
                     encryption is.",
                );
                ui.label(RichText::new(entropy_label(report.entropy)).color(theme::MUTED));
            });
            ui.add_space(48.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Identity").color(theme::MUTED));
                ui.label(
                    RichText::new(format!("SHA-256 {}", project.analysis.sha256))
                        .font(theme::mono())
                        .size(11.5),
                );
                ui.label(format!("{} bytes", report.size));
                ui.label(format!("{} imports", report.import_count));
                ui.label(format!("Base64 strings: {base64}"));
            });
            ui.add_space(48.0);
            ui.vertical(|ui| {
                ui.label(RichText::new("Packers and protectors").color(theme::MUTED));
                if report.detections.is_empty() {
                    ui.label("None recognized");
                }
                for detection in &report.detections {
                    ui.horizontal(|ui| {
                        let (label, color) = match detection.confidence {
                            Confidence::High => ("High", theme::ERROR),
                            Confidence::Medium => ("Medium", theme::NUMBER),
                            Confidence::Low => ("Low", theme::MUTED),
                        };
                        ui.label(RichText::new(label).color(color));
                        ui.label(RichText::new(&detection.name).strong());
                        ui.label(RichText::new(&detection.evidence).color(theme::MUTED));
                    });
                }
            });
        });
    });

    let sections = &report.sections;
    table::show(
        ui,
        "overview_sections",
        &SECTIONS,
        sections.len(),
        None,
        |ui, range, widths| {
            for index in range {
                let section = &sections[index];
                let row = table::row(ui, widths, false);
                let name = if section.name.is_empty() {
                    "(unnamed)"
                } else {
                    &section.name
                };
                let name_color = if section.executable {
                    theme::CALL
                } else {
                    theme::TEXT
                };
                table::text(ui, row.cells[0], name, name_color, theme::mono());
                table::text(
                    ui,
                    row.cells[1],
                    &format!("{:#x}", section.va),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[2],
                    &section.size.to_string(),
                    theme::MUTED,
                    theme::mono(),
                );
                let color = entropy_color(section.entropy);
                table::text(
                    ui,
                    row.cells[3],
                    &format!("{:.2}", section.entropy),
                    color,
                    theme::mono(),
                );
                density_bar(ui, row.cells[4], section.entropy, color);
            }
        },
    );
    None
}

fn density_bar(ui: &Ui, cell: egui::Rect, value: f32, color: egui::Color32) {
    let left = cell.left() + 12.0;
    let track = egui::Rect::from_center_size(
        egui::pos2(left + BAR_WIDTH / 2.0, cell.center().y),
        egui::vec2(BAR_WIDTH, 6.0),
    );
    let mut used = track;
    used.set_width(BAR_WIDTH * (value / MAX_ENTROPY).clamp(0.0, 1.0));
    ui.painter().rect_filled(track, 3.0, theme::BORDER);
    ui.painter().rect_filled(used, 3.0, color);
}

enum Scan {
    Idle,
    Running(Receiver<Vec<XorHit>>),
    Done(Vec<XorHit>),
}

pub struct XorState {
    scan: Scan,
    address: String,
    length: String,
    key: String,
    output: Option<Result<String, String>>,
    selected: Option<usize>,
}

impl Default for XorState {
    fn default() -> Self {
        Self {
            scan: Scan::Idle,
            address: String::new(),
            length: DEFAULT_XOR_LEN.to_owned(),
            key: String::new(),
            output: None,
            selected: None,
        }
    }
}

impl XorState {
    fn poll(&mut self, ui: &Ui, analysis: &Analysis) {
        match &self.scan {
            Scan::Idle => {
                let data = Arc::clone(&analysis.data);
                let sections = analysis.sections.clone();
                let (sender, receiver) = mpsc::channel();
                thread::spawn(move || {
                    let _ = sender.send(scan_xor(&data, &sections));
                });
                self.scan = Scan::Running(receiver);
            }
            Scan::Running(receiver) => match receiver.try_recv() {
                Ok(hits) => self.scan = Scan::Done(hits),
                Err(mpsc::TryRecvError::Empty) => {
                    ui.ctx().request_repaint_after(Duration::from_millis(100));
                }
                Err(mpsc::TryRecvError::Disconnected) => self.scan = Scan::Done(Vec::new()),
            },
            Scan::Done(_) => {}
        }
    }

    fn decode(&mut self, analysis: &Analysis) {
        self.output = Some(decode_manual(
            analysis,
            &self.address,
            &self.length,
            &self.key,
        ));
    }
}

fn decode_manual(
    analysis: &Analysis,
    address: &str,
    length: &str,
    key: &str,
) -> Result<String, String> {
    let va = analysis
        .resolve(address.trim())
        .ok_or("Enter an address such as 0x140001000")?;
    let len: usize = length
        .trim()
        .parse()
        .map_err(|_| "Enter a length in bytes")?;
    let key = parse_hex(key).ok_or("Enter the key as hex, such as 5A or DE AD BE EF")?;
    let bytes = analysis
        .read(va, len.min(MAX_PREVIEW_BYTES))
        .filter(|bytes| !bytes.is_empty())
        .ok_or_else(|| format!("No file data at {va:#x}"))?;

    let decoded = xor(bytes, &key);
    let text: String = decoded
        .iter()
        .map(|&byte| {
            if (0x20..=0x7E).contains(&byte) {
                char::from(byte)
            } else {
                '.'
            }
        })
        .collect();
    Ok(format!(
        "{}\n\n{text}\n\nEntropy before {:.2}, after {:.2}",
        tabs::hex_bytes(&decoded),
        entropy(bytes),
        entropy(&decoded),
    ))
}

pub fn xor_tab(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let analysis = &project.analysis;
    let state = &mut project.xor;
    state.poll(ui, analysis);

    card(ui, |ui| {
        ui.horizontal(|ui| {
            let field = |ui: &mut Ui, text: &mut String, hint: &str, width: f32| {
                ui.add(
                    egui::TextEdit::singleline(text)
                        .hint_text(hint)
                        .font(theme::mono())
                        .desired_width(width),
                )
            };
            field(ui, &mut state.address, "Address", 200.0);
            field(ui, &mut state.length, "Length", 90.0);
            field(ui, &mut state.key, "Key in hex, any length", 260.0);
            if ui.button("Decode").clicked() {
                state.decode(analysis);
            }
        });

        match &state.output {
            Some(Ok(text)) => {
                ui.add_space(8.0);
                egui::ScrollArea::vertical()
                    .id_salt("xor_output")
                    .max_height(150.0)
                    .auto_shrink([false, true])
                    .show(ui, |ui| {
                        ui.add(egui::Label::new(RichText::new(text).font(theme::mono())).wrap());
                    });
            }
            Some(Err(message)) => {
                ui.add_space(8.0);
                ui.label(RichText::new(message).color(theme::ERROR));
            }
            None => {}
        }

        ui.add_space(8.0);
        let summary = match &state.scan {
            Scan::Done(hits) => format!(
                "{} candidates. The auto scan tries every single-byte key over the first 16 MB \
                 of data sections, and can miss text or report false matches.",
                hits.len()
            ),
            _ => "Scanning data sections with every single-byte key".to_owned(),
        };
        ui.label(RichText::new(summary).color(theme::MUTED));
    });

    let Scan::Done(hits) = &state.scan else {
        ui.centered_and_justified(|ui| ui.spinner());
        return None;
    };
    if hits.is_empty() {
        tabs::no_results(ui, "No XOR-encoded text found");
        return None;
    }

    let mut chosen = None;
    table::show(
        ui,
        "xor_hits",
        &HITS,
        hits.len(),
        None,
        |ui, range, widths| {
            for index in range {
                let hit = &hits[index];
                let row = table::row(ui, widths, state.selected == Some(index));
                if row.response.clicked() {
                    chosen = Some(index);
                }
                table::text(
                    ui,
                    row.cells[0],
                    &format!("{:#x}", hit.va),
                    theme::TEXT,
                    theme::mono(),
                );
                table::text(
                    ui,
                    row.cells[1],
                    &format!("{:02X}", hit.key),
                    theme::NUMBER,
                    theme::mono(),
                );
                table::text(ui, row.cells[2], &hit.text, theme::TEXT, theme::mono());
            }
        },
    );

    if let Some(index) = chosen {
        let hit = hits[index].clone();
        state.selected = Some(index);
        state.address = format!("{:#x}", hit.va);
        state.length = hit.text.len().to_string();
        state.key = format!("{:02X}", hit.key);
        state.decode(analysis);
    }
    None
}

pub fn tip(ui: &Ui, cell: egui::Rect, id: impl egui::AsIdSalt, text: &str) {
    let id = ui.scope_id().with(id);
    ui.interact(cell, id, Sense::hover()).on_hover_text(text);
}

pub fn underline(ui: &Ui, drawn: egui::Rect, color: egui::Color32) {
    ui.painter()
        .hline(drawn.x_range(), drawn.bottom(), Stroke::new(1.0, color));
}
