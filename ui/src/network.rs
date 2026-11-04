use std::sync::mpsc::{self, Receiver};
use std::thread;

use std::path::Path;

use aero::{Capture, Emulator, Found, Request, Route, ScanEvent, Url, base_domain, same_domain};
use eframe::egui::{self, RichText, Ui};
use euphoria_engine::{Analysis, Listing, Patch};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::table::{self, Column, fill, fixed};
use crate::tabs::{self, Action, Filter};
use crate::theme;

const LINKS: [Column; 4] = [
    fixed("Found at", 170.0),
    fixed("Via", 90.0),
    fill("Link"),
    fixed("", 120.0),
];
const METHODS: [&str; 7] = ["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"];
const HOST_PANEL_WIDTH: f32 = 360.0;
const LOOPBACK: &str = "127.0.0.1";

struct LinkRow {
    url: String,
    va: u64,
    via: &'static str,
    // Where the link's own bytes sit in the file, when it was found verbatim in a plain string.
    target: Option<PatchTarget>,
}

#[derive(Clone, Copy)]
struct PatchTarget {
    va: u64,
    len: usize,
}

#[derive(Serialize, Deserialize)]
struct Snapshot {
    domain: String,
    found: Vec<Found>,
    captures: Vec<Capture>,
}

pub struct HostTab {
    pub domain: String,
    authorized: bool,
    scan: Option<Receiver<ScanEvent>>,
    found: Vec<Found>,
    notes: Vec<String>,
    paths: Vec<String>,
    method: String,
    url: String,
    headers: String,
    body: String,
    sending: Option<Receiver<Result<Capture, String>>>,
    captures: Vec<Capture>,
    selected: Option<usize>,
    message: Option<String>,
}

fn running_emulator(slot: &mut Option<Emulator>) -> Result<&Emulator, String> {
    if slot.is_none() {
        *slot = Some(Emulator::start().map_err(|error| error.to_string())?);
    }
    slot.as_ref()
        .ok_or_else(|| "The emulator did not start".to_owned())
}

impl HostTab {
    fn new(domain: String, url: String) -> Self {
        Self {
            domain,
            authorized: false,
            scan: None,
            found: Vec::new(),
            notes: Vec::new(),
            paths: Vec::new(),
            method: "GET".to_owned(),
            url,
            headers: String::new(),
            body: String::new(),
            sending: None,
            captures: Vec::new(),
            selected: None,
            message: None,
        }
    }

    fn start_scan(&mut self) {
        let (sender, receiver) = mpsc::channel();
        let domain = self.domain.clone();
        self.found.clear();
        self.notes.clear();
        self.scan = Some(receiver);
        thread::spawn(move || {
            if let Err(error) = aero::scan(&domain, &sender) {
                let _ = sender.send(ScanEvent::Warning(error.to_string()));
                let _ = sender.send(ScanEvent::Done);
            }
        });
    }

    fn is_busy(&self) -> bool {
        self.scan.is_some() || self.sending.is_some()
    }

    fn poll(&mut self) {
        if let Some(receiver) = &self.scan {
            let mut finished = false;
            for event in receiver.try_iter() {
                match event {
                    ScanEvent::Found(found) => {
                        let at = self.found.partition_point(|other| other.name < found.name);
                        self.found.insert(at, found);
                    }
                    ScanEvent::Warning(note) => self.notes.push(note),
                    ScanEvent::Done => finished = true,
                }
            }
            if finished {
                self.scan = None;
            }
        }

        if let Some(receiver) = &self.sending
            && let Ok(result) = receiver.try_recv()
        {
            self.sending = None;
            match result {
                Ok(capture) => {
                    self.captures.push(capture);
                    self.selected = Some(self.captures.len() - 1);
                    self.message = None;
                }
                Err(error) => self.message = Some(error),
            }
        }
    }

    fn send(&mut self) {
        let host = match Url::parse(self.url.trim()) {
            Ok(url) => url.host,
            Err(error) => {
                self.message = Some(error.to_string());
                return;
            }
        };
        if host != LOOPBACK && !same_domain(&host, &self.domain) {
            self.message = Some(format!(
                "{host} is outside {}. Analyze it from the Networking tab first.",
                self.domain
            ));
            return;
        }
        if host != LOOPBACK && !self.authorized {
            self.message = Some("Allow network access for this domain first.".to_owned());
            return;
        }

        let headers = self
            .headers
            .lines()
            .filter_map(|line| line.split_once(':'))
            .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
            .collect();
        let request = Request {
            method: self.method.clone(),
            url: self.url.trim().to_owned(),
            headers,
            body: self.body.clone().into_bytes(),
        };

        let (sender, receiver) = mpsc::channel();
        self.sending = Some(receiver);
        self.message = None;
        thread::spawn(move || {
            let _ = sender.send(aero::send(&request).map_err(|error| error.to_string()));
        });
    }

    fn emulate_selected(&mut self, emulator: &mut Option<Emulator>) {
        let Some(capture) = self.selected.and_then(|index| self.captures.get(index)) else {
            return;
        };
        let Ok(url) = Url::parse(&capture.url) else {
            return;
        };
        let content_type = capture
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
            .map_or("application/json", |(_, value)| value.as_str())
            .to_owned();
        let route = Route {
            method: capture.method.clone(),
            path: url.path,
            status: capture.status,
            content_type,
            body: capture.body.clone(),
        };

        match running_emulator(emulator) {
            Ok(emulator) => emulator.set_route(route),
            Err(error) => self.message = Some(error),
        }
    }
}

#[derive(Default)]
pub struct NetworkState {
    links: Vec<LinkRow>,
    filter: Option<Filter>,
    manual: String,
    pub hosts: Vec<HostTab>,
    consent: Option<usize>,
    pending: Vec<Patch>,
    emulator: Option<Emulator>,
    error: Option<String>,
}

impl NetworkState {
    pub fn load_links(&mut self, listing: &Listing) {
        self.links.clear();
        self.pending.clear();
        for entry in &listing.strings {
            for url in aero::extract_links(&entry.value) {
                // Only links stored verbatim can be patched, so we know which bytes to edit.
                let target = entry.value.find(&url).map(|at| PatchTarget {
                    va: entry.va + at as u64,
                    len: url.len(),
                });
                self.links.push(LinkRow {
                    url,
                    va: entry.va,
                    via: "String",
                    target,
                });
            }
            if let Some(decoded) = &entry.base64 {
                for url in aero::extract_links(decoded) {
                    self.links.push(LinkRow {
                        url,
                        va: entry.va,
                        via: "Base64",
                        target: None,
                    });
                }
            }
        }
        self.filter = Some(Filter::all(self.links.len()));
        self.hosts.clear();
        self.consent = None;
    }

    fn redirect(&mut self, index: usize, analysis: &Analysis) {
        let Some(row) = self.links.get(index) else {
            return;
        };
        let (Some(target), Ok(url)) = (row.target, Url::parse(&row.url)) else {
            self.error = Some(
                "This link is not stored as plain text, so there are no bytes to patch.".to_owned(),
            );
            return;
        };

        let address = match running_emulator(&mut self.emulator) {
            Ok(emulator) => emulator.address(),
            Err(error) => {
                self.error = Some(error);
                return;
            }
        };
        let replacement = aero::to_loopback(&url, Some(&address));

        match analysis.plan_patch(target.va, target.len, &replacement) {
            Ok(patch) => {
                self.pending.retain(|existing| existing.va != patch.va);
                self.pending.push(patch);
                self.error = None;
            }
            Err(_) => {
                self.error = Some(format!(
                    "{replacement} needs {} bytes, and this link only has {} in the file.",
                    replacement.len(),
                    target.len,
                ));
            }
        }
    }

    pub fn load_apk_links(&mut self, apk: &euphoria_apk::Apk) {
        self.links.clear();
        self.pending.clear();
        for found in &apk.strings {
            let at = found.index as u64;
            for url in aero::extract_links(&found.value) {
                self.links.push(LinkRow {
                    url,
                    va: at,
                    via: "DEX",
                    target: None,
                });
            }
            if let Some(decoded) = &found.base64 {
                for url in aero::extract_links(decoded) {
                    self.links.push(LinkRow {
                        url,
                        va: at,
                        via: "Base64",
                        target: None,
                    });
                }
            }
        }
        self.filter = Some(Filter::all(self.links.len()));
        self.hosts.clear();
        self.consent = None;
    }

    pub fn snapshot(&self) -> Value {
        let hosts: Vec<Snapshot> = self
            .hosts
            .iter()
            .map(|host| Snapshot {
                domain: host.domain.clone(),
                found: host.found.clone(),
                captures: host.captures.clone(),
            })
            .collect();
        serde_json::json!({ "hosts": hosts })
    }

    pub fn restore(&mut self, extras: &Value) {
        let saved = extras
            .get("hosts")
            .cloned()
            .and_then(|hosts| serde_json::from_value::<Vec<Snapshot>>(hosts).ok())
            .unwrap_or_default();
        for snapshot in saved {
            let url = format!("https://{}/", snapshot.domain);
            let mut host = HostTab::new(snapshot.domain, url);
            host.found = snapshot.found;
            host.captures = snapshot.captures;
            self.hosts.push(host);
        }
    }

    pub fn poll(&mut self, ctx: &egui::Context) {
        let mut busy = false;
        for host in &mut self.hosts {
            host.poll();
            busy |= host.is_busy();
        }
        if busy {
            ctx.request_repaint_after(std::time::Duration::from_millis(100));
        }
    }

    pub fn close(&mut self, index: usize) {
        self.hosts.remove(index);
        self.consent = None;
    }

    fn analyze(&mut self, link: &str) -> Option<usize> {
        let url = match Url::parse(link.trim()) {
            Ok(url) => url,
            Err(error) => {
                self.error = Some(error.to_string());
                return None;
            }
        };
        self.error = None;
        let domain = base_domain(&url.host);

        let paths = self
            .links
            .iter()
            .filter(|row| Url::parse(&row.url).is_ok_and(|other| same_domain(&other.host, &domain)))
            .map(|row| row.url.clone())
            .collect::<Vec<_>>();

        let index = match self.hosts.iter().position(|host| host.domain == domain) {
            Some(index) => index,
            None => {
                self.hosts
                    .push(HostTab::new(domain, link.trim().to_owned()));
                self.hosts.len() - 1
            }
        };
        let host = &mut self.hosts[index];
        host.url = link.trim().to_owned();
        host.paths = paths;
        if !host.authorized {
            self.consent = Some(index);
        }
        Some(index)
    }

    pub fn consent_dialog(&mut self, ctx: &egui::Context) {
        let Some(index) = self.consent else {
            return;
        };
        let Some(host) = self.hosts.get_mut(index) else {
            self.consent = None;
            return;
        };

        let domain = host.domain.clone();
        let mut close = false;
        egui::Modal::new(egui::Id::unique("aero_consent")).show(ctx, |ui| {
            ui.set_max_width(520.0);
            ui.label(RichText::new(format!("Let Aero contact {domain}?")).size(16.0));
            ui.add_space(8.0);
            ui.label(
                "Aero will ask crt.sh for logged certificates, run DNS lookups, and let you send \
                 requests to this domain. All of it leaves this machine from your IP address.",
            );
            ui.add_space(6.0);
            ui.label(
                "If this link came from a program you are analyzing, whoever runs that server may \
                 see the traffic. Only continue for systems you own or have permission to test.",
            );
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button("I have permission, scan").clicked() {
                    host.authorized = true;
                    host.start_scan();
                    close = true;
                }
                if ui.button("Stay offline").clicked() {
                    close = true;
                }
            });
        });
        if close {
            self.consent = None;
        }
    }
}

fn save_patched_copy(analysis: &Analysis, patches: &[Patch]) -> Action {
    let suggested = {
        let name = Path::new(&analysis.file_name);
        let stem = name.file_stem().unwrap_or_default().to_string_lossy();
        match name.extension() {
            Some(extension) => format!("{stem}.patched.{}", extension.to_string_lossy()),
            None => format!("{stem}.patched"),
        }
    };

    let Some(path) = rfd::FileDialog::new().set_file_name(suggested).save_file() else {
        return Action::Status("Save canceled".to_owned());
    };
    match analysis.save_patched(&path, patches) {
        Ok(()) => Action::Status(format!(
            "Saved a patched copy with {} redirect(s). The original file is untouched.",
            patches.len()
        )),
        Err(error) => Action::Status(format!("Could not save: {error:#}")),
    }
}

pub fn links(
    ui: &mut Ui,
    network: &mut NetworkState,
    analysis: Option<&Analysis>,
) -> Option<Action> {
    let mut action = None;

    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.add(
                    egui::TextEdit::singleline(&mut network.manual)
                        .hint_text("Paste any link")
                        .desired_width(460.0),
                );
                if ui.button("Analyze").clicked() {
                    let link = network.manual.clone();
                    if let Some(index) = network.analyze(&link) {
                        action = Some(Action::ShowHost(index));
                    }
                }
                if let Some(error) = &network.error {
                    ui.label(RichText::new(error).color(theme::ERROR));
                }
            });
        });

    if !network.pending.is_empty() {
        egui::Frame::new()
            .inner_margin(egui::Margin::symmetric(12, 6))
            .show(ui, |ui| {
                ui.horizontal(|ui| {
                    ui.label(
                        RichText::new(format!(
                            "{} link(s) redirected to {} in a patched copy",
                            network.pending.len(),
                            network
                                .emulator
                                .as_ref()
                                .map_or(LOOPBACK.to_owned(), Emulator::address)
                        ))
                        .color(theme::ACCENT),
                    );
                    if let Some(analysis) = analysis
                        && ui.button("Save patched copy").clicked()
                    {
                        action = Some(save_patched_copy(analysis, &network.pending));
                    }
                    if ui.button("Clear").clicked() {
                        network.pending.clear();
                    }
                });
            });
    }

    let rows = &network.links;
    let Some(filter) = &mut network.filter else {
        tabs::no_results(ui, "Open a binary to list the links inside it");
        return action;
    };
    filter.bar(ui, "Filter links", rows.len(), |i| rows[i].url.clone());
    if filter.matches.is_empty() {
        tabs::no_results(ui, "No links found in this file's strings");
        return action;
    }

    let mut analyze = None;
    let mut redirect = None;
    table::show(
        ui,
        "network_links",
        &LINKS,
        filter.matches.len(),
        None,
        |ui, range, widths| {
            ui.spacing_mut().button_padding.y = 2.0;
            ui.spacing_mut().interact_size.y = 20.0;
            for position in range {
                let index = filter.matches[position];
                let row_data = &rows[index];
                let row = table::row(ui, widths, false);
                table::text(
                    ui,
                    row.cells[0],
                    &format!("{:#x}", row_data.va),
                    theme::MUTED,
                    theme::mono(),
                );
                table::text(ui, row.cells[1], row_data.via, theme::MUTED, theme::body());
                table::text(ui, row.cells[2], &row_data.url, theme::TEXT, theme::mono());

                let button = row.cells[3].shrink2(egui::vec2(6.0, 3.0));
                if ui.put(button, egui::Button::new("Analyze")).clicked() {
                    analyze = Some(row_data.url.clone());
                }

                let patchable = row_data.target.is_some();
                row.response.context_menu(|ui| {
                    if ui.button("Analyze endpoint").clicked() {
                        analyze = Some(row_data.url.clone());
                        ui.close();
                    }
                    if ui
                        .add_enabled(patchable, egui::Button::new("Patch to local emulator"))
                        .clicked()
                    {
                        redirect = Some(index);
                        ui.close();
                    }
                    if !patchable {
                        ui.label(
                            RichText::new("Only links stored as plain text can be patched")
                                .color(theme::MUTED),
                        );
                    }
                });
            }
        },
    );

    if let Some(link) = analyze
        && let Some(index) = network.analyze(&link)
    {
        action = Some(Action::ShowHost(index));
    }
    if let (Some(index), Some(analysis)) = (redirect, analysis) {
        network.redirect(index, analysis);
    }
    action
}

pub fn host_tab(ui: &mut Ui, network: &mut NetworkState, index: usize) {
    let mut ask_consent = false;
    let emulator = &mut network.emulator;
    let Some(host) = network.hosts.get_mut(index) else {
        tabs::no_results(ui, "This tab was closed");
        return;
    };

    egui::Panel::left(format!("host_panel_{index}"))
        .exact_size(HOST_PANEL_WIDTH)
        .frame(egui::Frame::new().fill(theme::SURFACE).inner_margin(10))
        .show(ui, |ui| {
            ui.label(RichText::new(&host.domain).size(16.0));
            ui.add_space(6.0);
            if host.scan.is_some() {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(format!("Scanning, {} found so far", host.found.len()));
                });
            } else if host.authorized {
                if ui.button("Scan again").clicked() {
                    host.start_scan();
                }
            } else if ui.button("Allow network and scan").clicked() {
                ask_consent = true;
            }
            for note in &host.notes {
                ui.label(RichText::new(note).color(theme::NUMBER));
            }

            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("Subdomains ({})", host.found.len())).color(theme::MUTED),
            );
            egui::ScrollArea::vertical()
                .id_salt("host_subdomains")
                .max_height(ui.available_height() * 0.6)
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for found in &host.found {
                        let label = if found.addresses.is_empty() {
                            format!("{}  (no DNS)", found.name)
                        } else {
                            found.name.clone()
                        };
                        let addresses: Vec<String> =
                            found.addresses.iter().map(ToString::to_string).collect();
                        let response =
                            ui.selectable_label(false, RichText::new(label).font(theme::mono()));
                        if response.on_hover_text(addresses.join("\n")).clicked() {
                            host.url = format!("https://{}/", found.name);
                        }
                    }
                });

            ui.add_space(8.0);
            ui.label(
                RichText::new(format!("Paths in this file ({})", host.paths.len()))
                    .color(theme::MUTED),
            );
            egui::ScrollArea::vertical()
                .id_salt("host_paths")
                .auto_shrink([false, false])
                .show(ui, |ui| {
                    for path in &host.paths {
                        if ui
                            .selectable_label(false, RichText::new(path).font(theme::mono()))
                            .clicked()
                        {
                            host.url.clone_from(path);
                        }
                    }
                });
        });

    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 10))
        .show(ui, |ui| composer(ui, host));
    results(ui, host, emulator);

    if ask_consent {
        network.consent = Some(index);
    }
}

fn composer(ui: &mut Ui, host: &mut HostTab) {
    ui.horizontal(|ui| {
        egui::ComboBox::from_id_salt("request_method")
            .selected_text(host.method.as_str())
            .show_ui(ui, |ui| {
                for method in METHODS {
                    ui.selectable_value(&mut host.method, method.to_owned(), method);
                }
            });
        ui.add(
            egui::TextEdit::singleline(&mut host.url)
                .font(theme::mono())
                .desired_width(ui.available_width() - 90.0),
        );
        let sending = host.sending.is_some();
        if ui
            .add_enabled(
                !sending,
                egui::Button::new(if sending { "Sending" } else { "Send" }),
            )
            .clicked()
        {
            host.send();
        }
    });
    ui.add_space(4.0);
    ui.columns(2, |columns| {
        columns[0].add(
            egui::TextEdit::multiline(&mut host.headers)
                .hint_text("Headers, one per line\nAuthorization: Bearer ...")
                .font(theme::mono())
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
        columns[1].add(
            egui::TextEdit::multiline(&mut host.body)
                .hint_text("Request body")
                .font(theme::mono())
                .desired_rows(3)
                .desired_width(f32::INFINITY),
        );
    });
    if let Some(message) = &host.message {
        ui.add_space(4.0);
        ui.label(RichText::new(message).color(theme::ERROR));
    }
}

fn results(ui: &mut Ui, host: &mut HostTab, emulator: &mut Option<Emulator>) {
    if host.captures.is_empty() {
        tabs::no_results(ui, "Responses you capture show up here");
        return;
    }

    egui::Frame::new()
        .inner_margin(egui::Margin::symmetric(12, 4))
        .show(ui, |ui| {
            ui.horizontal(|ui| {
                ui.label(
                    RichText::new(format!("Captured ({})", host.captures.len()))
                        .color(theme::MUTED),
                );
                if ui.button("Serve this locally").clicked() {
                    host.emulate_selected(emulator);
                }
                if let Some(emulator) = emulator.as_ref() {
                    let address = emulator.address();
                    ui.label(
                        RichText::new(format!(
                            "{address}, {} routes, {} hits",
                            emulator.routes().len(),
                            emulator.hits().len()
                        ))
                        .font(theme::mono())
                        .color(theme::ACCENT),
                    );
                    if ui.button("Point request here").clicked() {
                        let path = host
                            .selected
                            .and_then(|index| host.captures.get(index))
                            .and_then(|capture| Url::parse(&capture.url).ok())
                            .map_or("/".to_owned(), |url| url.path);
                        host.url = format!("{address}{path}");
                    }
                }
            });

            egui::ScrollArea::vertical()
                .id_salt("captures")
                .max_height(120.0)
                .auto_shrink([false, true])
                .show(ui, |ui| {
                    for (index, capture) in host.captures.iter().enumerate().rev() {
                        let kind = if capture.is_json() { "JSON" } else { "no JSON" };
                        let label = format!(
                            "{} {} {}  {kind}, {} ms",
                            capture.status, capture.method, capture.url, capture.elapsed_ms
                        );
                        let selected = host.selected == Some(index);
                        if ui
                            .selectable_label(selected, RichText::new(label).font(theme::mono()))
                            .clicked()
                        {
                            host.selected = Some(index);
                        }
                    }
                });
        });

    let Some(capture) = host.selected.and_then(|index| host.captures.get(index)) else {
        return;
    };
    let Some(json) = &capture.json else {
        let content_type = capture
            .headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case("content-type"))
            .map_or("unknown type", |(_, value)| value.as_str());
        ui.vertical_centered(|ui| {
            ui.add_space(ui.available_height() / 2.0 - 40.0);
            ui.label(
                RichText::new("No JSON was returned from this URL")
                    .color(theme::MUTED)
                    .size(20.0),
            );
            ui.add_space(4.0);
            ui.label(
                RichText::new(format!(
                    "HTTP {}, {content_type}, {} bytes",
                    capture.status,
                    capture.body.len()
                ))
                .color(theme::MUTED),
            );
        });
        return;
    };

    let text = serde_json::to_string_pretty(json).unwrap_or_else(|_| capture.body.clone());
    egui::Frame::new()
        .fill(theme::SURFACE)
        .inner_margin(egui::Margin::symmetric(12, 8))
        .show(ui, |ui| {
            egui::ScrollArea::both()
                .id_salt("capture_body")
                .auto_shrink(false)
                .show(ui, |ui| {
                    ui.add(egui::Label::new(RichText::new(text).font(theme::mono())).extend());
                });
        });
}
