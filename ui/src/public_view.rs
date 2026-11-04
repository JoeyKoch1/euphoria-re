use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, RichText, Ui};
use euphoria_community::{Config, PublicDump, export_dump, lookup};

use crate::tabs::Action;
use crate::{Project, theme, tools};

const MAX_LIST_HEIGHT: f32 = 180.0;

type Outcome = Result<Option<PublicDump>, String>;

#[derive(Default)]
pub struct PublicState {
    config: Config,
    job: Option<Receiver<Outcome>>,
    result: Option<Outcome>,
    message: Option<String>,
    asking_share: bool,
}

impl PublicState {
    pub fn new(sha256: &str) -> Self {
        let mut state = Self {
            config: Config::load(),
            ..Self::default()
        };
        if state.config.automatic_lookups {
            state.start(sha256);
        }
        state
    }

    fn start(&mut self, sha256: &str) {
        let config = self.config.clone();
        let sha256 = sha256.to_owned();
        let (sender, receiver) = mpsc::channel();
        thread::spawn(move || {
            let outcome = lookup(&config, &sha256).map_err(|error| format!("{error:#}"));
            let _ = sender.send(outcome);
        });
        self.result = None;
        self.job = Some(receiver);
    }

    fn poll(&mut self, ctx: &egui::Context) {
        let Some(job) = &self.job else {
            return;
        };
        match job.try_recv() {
            Ok(outcome) => {
                self.result = Some(outcome);
                self.job = None;
            }
            Err(_) => ctx.request_repaint_after(std::time::Duration::from_millis(100)),
        }
    }
}

fn share(project: &mut Project) {
    let analysis = &project.analysis;
    let dump = export_dump(analysis);
    let Some(path) = rfd::FileDialog::new()
        .set_file_name(format!("{}.json", analysis.sha256))
        .add_filter("Euphoria public dump", &["json"])
        .save_file()
    else {
        return;
    };
    let written = serde_json::to_vec_pretty(&dump)
        .map_err(|error| error.to_string())
        .and_then(|bytes| std::fs::write(&path, bytes).map_err(|error| error.to_string()));
    project.public.message = Some(match written {
        Ok(()) => {
            tools::open_external(&project.public.config.dump_upload_url(&analysis.sha256));
            format!(
                "Saved {}. Upload that file on the page that just opened. Nothing was sent yet.",
                path.display()
            )
        }
        Err(error) => format!("Could not save: {error}"),
    });
}

pub fn show(ui: &mut Ui, project: &mut Project) -> Option<Action> {
    let mut action = None;
    project.public.poll(ui.ctx());
    let sha256 = project.analysis.sha256.clone();

    tools::card(ui, |ui| {
        ui.label(RichText::new("Public database").color(theme::MUTED));
        ui.add_space(4.0);
        ui.horizontal(|ui| {
            let busy = project.public.job.is_some();
            if ui
                .add_enabled(!busy, egui::Button::new("Check this file"))
                .on_hover_text("Sends this file's SHA-256 to GitHub. The file itself never leaves.")
                .clicked()
            {
                project.public.start(&sha256);
            }
            if ui.button("Share my routine names").clicked() {
                project.public.asking_share = true;
            }
            let mut automatic = project.public.config.automatic_lookups;
            if ui
                .checkbox(&mut automatic, "Check every file I open")
                .on_hover_text("Each lookup tells GitHub which file you opened.")
                .changed()
            {
                project.public.config.automatic_lookups = automatic;
                if let Err(error) = project.public.config.save() {
                    project.public.message = Some(format!("{error:#}"));
                }
            }
        });

        if project.public.job.is_some() {
            ui.label(RichText::new("Checking...").color(theme::MUTED));
        }
        if let Some(message) = &project.public.message {
            ui.label(RichText::new(message).color(theme::MUTED));
        }
        match &project.public.result {
            Some(Err(error)) => {
                ui.label(RichText::new(error).color(theme::ERROR));
            }
            Some(Ok(None)) => {
                ui.label(RichText::new("Nobody has shared this file yet.").color(theme::MUTED));
            }
            Some(Ok(Some(dump))) => action = found(ui, dump),
            None => {}
        }
    });

    if project.public.asking_share {
        let mut choice = None;
        egui::Modal::new(egui::Id::unique("share_dump")).show(ui.ctx(), |ui| {
            ui.set_max_width(520.0);
            ui.label(RichText::new("Share your routine names?").size(16.0));
            ui.add_space(8.0);
            ui.label(
                "Euphoria saves a small file with this file's hash, name, and the address, size, \
                 and name of each named routine. It holds no bytes from the file, no code, and no \
                 strings. You then upload it yourself on GitHub, where everyone can read it, so \
                 only share analysis of software you're allowed to discuss in public.",
            );
            ui.add_space(14.0);
            ui.horizontal(|ui| {
                if ui.button("Choose where to save").clicked() {
                    choice = Some(true);
                }
                if ui.button("Cancel").clicked() {
                    choice = Some(false);
                }
            });
        });
        if let Some(accepted) = choice {
            project.public.asking_share = false;
            if accepted {
                share(project);
            }
        }
    }
    action
}

// A contributor wrote all of this, so it stays plain text and nothing in it can be clicked except
// addresses that move around this same file.
fn found(ui: &mut Ui, dump: &PublicDump) -> Option<Action> {
    let mut action = None;
    ui.add_space(6.0);
    ui.label(format!(
        "{} routines shared as {}, made with {}",
        dump.functions.len(),
        dump.file_name,
        dump.tool
    ));
    if !dump.contributor.is_empty() {
        ui.label(format!("By {}", dump.contributor));
    }
    if !dump.tags.is_empty() {
        ui.label(format!("Tags: {}", dump.tags.join(", ")));
    }
    if !dump.notes.is_empty() {
        ui.label(&dump.notes);
    }
    ui.label(RichText::new("Read-only, and not checked by anyone.").color(theme::MUTED));
    egui::ScrollArea::vertical()
        .id_salt("public_dump")
        .max_height(MAX_LIST_HEIGHT)
        .show(ui, |ui| {
            for function in &dump.functions {
                let text = format!("{:#x}  {}", function.va, function.name);
                if ui
                    .selectable_label(false, RichText::new(text).font(theme::mono()))
                    .clicked()
                {
                    action = Some(Action::Go(function.va));
                }
            }
        });
    action
}
