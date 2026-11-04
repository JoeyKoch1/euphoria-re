use std::path::Path;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use std::sync::mpsc::{self, Receiver, TryRecvError};
use std::thread;
use std::time::Duration;

use eframe::egui::{self, RichText};
use euphoria_apk::Apk;
use euphoria_dump::{Options, Progress, Summary, dump_apk, dump_binary};
use euphoria_engine::{Analysis, Listing};

const MEGABYTE: f64 = 1024.0 * 1024.0;

#[derive(Clone)]
pub enum Source {
    Binary(Arc<Analysis>, Arc<Listing>),
    Apk(Arc<Apk>),
}

impl Source {
    fn file_name(&self) -> &str {
        match self {
            Self::Binary(analysis, _) => &analysis.file_name,
            Self::Apk(apk) => &apk.file_name,
        }
    }
}

struct Job {
    receiver: Receiver<Result<Summary, String>>,
    progress: Arc<Progress>,
}

#[derive(Default)]
pub struct DumpState {
    asking: Option<Source>,
    skip_original: bool,
    skip_decompile: bool,
    job: Option<Job>,
}

impl DumpState {
    pub fn is_running(&self) -> bool {
        self.job.is_some()
    }

    pub fn ask(&mut self, source: Source) {
        self.asking = Some(source);
    }

    pub fn dialog(&mut self, ctx: &egui::Context) {
        let Some(source) = self.asking.clone() else {
            return;
        };

        let mut choice = None;
        egui::Modal::new(egui::Id::unique("dump_dialog")).show(ctx, |ui| {
            ui.set_max_width(480.0);
            ui.label(RichText::new(format!("Dump {}", source.file_name())).size(16.0));
            ui.add_space(8.0);
            ui.label(
                "Writes everything Euphoria knows about this file into one zip: identity, \
                 sections or classes, routines, references, strings, and all the code.",
            );
            ui.add_space(8.0);

            let mut include = !self.skip_original;
            ui.checkbox(&mut include, "Include the original file");
            self.skip_original = !include;
            let mut decompile = !self.skip_decompile;
            ui.checkbox(
                &mut decompile,
                "Include pseudocode for every routine (takes longer)",
            );
            self.skip_decompile = !decompile;
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

        match choice {
            Some(true) => {
                self.asking = None;
                let stem = Path::new(source.file_name())
                    .file_stem()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .into_owned();
                if let Some(path) = rfd::FileDialog::new()
                    .set_file_name(format!("{stem}.dump.zip"))
                    .add_filter("Zip archive", &["zip"])
                    .save_file()
                {
                    self.start(source, &path);
                }
            }
            Some(false) => self.asking = None,
            None => {}
        }
    }

    fn start(&mut self, source: Source, path: &Path) {
        let options = Options {
            include_original: !self.skip_original,
            decompile: !self.skip_decompile,
        };
        let progress = Arc::new(Progress::default());
        let shared = Arc::clone(&progress);
        let path = path.to_path_buf();
        let (sender, receiver) = mpsc::channel();

        thread::spawn(move || {
            let result = match &source {
                Source::Binary(analysis, listing) => {
                    dump_binary(analysis, listing, &path, options, &shared)
                }
                Source::Apk(apk) => dump_apk(apk, &path, options, &shared),
            };
            let _ = sender.send(result.map_err(|error| format!("{error:#}")));
        });

        self.job = Some(Job { receiver, progress });
    }

    // Returns a status line while running, and again once when the dump ends.
    pub fn poll(&mut self, ctx: &egui::Context) -> Option<String> {
        let job = self.job.as_ref()?;
        match job.receiver.try_recv() {
            Ok(result) => {
                self.job = None;
                Some(match result {
                    Ok(summary) => finished_text(&summary),
                    Err(error) => format!("Dump failed: {error}"),
                })
            }
            Err(TryRecvError::Empty) => {
                ctx.request_repaint_after(Duration::from_millis(100));
                Some(format!(
                    "Dumping: {} files, {:.1} MB",
                    job.progress.files.load(Ordering::Relaxed),
                    job.progress.bytes.load(Ordering::Relaxed) as f64 / MEGABYTE
                ))
            }
            Err(TryRecvError::Disconnected) => {
                self.job = None;
                Some("Dump failed: the worker stopped".to_owned())
            }
        }
    }
}

fn finished_text(summary: &Summary) -> String {
    format!(
        "Dump saved: {} files, {:.1} MB packed into {:.1} MB in {:.2} s",
        summary.files,
        summary.uncompressed_bytes as f64 / MEGABYTE,
        summary.zip_bytes as f64 / MEGABYTE,
        summary.seconds
    )
}
