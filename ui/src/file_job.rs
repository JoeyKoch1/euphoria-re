use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread;

use anyhow::{Result, ensure};
use euphoria_engine::{Analysis, dataset};
use euphoria_plugins::BinaryView;

use crate::{ApkView, NetworkState, Project, SqlView};

pub enum LoadedFile {
    Binary(Box<Project>, BinaryView),
    Apk(ApkView, BinaryView),
    Sql(SqlView),
}

pub enum Outcome {
    Opened(PathBuf, Box<LoadedFile>, NetworkState),
    Saved(u64),
}

enum Event {
    Progress(&'static str),
    Finished(Result<Outcome, String>),
}

pub struct FileJob {
    receiver: Receiver<Event>,
    cancelled: Arc<AtomicBool>,
    pub progress: &'static str,
}

impl FileJob {
    fn start(
        work: impl FnOnce(&Sender<Event>, &AtomicBool) -> Result<Outcome> + Send + 'static,
    ) -> Self {
        let (sender, receiver) = mpsc::channel();
        let cancelled = Arc::new(AtomicBool::new(false));
        let flag = Arc::clone(&cancelled);
        thread::spawn(move || {
            let result = work(&sender, &flag).map_err(|error| format!("{error:#}"));
            let _ = sender.send(Event::Finished(result));
        });
        Self {
            receiver,
            cancelled,
            progress: "Starting...",
        }
    }

    pub fn open(path: PathBuf) -> Self {
        Self::start(move |sender, cancelled| {
            let progress = |message| -> Result<()> {
                ensure!(!cancelled.load(Ordering::Relaxed), "Open canceled");
                let _ = sender.send(Event::Progress(message));
                Ok(())
            };
            progress("Reading file...")?;
            let mut network = NetworkState::default();
            let loaded = if euphoria_apk::is_apk(&path) {
                let apk = euphoria_apk::Apk::open(&path)?;
                progress("Indexing APK...")?;
                network.load_apk_links(&apk);
                let view = BinaryView::named(
                    apk.file_name.clone(),
                    "android",
                    apk.sha256.clone(),
                    Arc::clone(&apk.data),
                );
                LoadedFile::Apk(ApkView::new(apk), view)
            } else if euphoria_sql::is_sql_file(&path) {
                LoadedFile::Sql(SqlView::new(euphoria_sql::open(&path)?))
            } else {
                let project = Project::open(&path, &progress)?;
                progress("Indexing links...")?;
                network.load_links(&project.listing);
                network.restore(&project.analysis.extras);
                let view = BinaryView::new(&project.analysis, &project.listing);
                LoadedFile::Binary(Box::new(project), view)
            };
            progress("Ready")?;
            Ok(Outcome::Opened(path, Box::new(loaded), network))
        })
    }

    pub fn save(path: PathBuf, analysis: Arc<Analysis>, extras: serde_json::Value) -> Self {
        Self::start(move |sender, cancelled| {
            let _ = sender.send(Event::Progress("Compressing dataset..."));
            let meta = dataset::Meta {
                file_name: analysis.file_name.clone(),
                sha256: analysis.sha256.clone(),
                extras,
            };
            let written = dataset::write_cancellable(
                &path.with_extension(dataset::EXTENSION),
                &meta,
                &analysis.data,
                cancelled,
            )?;
            Ok(Outcome::Saved(written))
        })
    }

    pub fn cancel(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
        self.progress = "Canceling...";
    }

    pub fn poll(&mut self) -> Option<Result<Outcome, String>> {
        loop {
            match self.receiver.try_recv() {
                Ok(Event::Progress(message)) => {
                    if !self.cancelled.load(Ordering::Relaxed) {
                        self.progress = message;
                    }
                }
                Ok(Event::Finished(Ok(Outcome::Opened(..))))
                    if self.cancelled.load(Ordering::Relaxed) =>
                {
                    return Some(Err("Open canceled".into()));
                }
                Ok(Event::Finished(result)) => return Some(result),
                Err(TryRecvError::Empty) => return None,
                Err(TryRecvError::Disconnected) => {
                    return Some(Err("The file worker stopped".into()));
                }
            }
        }
    }
}

impl Drop for FileJob {
    fn drop(&mut self) {
        self.cancelled.store(true, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reports_worker_failure_and_discards_canceled_loads() {
        let (sender, receiver) = mpsc::channel();
        let mut job = FileJob {
            receiver,
            cancelled: Arc::new(AtomicBool::new(false)),
            progress: "Starting",
        };
        drop(sender);
        assert!(job.poll().unwrap().is_err());
        let (sender, receiver) = mpsc::channel();
        job.receiver = receiver;
        job.cancel();
        let script = euphoria_sql::Script::default();
        assert!(
            sender
                .send(Event::Finished(Ok(Outcome::Opened(
                    "test.sql".into(),
                    Box::new(LoadedFile::Sql(SqlView::new(script))),
                    NetworkState::default(),
                ))))
                .is_ok()
        );
        assert!(job.poll().unwrap().is_err());
    }
}
