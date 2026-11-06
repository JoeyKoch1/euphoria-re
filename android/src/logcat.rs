use std::io::{BufRead, BufReader};
use std::process::{Child, ExitStatus, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::adb::Adb;

const MAX_LINE_CHARS: usize = 2000;
const BATCH_LINES: usize = 32;
const BATCH_INTERVAL: Duration = Duration::from_millis(200);
const CHANNEL_BATCHES: usize = 512;

// `adb logcat` is a long-lived child owned by the runtime worker. A reader thread turns its
// output into batches so the UI only wakes up with useful chunks.
pub(crate) struct Logcat {
    child: Child,
    receiver: Receiver<Vec<String>>,
    stop: Arc<AtomicBool>,
    reader: Option<JoinHandle<()>>,
}

impl Logcat {
    pub fn start(adb: &Adb, serial: &str) -> Result<Self> {
        let mut command = adb.logcat_command(serial)?;
        let mut child = command
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .context("cannot start adb logcat")?;
        let stdout = child.stdout.take().context("missing logcat stdout")?;
        let (sender, receiver) = mpsc::sync_channel(CHANNEL_BATCHES);
        let stop = Arc::new(AtomicBool::new(false));
        let reader = spawn_reader(stdout, sender, Arc::clone(&stop));
        Ok(Self {
            child,
            receiver,
            stop,
            reader: Some(reader),
        })
    }

    pub fn try_recv(&self) -> Option<Vec<String>> {
        self.receiver.try_recv().ok()
    }

    pub fn exited(&mut self) -> Option<ExitStatus> {
        self.child.try_wait().ok().flatten()
    }

    pub fn stop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        let _ = self.child.kill();
        let _ = self.child.wait();
        // Drop the receiver first so the reader cannot block on a full channel while joining.
        let (_, empty) = mpsc::sync_channel(1);
        drop(std::mem::replace(&mut self.receiver, empty));
        if let Some(reader) = self.reader.take() {
            let _ = reader.join();
        }
    }
}

impl Drop for Logcat {
    fn drop(&mut self) {
        self.stop();
    }
}

fn spawn_reader(
    stdout: std::process::ChildStdout,
    sender: SyncSender<Vec<String>>,
    stop: Arc<AtomicBool>,
) -> JoinHandle<()> {
    thread::spawn(move || {
        let mut reader = BufReader::new(stdout);
        let mut line = String::new();
        let mut batch = Vec::new();
        let mut sent_at = Instant::now();
        loop {
            if stop.load(Ordering::Relaxed) {
                break;
            }
            line.clear();
            match reader.read_line(&mut line) {
                Ok(0) | Err(_) => break,
                Ok(_) => {
                    let text = line.trim_end_matches(['\r', '\n']);
                    batch.push(cap_line(text));
                    if batch.len() >= BATCH_LINES || sent_at.elapsed() >= BATCH_INTERVAL {
                        if sender.send(std::mem::take(&mut batch)).is_err() {
                            return;
                        }
                        sent_at = Instant::now();
                    }
                }
            }
        }
        if !batch.is_empty() {
            let _ = sender.send(batch);
        }
    })
}

fn cap_line(text: &str) -> String {
    if text.chars().count() <= MAX_LINE_CHARS {
        return text.to_owned();
    }
    let mut capped: String = text.chars().take(MAX_LINE_CHARS).collect();
    capped.push('…');
    capped
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn long_log_lines_are_capped() {
        let text = "x".repeat(MAX_LINE_CHARS + 10);
        let capped = cap_line(&text);
        assert_eq!(capped.chars().count(), MAX_LINE_CHARS + 1);
        assert!(capped.ends_with('…'));
        assert_eq!(cap_line("short"), "short");
    }
}
