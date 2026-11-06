use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use eframe::egui::{self, RichText, Ui};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::theme;

const DEFAULT_ENDPOINT: &str = "http://127.0.0.1:11434/v1/chat/completions";
const MAX_PROMPT_CHARS: usize = 24_000;
const SYSTEM: &str = "You explain assembly routines to a reverse engineer. Be concrete and concise. \
Cover inputs, outputs, side effects, control flow, and anything suspicious. If the evidence is \
incomplete, say what is uncertain. Never invent symbol names.";

// Off by default. Nothing is sent until the user turns this on and presses Explain, and only the
// pseudocode of the routine on screen is ever included in a request.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default = "default_endpoint")]
    pub endpoint: String,
    #[serde(default)]
    pub model: String,
}

fn default_endpoint() -> String {
    DEFAULT_ENDPOINT.to_owned()
}

impl Default for Config {
    fn default() -> Self {
        Self {
            enabled: false,
            endpoint: default_endpoint(),
            model: String::new(),
        }
    }
}

fn config_path() -> Option<PathBuf> {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
    Some(base.join("Euphoria").join("assist.json"))
}

impl Config {
    pub fn load() -> Self {
        config_path()
            .and_then(|path| std::fs::read(path).ok())
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) {
        let Some(path) = config_path() else {
            return;
        };
        let Ok(bytes) = serde_json::to_vec_pretty(self) else {
            return;
        };
        if let Some(parent) = path.parent() {
            let _ = std::fs::create_dir_all(parent);
        }
        let _ = std::fs::write(path, bytes);
    }
}

pub fn is_loopback(endpoint: &str) -> bool {
    let Some((_, rest)) = endpoint.split_once("://") else {
        return false;
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or("");
    let host = match authority.strip_prefix('[') {
        Some(rest) => rest.split(']').next().unwrap_or(""),
        None => match authority.rsplit_once(':') {
            Some((host, port)) if port.chars().all(|digit| digit.is_ascii_digit()) => host,
            _ => authority,
        },
    };
    matches!(host, "127.0.0.1" | "localhost" | "::1")
}

fn prompt(va: u64, code: &str) -> String {
    let code = match code.char_indices().nth(MAX_PROMPT_CHARS) {
        Some((end, _)) => &code[..end],
        None => code,
    };
    format!("Routine at {va:#x}. Explain what it does.\n\n```c\n{code}\n```")
}

fn parse_answer(body: &str) -> Result<String, String> {
    let value: Value =
        serde_json::from_str(body).map_err(|_| "The endpoint did not return JSON".to_owned())?;
    value
        .pointer("/choices/0/message/content")
        .and_then(Value::as_str)
        .or_else(|| value.pointer("/choices/0/text").and_then(Value::as_str))
        .or_else(|| value.get("response").and_then(Value::as_str))
        .or_else(|| value.pointer("/message/content").and_then(Value::as_str))
        .map(str::trim)
        .filter(|text| !text.is_empty())
        .map(str::to_owned)
        .ok_or_else(|| "The endpoint returned no explanation text".to_owned())
}

pub fn ask(config: &Config, va: u64, code: &str) -> Result<String, String> {
    let endpoint = config.endpoint.trim();
    if endpoint.is_empty() {
        return Err("Set an endpoint in Assist settings".to_owned());
    }
    if config.model.trim().is_empty() {
        return Err("Set a model name in Assist settings".to_owned());
    }

    let body = serde_json::to_vec(&serde_json::json!({
        "model": config.model.trim(),
        "stream": false,
        "temperature": 0.2,
        "messages": [
            { "role": "system", "content": SYSTEM },
            { "role": "user", "content": prompt(va, code) },
        ],
    }))
    .map_err(|error| error.to_string())?;

    let response = aero::send(&aero::Request {
        method: "POST".to_owned(),
        url: endpoint.to_owned(),
        headers: vec![("Content-Type".to_owned(), "application/json".to_owned())],
        body,
    })
    .map_err(|error| error.to_string())?;

    if !(200..300).contains(&response.status) {
        let excerpt: String = response.body.chars().take(300).collect();
        return Err(format!(
            "The endpoint answered {}: {excerpt}",
            response.status
        ));
    }
    parse_answer(&response.body)
}

#[derive(Default)]
pub struct State {
    job: Option<(u64, Receiver<Result<String, String>>)>,
    answer: Option<(u64, String)>,
    error: Option<(u64, String)>,
}

impl State {
    fn start(&mut self, va: u64, code: &str, config: &Config, ctx: &egui::Context) {
        config.save();
        let config = config.clone();
        let code = code.to_owned();
        let (sender, receiver) = mpsc::channel();
        let ctx = ctx.clone();
        thread::spawn(move || {
            let outcome = ask(&config, va, &code);
            let _ = sender.send(outcome);
            ctx.request_repaint();
        });
        self.answer = None;
        self.error = None;
        self.job = Some((va, receiver));
    }

    fn poll(&mut self) {
        let Some((va, receiver)) = &self.job else {
            return;
        };
        match receiver.try_recv() {
            Ok(Ok(answer)) => {
                self.answer = Some((*va, answer));
                self.job = None;
            }
            Ok(Err(error)) => {
                self.error = Some((*va, error));
                self.job = None;
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => {
                self.error = Some((*va, "The assist request stopped".to_owned()));
                self.job = None;
            }
        }
    }

    fn clear(&mut self) {
        self.job = None;
        self.answer = None;
        self.error = None;
    }
}

pub fn panel(ui: &mut Ui, config: &mut Config, state: &mut State, va: u64, code: &str) {
    state.poll();

    egui::CollapsingHeader::new("Assist")
        .default_open(config.enabled)
        .show(ui, |ui| {
            let mut save = false;
            save |= ui
                .checkbox(&mut config.enabled, "Local AI assist")
                .on_hover_text(
                    "Asks a local OpenAI-compatible endpoint to explain the routine on screen. \
                     Only that routine's pseudocode is sent, and only when you press Explain.",
                )
                .changed();

            if !config.enabled {
                ui.label(RichText::new("Off. Nothing is sent anywhere.").color(theme::MUTED));
                if save {
                    config.save();
                }
                return;
            }

            egui::Grid::new("assist_settings")
                .num_columns(2)
                .spacing([10.0, 4.0])
                .show(ui, |ui| {
                    ui.label(RichText::new("Endpoint").color(theme::MUTED));
                    save |= ui
                        .add(
                            egui::TextEdit::singleline(&mut config.endpoint)
                                .desired_width(420.0)
                                .hint_text(DEFAULT_ENDPOINT),
                        )
                        .lost_focus();
                    ui.end_row();
                    ui.label(RichText::new("Model").color(theme::MUTED));
                    save |= ui
                        .add(
                            egui::TextEdit::singleline(&mut config.model)
                                .desired_width(240.0)
                                .hint_text("model name"),
                        )
                        .lost_focus();
                    ui.end_row();
                });

            if !is_loopback(&config.endpoint) {
                ui.label(
                    RichText::new(
                        "This endpoint is not on this machine. The pseudocode you send leaves \
                         your computer.",
                    )
                    .color(theme::NUMBER),
                );
            }
            ui.label(
                RichText::new("Sends only the routine's pseudocode, when you press Explain.")
                    .color(theme::MUTED)
                    .size(11.0),
            );

            ui.horizontal(|ui| {
                if ui
                    .button("Explain this routine")
                    .on_hover_text("Ask the endpoint to describe the code on screen")
                    .clicked()
                {
                    state.start(va, code, config, ui.ctx());
                }
                if state.job.is_some() && ui.button("Stop waiting").clicked() {
                    state.job = None;
                }
                let has_text = state.answer.as_ref().is_some_and(|(at, _)| *at == va)
                    || state.error.as_ref().is_some_and(|(at, _)| *at == va);
                if has_text && ui.button("Clear").clicked() {
                    state.clear();
                }
            });

            if let Some((at, _)) = &state.job
                && *at == va
            {
                ui.horizontal(|ui| {
                    ui.spinner();
                    ui.label(RichText::new("Waiting for the endpoint...").color(theme::MUTED));
                });
            }
            if let Some((at, error)) = &state.error
                && *at == va
            {
                ui.label(RichText::new(error).color(theme::ERROR));
            }
            if let Some((at, answer)) = &state.answer
                && *at == va
            {
                egui::ScrollArea::vertical()
                    .id_salt("assist_answer")
                    .max_height(260.0)
                    .auto_shrink(false)
                    .show(ui, |ui| {
                        ui.add(
                            egui::Label::new(RichText::new(answer).size(12.5))
                                .selectable(true)
                                .wrap(),
                        );
                    });
            }

            if save {
                config.save();
            }
        });
}

#[cfg(test)]
mod tests {
    use std::io::{Read, Write};
    use std::net::TcpListener;

    use super::*;

    fn config(endpoint: &str) -> Config {
        Config {
            enabled: true,
            endpoint: endpoint.to_owned(),
            model: "test-model".to_owned(),
        }
    }

    #[test]
    fn only_treats_this_machine_as_loopback() {
        assert!(is_loopback("http://127.0.0.1:11434/v1/chat/completions"));
        assert!(is_loopback("http://localhost:8080/v1"));
        assert!(is_loopback("http://[::1]:8080/v1"));
        assert!(!is_loopback("https://api.example.com/v1"));
        assert!(!is_loopback("http://192.168.1.20:11434/v1"));
        assert!(!is_loopback("not a url"));
    }

    #[test]
    fn clips_long_pseudocode() {
        let code = "x".repeat(MAX_PROMPT_CHARS + 500);
        let text = prompt(0x1000, &code);
        assert!(text.len() < MAX_PROMPT_CHARS + 200);
        assert!(text.contains("0x1000"));
    }

    #[test]
    fn reads_the_common_response_shapes() {
        let openai = r#"{"choices":[{"message":{"content":" Returns the sum. "}}]}"#;
        assert_eq!(parse_answer(openai).unwrap(), "Returns the sum.");

        let completion = r#"{"choices":[{"text":"Loops over the buffer."}]}"#;
        assert_eq!(parse_answer(completion).unwrap(), "Loops over the buffer.");

        let ollama = r#"{"response":"Copies 16 bytes."}"#;
        assert_eq!(parse_answer(ollama).unwrap(), "Copies 16 bytes.");

        assert!(parse_answer("not json").is_err());
        assert!(parse_answer(r#"{"choices":[]}"#).is_err());
    }

    #[test]
    fn asks_a_loopback_endpoint_and_reports_errors() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let server = std::thread::spawn(move || {
            for (status, body) in [
                (
                    200,
                    r#"{"choices":[{"message":{"content":"Adds two numbers."}}]}"#,
                ),
                (503, "model not loaded"),
            ] {
                let (mut stream, _) = listener.accept().unwrap();
                let mut request = [0u8; 8192];
                let _ = stream.read(&mut request);
                let response = format!(
                    "HTTP/1.1 {status} X\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{body}",
                    body.len()
                );
                stream.write_all(response.as_bytes()).unwrap();
            }
        });

        let endpoint = format!("http://{address}/v1/chat/completions");
        let answer = ask(&config(&endpoint), 0x1000, "return a + b;").unwrap();
        assert_eq!(answer, "Adds two numbers.");

        let error = ask(&config(&endpoint), 0x1000, "return a + b;").unwrap_err();
        assert!(error.contains("503"), "{error}");
        assert!(error.contains("model not loaded"), "{error}");

        server.join().unwrap();
    }
}
