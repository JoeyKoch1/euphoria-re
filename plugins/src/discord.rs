use std::io::{self, Read, Write};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

const OP_HANDSHAKE: u32 = 0;
const OP_FRAME: u32 = 1;
const PIPE_COUNT: u32 = 10;
const MAX_FRAME_BYTES: usize = 1024 * 1024;
const MAX_TEXT_CHARS: usize = 120;

enum Command {
    Send(Value),
}

// Talks to the Discord app already running on this machine, over its local pipe.
pub(crate) struct Discord {
    commands: Sender<Command>,
    status: Arc<Mutex<String>>,
    last_reply: Arc<Mutex<Option<Value>>>,
    connected_at: u64,
}

#[derive(Default)]
pub(crate) struct Activity {
    pub(crate) details: Option<String>,
    pub(crate) state: Option<String>,
    pub(crate) large_image: Option<String>,
    pub(crate) large_text: Option<String>,
    pub(crate) started: bool,
}

impl Discord {
    pub(crate) fn connect(client_id: String) -> Self {
        let (commands, receiver) = mpsc::channel();
        let status = Arc::new(Mutex::new("connecting".to_owned()));
        let last_reply = Arc::new(Mutex::new(None));

        let shared = Arc::clone(&status);
        let reply = Arc::clone(&last_reply);
        thread::spawn(move || {
            let result = open_pipe().and_then(|stream| {
                run_session(
                    stream,
                    &client_id,
                    &receiver,
                    &|text| set_status(&shared, text),
                    &|value| {
                        if let Ok(mut slot) = reply.lock() {
                            *slot = Some(value.clone());
                        }
                    },
                )
            });
            set_status(
                &shared,
                match result {
                    Ok(()) => "disconnected".to_owned(),
                    Err(error) => format!("not connected: {error}"),
                },
            );
        });

        Self {
            commands,
            status,
            last_reply,
            connected_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |time| time.as_secs()),
        }
    }

    pub(crate) fn set_activity(&self, activity: Activity) {
        let payload = activity_json(&activity, self.connected_at);
        let _ = self.commands.send(Command::Send(activity_payload(payload)));
    }

    pub(crate) fn last_reply(&self) -> Option<Value> {
        self.last_reply.lock().ok().and_then(|reply| reply.clone())
    }

    pub(crate) fn clear(&self) {
        let _ = self
            .commands
            .send(Command::Send(activity_payload(Value::Null)));
    }

    pub(crate) fn status(&self) -> String {
        self.status
            .lock()
            .map_or_else(|_| "unknown".to_owned(), |status| status.clone())
    }
}

fn set_status(status: &Mutex<String>, text: String) {
    if let Ok(mut status) = status.lock() {
        *status = text;
    }
}

pub(crate) fn is_valid_client_id(id: &str) -> bool {
    !id.is_empty() && id.len() <= 32 && id.bytes().all(|byte| byte.is_ascii_digit())
}

fn clip(text: &str) -> String {
    text.chars().take(MAX_TEXT_CHARS).collect()
}

fn activity_json(activity: &Activity, connected_at: u64) -> Value {
    let mut fields = serde_json::Map::new();
    if let Some(details) = &activity.details {
        fields.insert("details".to_owned(), json!(clip(details)));
    }
    if let Some(state) = &activity.state {
        fields.insert("state".to_owned(), json!(clip(state)));
    }

    let mut assets = serde_json::Map::new();
    if let Some(image) = &activity.large_image {
        assets.insert("large_image".to_owned(), json!(clip(image)));
    }
    if let Some(text) = &activity.large_text {
        assets.insert("large_text".to_owned(), json!(clip(text)));
    }
    if !assets.is_empty() {
        fields.insert("assets".to_owned(), Value::Object(assets));
    }

    if activity.started {
        fields.insert("timestamps".to_owned(), json!({ "start": connected_at }));
    }
    Value::Object(fields)
}

fn activity_payload(activity: Value) -> Value {
    json!({
        "cmd": "SET_ACTIVITY",
        "nonce": format!("euphoria-{}", std::process::id()),
        "args": { "pid": std::process::id(), "activity": activity },
    })
}

fn encode_frame(op: u32, payload: &Value) -> Vec<u8> {
    let body = payload.to_string().into_bytes();
    let mut frame = Vec::with_capacity(body.len() + 8);
    frame.extend_from_slice(&op.to_le_bytes());
    frame.extend_from_slice(&(body.len() as u32).to_le_bytes());
    frame.extend_from_slice(&body);
    frame
}

fn read_frame(stream: &mut impl Read) -> io::Result<(u32, Value)> {
    let mut header = [0u8; 8];
    stream.read_exact(&mut header)?;
    let op = u32::from_le_bytes([header[0], header[1], header[2], header[3]]);
    let length = u32::from_le_bytes([header[4], header[5], header[6], header[7]]) as usize;
    if length > MAX_FRAME_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Discord sent an oversized message",
        ));
    }

    let mut body = vec![0u8; length];
    stream.read_exact(&mut body)?;
    let value = serde_json::from_slice(&body).map_err(io::Error::other)?;
    Ok((op, value))
}

fn run_session<S: Read + Write>(
    mut stream: S,
    client_id: &str,
    commands: &Receiver<Command>,
    report: &dyn Fn(String),
    on_reply: &dyn Fn(&Value),
) -> io::Result<()> {
    let handshake = json!({ "v": 1, "client_id": client_id });
    stream.write_all(&encode_frame(OP_HANDSHAKE, &handshake))?;
    let (_, ready) = read_frame(&mut stream)?;
    if ready.get("evt").and_then(Value::as_str) != Some("READY") {
        let message = ready
            .get("message")
            .and_then(Value::as_str)
            .unwrap_or("Discord refused the connection");
        return Err(io::Error::other(message.to_owned()));
    }
    report("connected".to_owned());

    while let Ok(Command::Send(payload)) = commands.recv() {
        stream.write_all(&encode_frame(OP_FRAME, &payload))?;
        let (_, reply) = read_frame(&mut stream)?;
        on_reply(&reply);
        if reply.get("evt").and_then(Value::as_str) == Some("ERROR") {
            let message = reply
                .pointer("/data/message")
                .and_then(Value::as_str)
                .unwrap_or("Discord rejected the update");
            report(format!("connected, last update failed: {message}"));
        } else {
            report("connected".to_owned());
        }
    }
    Ok(())
}

#[cfg(windows)]
fn open_pipe() -> io::Result<std::fs::File> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "Discord is not running");
    for index in 0..PIPE_COUNT {
        let path = format!(r"\\.\pipe\discord-ipc-{index}");
        match std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(path)
        {
            Ok(file) => return Ok(file),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(unix)]
fn open_pipe() -> io::Result<std::os::unix::net::UnixStream> {
    let base = ["XDG_RUNTIME_DIR", "TMPDIR", "TMP", "TEMP"]
        .iter()
        .find_map(std::env::var_os)
        .map_or_else(
            || std::path::PathBuf::from("/tmp"),
            std::path::PathBuf::from,
        );

    let mut last = io::Error::new(io::ErrorKind::NotFound, "Discord is not running");
    for index in 0..PIPE_COUNT {
        match std::os::unix::net::UnixStream::connect(base.join(format!("discord-ipc-{index}"))) {
            Ok(stream) => return Ok(stream),
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => last = error,
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;
    use std::io::Cursor;

    use super::*;

    struct FakeDiscord {
        replies: Cursor<Vec<u8>>,
        written: Vec<u8>,
    }

    impl Read for FakeDiscord {
        fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
            self.replies.read(buffer)
        }
    }

    impl Write for FakeDiscord {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            self.written.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            Ok(())
        }
    }

    fn fake(replies: &[Value]) -> FakeDiscord {
        let mut bytes = Vec::new();
        for reply in replies {
            bytes.extend(encode_frame(OP_FRAME, reply));
        }
        FakeDiscord {
            replies: Cursor::new(bytes),
            written: Vec::new(),
        }
    }

    #[test]
    fn encodes_and_decodes_frames() {
        let frame = encode_frame(OP_FRAME, &json!({ "a": 1 }));
        assert_eq!(&frame[..4], &1u32.to_le_bytes());
        assert_eq!(&frame[4..8], &7u32.to_le_bytes());

        let (op, value) = read_frame(&mut Cursor::new(frame)).unwrap();
        assert_eq!(op, OP_FRAME);
        assert_eq!(value["a"], 1);
    }

    #[test]
    fn rejects_oversized_and_broken_frames() {
        let mut huge = 1u32.to_le_bytes().to_vec();
        huge.extend_from_slice(&u32::MAX.to_le_bytes());
        assert!(read_frame(&mut Cursor::new(huge)).is_err());
        assert!(read_frame(&mut Cursor::new(vec![1, 2, 3])).is_err());

        let mut invalid = 1u32.to_le_bytes().to_vec();
        invalid.extend_from_slice(&3u32.to_le_bytes());
        invalid.extend_from_slice(b"{{{");
        assert!(read_frame(&mut Cursor::new(invalid)).is_err());
    }

    #[test]
    fn shakes_hands_then_sends_activity() {
        let mut stream = fake(&[json!({ "evt": "READY" }), json!({ "evt": null })]);
        let (sender, receiver) = mpsc::channel();
        sender
            .send(Command::Send(activity_payload(json!({ "details": "x" }))))
            .unwrap();
        drop(sender);

        let reports = RefCell::new(Vec::new());
        run_session(
            &mut stream,
            "123",
            &receiver,
            &|text| reports.borrow_mut().push(text),
            &|_| {},
        )
        .unwrap();

        let mut written = Cursor::new(stream.written);
        let (op, handshake) = read_frame(&mut written).unwrap();
        assert_eq!(op, OP_HANDSHAKE);
        assert_eq!(handshake["client_id"], "123");

        let (op, update) = read_frame(&mut written).unwrap();
        assert_eq!(op, OP_FRAME);
        assert_eq!(update["cmd"], "SET_ACTIVITY");
        assert_eq!(update["args"]["activity"]["details"], "x");
        assert_eq!(reports.into_inner(), ["connected", "connected"]);
    }

    #[test]
    fn reports_a_refused_handshake() {
        let mut stream = fake(&[json!({ "code": 4000, "message": "Invalid Client ID" })]);
        let (_sender, receiver) = mpsc::channel();

        let error = run_session(&mut stream, "1", &receiver, &|_| {}, &|_| {}).unwrap_err();
        assert!(error.to_string().contains("Invalid Client ID"));
    }

    #[test]
    fn builds_activity_with_a_steady_start_time_and_art() {
        let activity = Activity {
            details: Some("sample.exe".to_owned()),
            state: Some("Tab: Graph".to_owned()),
            large_image: Some("euphoria".to_owned()),
            large_text: Some("Euphoria".to_owned()),
            started: true,
        };
        let json = activity_json(&activity, 1234);

        assert_eq!(json["details"], "sample.exe");
        assert_eq!(json["state"], "Tab: Graph");
        assert_eq!(json["assets"]["large_image"], "euphoria");
        assert_eq!(json["assets"]["large_text"], "Euphoria");
        assert_eq!(json["timestamps"]["start"], 1234);

        let empty = activity_json(&Activity::default(), 1234);
        assert_eq!(empty, json!({}));
    }

    #[test]
    fn validates_client_ids() {
        assert!(is_valid_client_id("1234567890"));
        assert!(!is_valid_client_id(""));
        assert!(!is_valid_client_id("abc"));
        assert!(!is_valid_client_id(&"1".repeat(33)));
    }
}
