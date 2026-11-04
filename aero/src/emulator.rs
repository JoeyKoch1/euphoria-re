use std::io::{ErrorKind, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::Duration;

use serde::{Deserialize, Serialize};

use crate::Error;

const SHORT_PORTS: [u16; 6] = [80, 81, 82, 88, 89, 8080];
const MAX_HEAD_BYTES: usize = 64 * 1024;
const POLL: Duration = Duration::from_millis(25);
const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Route {
    pub method: String,
    pub path: String,
    pub status: u16,
    pub content_type: String,
    pub body: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hit {
    pub method: String,
    pub path: String,
    pub status: u16,
}

#[derive(Default)]
struct Shared {
    routes: Mutex<Vec<Route>>,
    hits: Mutex<Vec<Hit>>,
    stop: AtomicBool,
}

// A local fake server that replays saved responses. It only ever listens on 127.0.0.1.
pub struct Emulator {
    port: u16,
    shared: Arc<Shared>,
    worker: Option<thread::JoinHandle<()>>,
}

impl Emulator {
    // Short ports come first because a patched URL has to fit in the space of the original.
    pub fn start() -> Result<Self, Error> {
        Self::start_preferring(&SHORT_PORTS)
    }

    pub fn start_preferring(ports: &[u16]) -> Result<Self, Error> {
        let listener = ports
            .iter()
            .find_map(|&port| TcpListener::bind(("127.0.0.1", port)).ok())
            .map_or_else(|| TcpListener::bind(("127.0.0.1", 0)), Ok)?;
        listener.set_nonblocking(true)?;
        let port = listener.local_addr()?.port();

        let shared = Arc::new(Shared::default());
        let state = Arc::clone(&shared);
        let worker = thread::spawn(move || accept_loop(&listener, &state));

        Ok(Self {
            port,
            shared,
            worker: Some(worker),
        })
    }

    pub fn address(&self) -> String {
        if self.port == 80 {
            return "http://127.0.0.1".to_owned();
        }
        format!("http://127.0.0.1:{}", self.port)
    }

    pub fn set_route(&self, route: Route) {
        if let Ok(mut routes) = self.shared.routes.lock() {
            routes.retain(|existing| {
                !(existing.method == route.method && existing.path == route.path)
            });
            routes.push(route);
        }
    }

    pub fn routes(&self) -> Vec<Route> {
        self.shared
            .routes
            .lock()
            .map(|routes| routes.clone())
            .unwrap_or_default()
    }

    pub fn hits(&self) -> Vec<Hit> {
        self.shared
            .hits
            .lock()
            .map(|hits| hits.clone())
            .unwrap_or_default()
    }
}

impl Drop for Emulator {
    fn drop(&mut self) {
        self.shared.stop.store(true, Ordering::Relaxed);
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn accept_loop(listener: &TcpListener, shared: &Arc<Shared>) {
    while !shared.stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                let shared = Arc::clone(shared);
                thread::spawn(move || {
                    let _ = serve(stream, &shared);
                });
            }
            Err(error) if error.kind() == ErrorKind::WouldBlock => thread::sleep(POLL),
            Err(_) => thread::sleep(POLL),
        }
    }
}

fn serve(mut stream: TcpStream, shared: &Shared) -> std::io::Result<()> {
    stream.set_nonblocking(false)?;
    stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;

    let mut head = Vec::new();
    let mut buffer = [0u8; 2048];
    while !head.windows(4).any(|window| window == b"\r\n\r\n") && head.len() < MAX_HEAD_BYTES {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        head.extend_from_slice(&buffer[..read]);
    }

    let text = String::from_utf8_lossy(&head);
    let mut parts = text.lines().next().unwrap_or("").split_whitespace();
    let method = parts.next().unwrap_or("").to_owned();
    let full_path = parts.next().unwrap_or("/");
    let path = full_path.split('?').next().unwrap_or("/").to_owned();

    let route = shared.routes.lock().ok().and_then(|routes| {
        routes
            .iter()
            .find(|route| {
                route.method == method && route.path.split('?').next() == Some(path.as_str())
            })
            .cloned()
    });
    let (status, content_type, body) = match route {
        Some(route) => (route.status, route.content_type, route.body),
        None => (
            404,
            "text/plain".to_owned(),
            "No saved response for this route".to_owned(),
        ),
    };

    if let Ok(mut hits) = shared.hits.lock() {
        hits.push(Hit {
            method,
            path,
            status,
        });
    }

    let response = format!(
        "HTTP/1.1 {status} Emulated\r\nContent-Type: {content_type}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
        body.len()
    );
    stream.write_all(response.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::http::{Request, send};

    fn get(url: String) -> crate::Capture {
        send(&Request {
            method: "GET".to_owned(),
            url,
            ..Request::default()
        })
        .unwrap()
    }

    #[test]
    fn replays_saved_json_through_the_real_client() {
        let emulator = Emulator::start_preferring(&[0]).unwrap();
        assert!(emulator.address().starts_with("http://127.0.0.1:"));

        emulator.set_route(Route {
            method: "GET".to_owned(),
            path: "/api/config?x=1".to_owned(),
            status: 200,
            content_type: "application/json".to_owned(),
            body: r#"{"enabled":true,"name":"é"}"#.to_owned(),
        });

        let capture = get(format!("{}/api/config?y=2", emulator.address()));
        assert_eq!(capture.status, 200);
        assert!(capture.is_json());
        assert_eq!(capture.json.unwrap()["name"], "é");

        let missing = get(format!("{}/nope", emulator.address()));
        assert_eq!(missing.status, 404);
        assert!(!missing.is_json());

        let hits = emulator.hits();
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].path, "/api/config");
        assert_eq!(hits[1].status, 404);
    }

    #[test]
    fn replacing_a_route_keeps_only_the_newest() {
        let emulator = Emulator::start_preferring(&[0]).unwrap();
        for body in ["one", "two"] {
            emulator.set_route(Route {
                method: "GET".to_owned(),
                path: "/a".to_owned(),
                status: 200,
                content_type: "text/plain".to_owned(),
                body: body.to_owned(),
            });
        }
        assert_eq!(emulator.routes().len(), 1);
        assert_eq!(get(format!("{}/a", emulator.address())).body, "two");
    }

    #[test]
    fn skips_a_busy_preferred_port() {
        let busy = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let taken = busy.local_addr().unwrap().port();

        let emulator = Emulator::start_preferring(&[taken, 0]).unwrap();
        assert!(!emulator.address().ends_with(&format!(":{taken}")));
    }

    #[test]
    fn stops_listening_when_dropped() {
        let emulator = Emulator::start_preferring(&[0]).unwrap();
        let address = emulator.address();
        drop(emulator);
        let result = send(&Request {
            method: "GET".to_owned(),
            url: format!("{address}/"),
            ..Request::default()
        });
        assert!(result.is_err());
    }
}
