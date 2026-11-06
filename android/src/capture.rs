use std::collections::VecDeque;
use std::io::{self, Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream, ToSocketAddrs};
use std::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

const HEAD_LIMIT: usize = 64 * 1024;
const LINE_LIMIT: usize = 8 * 1024;
const PREVIEW_LIMIT: usize = 1000;
const SOCKET_TIMEOUT: Duration = Duration::from_secs(20);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const ACCEPT_POLL: Duration = Duration::from_millis(25);
const MAX_CONNECTIONS: usize = 128;
// The UI drains a few times a second; this bounds memory if a long install gives it no chance
// to do so while the proxy keeps reporting traffic.
const EVENT_BACKLOG: usize = 512;

// One captured exchange. HTTP requests carry a status and a body preview; CONNECT tunnels carry
// only the destination and byte counts because TLS keeps the payload opaque.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureEvent {
    pub id: u64,
    pub scheme: &'static str,
    pub method: String,
    pub host: String,
    pub path: String,
    pub status: Option<u16>,
    pub request_bytes: u64,
    pub response_bytes: u64,
    pub millis: u64,
    pub content_type: String,
    pub preview: String,
    pub note: String,
}

pub struct CaptureServer {
    port: u16,
    stop: Arc<AtomicBool>,
    events: EventSink,
}

#[derive(Clone)]
struct EventSink(Arc<Mutex<VecDeque<CaptureEvent>>>);

impl EventSink {
    fn push(&self, event: CaptureEvent) {
        let Ok(mut queue) = self.0.lock() else {
            return;
        };
        if queue.len() >= EVENT_BACKLOG {
            queue.pop_front();
        }
        queue.push_back(event);
    }
}

impl CaptureServer {
    pub fn start() -> Result<Self> {
        let listener =
            TcpListener::bind(("127.0.0.1", 0)).context("cannot bind the capture proxy")?;
        listener
            .set_nonblocking(true)
            .context("cannot configure the capture proxy")?;
        let port = listener.local_addr()?.port();
        let stop = Arc::new(AtomicBool::new(false));
        let ids = Arc::new(AtomicU64::new(1));
        let active = Arc::new(AtomicUsize::new(0));
        let events = EventSink(Arc::new(Mutex::new(VecDeque::new())));
        let accept_events = events.clone();
        let accept_stop = Arc::clone(&stop);
        thread::spawn(move || accept_loop(listener, accept_events, accept_stop, ids, active));
        Ok(Self { port, stop, events })
    }

    pub fn port(&self) -> u16 {
        self.port
    }

    pub fn drain(&self) -> Vec<CaptureEvent> {
        let Ok(mut queue) = self.events.0.lock() else {
            return Vec::new();
        };
        queue.drain(..).collect()
    }
}

impl Drop for CaptureServer {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
    }
}

fn accept_loop(
    listener: TcpListener,
    events: EventSink,
    stop: Arc<AtomicBool>,
    ids: Arc<AtomicU64>,
    active: Arc<AtomicUsize>,
) {
    while !stop.load(Ordering::Relaxed) {
        match listener.accept() {
            Ok((stream, _)) => {
                // A single misbehaving guest app must not be able to spawn unbounded host
                // threads; further connections are dropped until one finishes.
                if active.fetch_add(1, Ordering::Relaxed) >= MAX_CONNECTIONS {
                    active.fetch_sub(1, Ordering::Relaxed);
                    continue;
                }
                let events = events.clone();
                let stop = Arc::clone(&stop);
                let ids = Arc::clone(&ids);
                let active = Arc::clone(&active);
                thread::spawn(move || {
                    let _guard = ActiveGuard(active);
                    handle_client(stream, events, stop, ids);
                });
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => thread::sleep(ACCEPT_POLL),
            Err(_) => thread::sleep(Duration::from_millis(100)),
        }
    }
}

struct ActiveGuard(Arc<AtomicUsize>);

impl Drop for ActiveGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

fn handle_client(
    mut client: TcpStream,
    events: EventSink,
    stop: Arc<AtomicBool>,
    ids: Arc<AtomicU64>,
) {
    let _ = client.set_read_timeout(Some(SOCKET_TIMEOUT));
    let _ = client.set_write_timeout(Some(SOCKET_TIMEOUT));
    let started = Instant::now();
    let Ok(head) = read_head(&mut client) else {
        return;
    };
    let Some(request) = Request::parse(&head) else {
        return;
    };
    let id = ids.fetch_add(1, Ordering::Relaxed);
    if request.method.eq_ignore_ascii_case("CONNECT") {
        tunnel(id, client, request, events, stop, started);
    } else {
        forward(id, client, request, events, started);
    }
}

struct Request {
    method: String,
    host: String,
    port: u16,
    path: String,
    headers: Vec<(String, String)>,
    head: Vec<u8>,
}

impl Request {
    fn parse(head: &[u8]) -> Option<Self> {
        let text = String::from_utf8_lossy(head);
        let mut lines = text.split('\n').map(|line| line.trim_end_matches('\r'));
        let request_line = lines.next()?;
        let mut parts = request_line.split_whitespace();
        let method = parts.next()?.to_owned();
        let target = parts.next()?;
        let headers = parse_headers(lines);

        if method.eq_ignore_ascii_case("CONNECT") {
            let (host, port) = split_host_port(target, 443)?;
            return Some(Self {
                method,
                host,
                port,
                path: String::new(),
                headers,
                head: head.to_vec(),
            });
        }

        let (host, port, path) = if let Some(rest) = target.strip_prefix("http://") {
            let (authority, path) = match rest.find('/') {
                Some(index) => (&rest[..index], rest[index..].to_owned()),
                None => (rest, "/".to_owned()),
            };
            let (host, port) = split_host_port(authority, 80)?;
            (host, port, path)
        } else {
            let host_header = header(&headers, "host")?;
            let (host, port) = split_host_port(host_header, 80)?;
            (host, port, target.to_owned())
        };
        Some(Self {
            method,
            host,
            port,
            path,
            headers,
            head: head.to_vec(),
        })
    }
}

fn split_host_port(value: &str, default_port: u16) -> Option<(String, u16)> {
    let value = value.trim();
    if value.is_empty() {
        return None;
    }
    // IPv6 literals arrive as [::1]:8080.
    if let Some(rest) = value.strip_prefix('[') {
        let (host, tail) = rest.split_once(']')?;
        let port = tail
            .strip_prefix(':')
            .and_then(|port| port.parse().ok())
            .unwrap_or(default_port);
        return Some((host.to_owned(), port));
    }
    match value.rsplit_once(':') {
        Some((host, port)) if !host.contains(':') => Some((host.to_owned(), port.parse().ok()?)),
        _ => Some((value.to_owned(), default_port)),
    }
}

fn parse_headers<'a>(lines: impl Iterator<Item = &'a str>) -> Vec<(String, String)> {
    let mut headers = Vec::new();
    for line in lines {
        if line.is_empty() {
            break;
        }
        if let Some((name, value)) = line.split_once(':') {
            headers.push((name.trim().to_ascii_lowercase(), value.trim().to_owned()));
        }
    }
    headers
}

fn header<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(key, _)| key == name)
        .map(|(_, value)| value.as_str())
}

fn connect(host: &str, port: u16) -> io::Result<TcpStream> {
    let mut last = io::Error::new(io::ErrorKind::NotFound, "host did not resolve");
    for address in (host, port).to_socket_addrs()? {
        match TcpStream::connect_timeout(&address, CONNECT_TIMEOUT) {
            Ok(stream) => {
                let _ = stream.set_read_timeout(Some(SOCKET_TIMEOUT));
                let _ = stream.set_write_timeout(Some(SOCKET_TIMEOUT));
                return Ok(stream);
            }
            Err(error) => last = error,
        }
    }
    Err(last)
}

fn forward(id: u64, mut client: TcpStream, request: Request, events: EventSink, started: Instant) {
    let target = (request.host.clone(), request.port);
    let mut remote = match connect(&target.0, target.1) {
        Ok(remote) => remote,
        Err(error) => {
            let _ = respond_error(&mut client, "502 Bad Gateway");
            events.push(event_for(
                id,
                "http",
                &request,
                None,
                request.head.len() as u64,
                0,
                started,
                "",
                "",
                format!("could not connect to {}:{}: {error}", target.0, target.1),
            ));
            return;
        }
    };

    let mut outgoing = Vec::with_capacity(request.head.len());
    outgoing
        .extend_from_slice(format!("{} {} HTTP/1.1\r\n", request.method, request.path).as_bytes());
    let mut forwarded_head = false;
    for (name, value) in &request.headers {
        if matches!(
            name.as_str(),
            "proxy-connection" | "connection" | "keep-alive" | "proxy-authorization" | "expect"
        ) {
            continue;
        }
        outgoing.extend_from_slice(format!("{name}: {value}\r\n").as_bytes());
        if name == "host" {
            forwarded_head = true;
        }
    }
    if !forwarded_head {
        outgoing.extend_from_slice(format!("host: {}:{}\r\n", target.0, target.1).as_bytes());
    }
    outgoing.extend_from_slice(b"connection: close\r\n\r\n");

    let mut request_bytes = outgoing.len() as u64;
    let mut request_preview = Vec::new();
    let request_mode = request_body_mode(&request.headers);
    if remote.write_all(&outgoing).is_err() {
        return;
    }
    if relay_body(
        &mut client,
        &mut remote,
        &request_mode,
        Some(&mut request_preview),
        &mut request_bytes,
    )
    .is_err()
    {
        return;
    }

    let Ok(response_head) = read_head(&mut remote) else {
        let _ = respond_error(&mut client, "502 Bad Gateway");
        events.push(event_for(
            id,
            "http",
            &request,
            None,
            request_bytes,
            0,
            started,
            "",
            "",
            "the host closed the connection without a response".to_owned(),
        ));
        return;
    };
    let status = parse_status(&response_head);
    let response_headers = parse_headers(
        String::from_utf8_lossy(&response_head)
            .split('\n')
            .map(|line| line.trim_end_matches('\r'))
            .skip(1),
    );
    let content_type = header(&response_headers, "content-type")
        .unwrap_or_default()
        .to_owned();
    // Compressed bodies are not decoded; showing their bytes as text would be garbage.
    let readable =
        textual(&content_type) && header(&response_headers, "content-encoding").is_none();
    let mut response_bytes = response_head.len() as u64;
    let mut preview = Vec::new();
    if client.write_all(&response_head).is_ok() {
        let mode = response_body_mode(status, &response_headers, is_head(&request.method));
        let _ = relay_body(
            &mut remote,
            &mut client,
            &mode,
            readable.then_some(&mut preview),
            &mut response_bytes,
        );
    }

    let preview = if preview.is_empty() {
        text_preview(&request_preview)
    } else {
        text_preview(&preview)
    };
    events.push(event_for(
        id,
        "http",
        &request,
        status,
        request_bytes,
        response_bytes,
        started,
        &content_type,
        &preview,
        String::new(),
    ));
}

fn tunnel(
    id: u64,
    mut client: TcpStream,
    request: Request,
    events: EventSink,
    stop: Arc<AtomicBool>,
    started: Instant,
) {
    let remote = match connect(&request.host, request.port) {
        Ok(remote) => remote,
        Err(error) => {
            let _ = respond_error(&mut client, "502 Bad Gateway");
            events.push(event_for(
                id,
                "https",
                &request,
                None,
                0,
                0,
                started,
                "",
                "",
                format!(
                    "could not connect to {}:{}: {error}",
                    request.host, request.port
                ),
            ));
            return;
        }
    };
    if client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .is_err()
    {
        return;
    }
    // Long-lived TLS connections may stay open for minutes, so report the destination now and
    // fill in the byte counts when the tunnel closes.
    events.push(event_for(
        id,
        "https",
        &request,
        None,
        0,
        0,
        started,
        "",
        "",
        "TLS tunnel open; bodies are encrypted".to_owned(),
    ));

    let client_reader = match client.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let remote_writer = match remote.try_clone() {
        Ok(stream) => stream,
        Err(_) => return,
    };
    let up = Arc::new(AtomicU64::new(0));
    let down = Arc::new(AtomicU64::new(0));
    let up_count = Arc::clone(&up);
    let down_count = Arc::clone(&down);
    let up_stop = Arc::clone(&stop);
    let down_stop = Arc::clone(&stop);
    let upload = thread::spawn(move || pump(client_reader, remote, up_count, up_stop));
    let download = thread::spawn(move || pump(remote_writer, client, down_count, down_stop));
    let _ = upload.join();
    let _ = download.join();

    events.push(event_for(
        id,
        "https",
        &request,
        None,
        up.load(Ordering::Relaxed),
        down.load(Ordering::Relaxed),
        started,
        "",
        "",
        "TLS tunnel closed; bodies are encrypted and were not decrypted".to_owned(),
    ));
}

fn pump(
    mut source: TcpStream,
    mut sink: TcpStream,
    counter: Arc<AtomicU64>,
    stop: Arc<AtomicBool>,
) {
    let mut buffer = [0u8; 16 * 1024];
    loop {
        if stop.load(Ordering::Relaxed) {
            break;
        }
        match source.read(&mut buffer) {
            Ok(0) => break,
            Ok(read) => {
                if sink.write_all(&buffer[..read]).is_err() {
                    break;
                }
                counter.fetch_add(read as u64, Ordering::Relaxed);
            }
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock
                        | io::ErrorKind::TimedOut
                        | io::ErrorKind::Interrupted
                ) => {}
            Err(_) => break,
        }
    }
    let _ = sink.shutdown(Shutdown::Both);
}

enum BodyMode {
    None,
    Length(u64),
    Chunked,
    UntilClose,
}

// A request without Content-Length or chunked framing has no body; treating it as
// read-until-close would wait for the client to hang up before contacting the server.
fn request_body_mode(headers: &[(String, String)]) -> BodyMode {
    if chunked(headers) {
        BodyMode::Chunked
    } else if let Some(length) = content_length(headers) {
        BodyMode::Length(length)
    } else {
        BodyMode::None
    }
}

fn response_body_mode(
    status: Option<u16>,
    headers: &[(String, String)],
    is_head: bool,
) -> BodyMode {
    if is_head || matches!(status, Some(100..=199 | 204 | 304)) {
        return BodyMode::None;
    }
    if chunked(headers) {
        BodyMode::Chunked
    } else if let Some(length) = content_length(headers) {
        BodyMode::Length(length)
    } else {
        // Euphoria asks for Connection: close, so the host closes the socket when done.
        BodyMode::UntilClose
    }
}

fn chunked(headers: &[(String, String)]) -> bool {
    header(headers, "transfer-encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"))
}

fn content_length(headers: &[(String, String)]) -> Option<u64> {
    header(headers, "content-length").and_then(|value| value.trim().parse().ok())
}

fn is_head(method: &str) -> bool {
    method.eq_ignore_ascii_case("HEAD")
}

fn relay_body(
    source: &mut TcpStream,
    sink: &mut TcpStream,
    mode: &BodyMode,
    preview: Option<&mut Vec<u8>>,
    counter: &mut u64,
) -> io::Result<()> {
    match mode {
        BodyMode::None => Ok(()),
        BodyMode::Length(length) => {
            copy_exact(source, sink, *length, preview, counter);
            Ok(())
        }
        BodyMode::Chunked => relay_chunked(source, sink, preview, counter),
        BodyMode::UntilClose => {
            copy_exact(source, sink, u64::MAX, preview, counter);
            Ok(())
        }
    }
}

fn copy_exact(
    source: &mut TcpStream,
    sink: &mut TcpStream,
    limit: u64,
    mut preview: Option<&mut Vec<u8>>,
    counter: &mut u64,
) {
    let mut remaining = limit;
    let mut buffer = [0u8; 16 * 1024];
    let mut stalls = 0;
    while remaining > 0 {
        let want = buffer.len().min(remaining.min(usize::MAX as u64) as usize);
        match source.read(&mut buffer[..want]) {
            Ok(0) => break,
            Ok(read) => {
                stalls = 0;
                if sink.write_all(&buffer[..read]).is_err() {
                    return;
                }
                *counter += read as u64;
                if let Some(preview) = preview.as_deref_mut() {
                    push_preview(preview, &buffer[..read]);
                }
                remaining -= read as u64;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error)
                if matches!(
                    error.kind(),
                    io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
                ) =>
            {
                stalls += 1;
                if stalls >= 3 {
                    break;
                }
            }
            Err(_) => break,
        }
    }
}

fn relay_chunked(
    source: &mut TcpStream,
    sink: &mut TcpStream,
    mut preview: Option<&mut Vec<u8>>,
    counter: &mut u64,
) -> io::Result<()> {
    loop {
        let line = read_line(source)?;
        sink.write_all(&line)?;
        *counter += line.len() as u64;
        let size_text = String::from_utf8_lossy(&line);
        let size_text = size_text.split(';').next().unwrap_or("").trim();
        let size = u64::from_str_radix(size_text, 16).unwrap_or(0);
        if size == 0 {
            // Trailers, then the final empty line.
            loop {
                let trailer = read_line(source)?;
                sink.write_all(&trailer)?;
                *counter += trailer.len() as u64;
                if trailer == b"\r\n" || trailer == b"\n" {
                    return Ok(());
                }
            }
        }
        copy_exact(
            source,
            sink,
            size.saturating_add(2),
            preview.as_deref_mut(),
            counter,
        );
    }
}

fn read_head(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut head = Vec::with_capacity(2048);
    let mut byte = [0u8; 1];
    while head.len() < HEAD_LIMIT {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                head.push(byte[0]);
                if head.ends_with(b"\r\n\r\n") {
                    return Ok(head);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(head)
}

fn read_line(stream: &mut TcpStream) -> io::Result<Vec<u8>> {
    let mut line = Vec::new();
    let mut byte = [0u8; 1];
    while line.len() < LINE_LIMIT {
        match stream.read(&mut byte) {
            Ok(0) => break,
            Ok(_) => {
                line.push(byte[0]);
                if byte[0] == b'\n' {
                    return Ok(line);
                }
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => return Err(error),
        }
    }
    Ok(line)
}

fn parse_status(head: &[u8]) -> Option<u16> {
    let text = String::from_utf8_lossy(head);
    let line = text.lines().next()?;
    let mut parts = line.split_whitespace();
    parts.next()?;
    parts.next()?.parse().ok()
}

fn respond_error(client: &mut TcpStream, status: &str) -> io::Result<()> {
    let body = b"Euphoria could not reach this host.\n";
    write!(
        client,
        "HTTP/1.1 {status}\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\
         Connection: close\r\n\r\n",
        body.len()
    )?;
    client.write_all(body)
}

fn textual(content_type: &str) -> bool {
    let content_type = content_type.to_ascii_lowercase();
    [
        "text/",
        "json",
        "xml",
        "javascript",
        "x-www-form-urlencoded",
        "graphql",
    ]
    .iter()
    .any(|needle| content_type.contains(needle))
}

fn push_preview(preview: &mut Vec<u8>, bytes: &[u8]) {
    if preview.len() >= PREVIEW_LIMIT {
        return;
    }
    let room = PREVIEW_LIMIT - preview.len();
    preview.extend_from_slice(&bytes[..bytes.len().min(room)]);
}

fn text_preview(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes)
        .chars()
        .filter(|ch| !ch.is_control() || matches!(ch, '\n' | '\r' | '\t'))
        .take(PREVIEW_LIMIT)
        .collect()
}

#[allow(clippy::too_many_arguments)]
fn event_for(
    id: u64,
    scheme: &'static str,
    request: &Request,
    status: Option<u16>,
    request_bytes: u64,
    response_bytes: u64,
    started: Instant,
    content_type: &str,
    preview: &str,
    note: String,
) -> CaptureEvent {
    CaptureEvent {
        id,
        scheme,
        method: request.method.clone(),
        host: request.host.clone(),
        path: request.path.clone(),
        status,
        request_bytes,
        response_bytes,
        millis: started.elapsed().as_millis().min(u64::MAX as u128) as u64,
        content_type: content_type.to_owned(),
        preview: preview.to_owned(),
        note,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_proxy_and_origin_requests() {
        let absolute = Request::parse(
            b"GET http://example.com:8080/a?b=1 HTTP/1.1\r\nHost: example.com\r\n\r\n",
        )
        .unwrap();
        assert_eq!(absolute.method, "GET");
        assert_eq!(absolute.host, "example.com");
        assert_eq!(absolute.port, 8080);
        assert_eq!(absolute.path, "/a?b=1");

        let origin = Request::parse(b"POST /submit HTTP/1.1\r\nHost: example.org\r\n\r\n").unwrap();
        assert_eq!(origin.host, "example.org");
        assert_eq!(origin.port, 80);
        assert_eq!(origin.path, "/submit");

        let tunnel = Request::parse(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n").unwrap();
        assert_eq!(tunnel.port, 443);
    }

    #[test]
    fn splits_hosts_and_ports() {
        assert_eq!(
            split_host_port("example.com", 80),
            Some(("example.com".into(), 80))
        );
        assert_eq!(
            split_host_port("example.com:81", 80),
            Some(("example.com".into(), 81))
        );
        assert_eq!(
            split_host_port("[::1]:8080", 80),
            Some(("::1".into(), 8080))
        );
        assert_eq!(split_host_port("", 80), None);
    }

    #[test]
    fn detects_body_framing() {
        let headers = vec![("content-length".to_owned(), "12".to_owned())];
        assert!(matches!(
            response_body_mode(Some(200), &headers, false),
            BodyMode::Length(12)
        ));
        assert!(matches!(
            response_body_mode(Some(200), &headers, true),
            BodyMode::None
        ));
        assert!(matches!(
            response_body_mode(Some(204), &headers, false),
            BodyMode::None
        ));
        let chunked = vec![("transfer-encoding".to_owned(), "chunked".to_owned())];
        assert!(matches!(
            response_body_mode(Some(200), &chunked, false),
            BodyMode::Chunked
        ));
        assert!(matches!(request_body_mode(&headers), BodyMode::Length(12)));
        assert!(matches!(request_body_mode(&[]), BodyMode::None));
        assert!(matches!(
            response_body_mode(Some(200), &[], false),
            BodyMode::UntilClose
        ));
    }

    #[test]
    fn reads_status_lines() {
        assert_eq!(parse_status(b"HTTP/1.1 204 No Content\r\n\r\n"), Some(204));
        assert_eq!(parse_status(b"garbage"), None);
    }

    #[test]
    fn previews_only_readable_text() {
        assert!(textual("text/html; charset=utf-8"));
        assert!(textual("application/json"));
        assert!(!textual("image/png"));
        assert_eq!(text_preview(b"hello\x01world\n"), "helloworld\n");
    }

    #[test]
    fn forwards_http_and_reports_the_exchange() {
        let (port, server) = one_shot(
            b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\
              Connection: close\r\n\r\nhello",
        );
        let capture = CaptureServer::start().unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", capture.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(
            client,
            "GET http://127.0.0.1:{port}/hi?x=1 HTTP/1.1\r\nHost: 127.0.0.1:{port}\r\n\r\n"
        )
        .unwrap();
        let mut response = Vec::new();
        client.read_to_end(&mut response).unwrap();
        assert!(String::from_utf8_lossy(&response).contains("hello"));

        let event = wait_for_event(&capture, |_| true);
        assert_eq!(event.method, "GET");
        assert_eq!(event.scheme, "http");
        assert_eq!(event.host, "127.0.0.1");
        assert_eq!(event.path, "/hi?x=1");
        assert_eq!(event.status, Some(200));
        assert_eq!(event.preview, "hello");
        assert!(event.request_bytes > 0 && event.response_bytes > 0);
        server.join().unwrap();
    }

    #[test]
    fn records_connect_tunnels_without_their_payload() {
        let (port, server) = echo_once();
        let capture = CaptureServer::start().unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", capture.port())).unwrap();
        client
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        write!(client, "CONNECT 127.0.0.1:{port} HTTP/1.1\r\n\r\n").unwrap();
        read_headers(&mut client);
        client.write_all(b"ping").unwrap();
        let mut echoed = [0u8; 4];
        client.read_exact(&mut echoed).unwrap();
        assert_eq!(&echoed, b"ping");
        let _ = client.shutdown(Shutdown::Both);

        let event = wait_for_event(&capture, |event| event.note.contains("closed"));
        assert_eq!(event.method, "CONNECT");
        assert_eq!(event.scheme, "https");
        assert_eq!(event.status, None);
        assert_eq!(event.request_bytes, 4);
        assert_eq!(event.response_bytes, 4);
        assert!(event.note.contains("encrypted"));
        server.join().unwrap();
    }

    fn wait_for_event(
        server: &CaptureServer,
        matches: impl Fn(&CaptureEvent) -> bool,
    ) -> CaptureEvent {
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            for event in server.drain() {
                if matches(&event) {
                    return event;
                }
            }
            assert!(Instant::now() < deadline, "no capture event arrived");
            thread::sleep(Duration::from_millis(20));
        }
    }

    fn read_headers(stream: &mut TcpStream) -> Vec<u8> {
        let mut head = Vec::new();
        let mut byte = [0u8; 1];
        while !head.ends_with(b"\r\n\r\n") {
            if stream.read(&mut byte).unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
        head
    }

    fn one_shot(response: &[u8]) -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let response = response.to_vec();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _ = read_headers(&mut stream);
            let _ = stream.write_all(&response);
            let _ = stream.shutdown(Shutdown::Both);
        });
        (port, server)
    }

    fn echo_once() -> (u16, thread::JoinHandle<()>) {
        let listener = TcpListener::bind(("127.0.0.1", 0)).unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0u8; 16];
            if let Ok(read) = stream.read(&mut buffer)
                && read > 0
            {
                let _ = stream.write_all(&buffer[..read]);
            }
            let _ = stream.shutdown(Shutdown::Both);
        });
        (port, server)
    }
}
