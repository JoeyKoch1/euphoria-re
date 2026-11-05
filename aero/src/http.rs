use std::io::{self, ErrorKind, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Error;
use crate::url::Url;

const USER_AGENT: &str = "Aero/0.1";
const TIMEOUT: Duration = Duration::from_secs(15);
const MAX_RESPONSE_BYTES: u64 = 16 * 1024 * 1024;

#[derive(Clone, Debug, Default)]
pub struct Request {
    pub method: String,
    pub url: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Response {
    pub status: u16,
    pub reason: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl Response {
    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(key, _)| key.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Capture {
    pub method: String,
    pub url: String,
    pub status: u16,
    pub headers: Vec<(String, String)>,
    pub body: String,
    pub json: Option<Value>,
    pub elapsed_ms: u64,
    pub captured_at: u64,
}

impl Capture {
    pub fn new(request: &Request, response: &Response, elapsed: Duration) -> Self {
        let json = serde_json::from_slice(&response.body).ok();
        Self {
            method: request.method.clone(),
            url: request.url.clone(),
            status: response.status,
            headers: response.headers.clone(),
            body: String::from_utf8_lossy(&response.body).into_owned(),
            json,
            elapsed_ms: elapsed.as_millis() as u64,
            captured_at: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |time| time.as_secs()),
        }
    }

    pub fn is_json(&self) -> bool {
        self.json.is_some()
    }
}

pub fn send(request: &Request) -> Result<Capture, Error> {
    let started = Instant::now();
    let url = Url::parse(&request.url)?;
    if !matches!(url.scheme.as_str(), "http" | "https") {
        return Err(Error::UnsupportedScheme(url.scheme));
    }

    let port = url.port.or(url.default_port()).unwrap_or(80);
    let stream = connect(&url.host, port)?;
    let head = build_request(request, &url, port);
    let head_only = request.method.eq_ignore_ascii_case("HEAD");

    let raw = if url.scheme == "https" {
        let mut tls = tls_stream(stream, &url.host)?;
        tls.write_all(&head)?;
        tls.flush()?;
        read_all(&mut tls, head_only)?
    } else {
        let mut stream = stream;
        stream.write_all(&head)?;
        stream.flush()?;
        read_all(&mut stream, head_only)?
    };

    let response = parse_response_for(&raw, head_only)?;
    Ok(Capture::new(request, &response, started.elapsed()))
}

fn connect(host: &str, port: u16) -> Result<TcpStream, Error> {
    let target = format!("{host}:{port}");
    let failed = |error| Error::Connect(target.clone(), error);
    let addresses = if host.contains(':') {
        (host, port).to_socket_addrs()
    } else {
        target.to_socket_addrs()
    }
    .map_err(failed)?;

    let mut last = io::Error::new(ErrorKind::NotFound, "no addresses found");
    for address in addresses {
        match TcpStream::connect_timeout(&address, TIMEOUT) {
            Ok(stream) => {
                stream.set_read_timeout(Some(TIMEOUT))?;
                stream.set_write_timeout(Some(TIMEOUT))?;
                return Ok(stream);
            }
            Err(error) => last = error,
        }
    }
    Err(failed(last))
}

fn tls_stream(
    stream: TcpStream,
    host: &str,
) -> Result<StreamOwned<ClientConnection, TcpStream>, Error> {
    let mut roots = RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    let name = ServerName::try_from(host.to_owned()).map_err(|_| Error::BadUrl(host.to_owned()))?;
    let connection = ClientConnection::new(Arc::new(config), name)?;
    Ok(StreamOwned::new(connection, stream))
}

fn build_request(request: &Request, url: &Url, port: u16) -> Vec<u8> {
    let method = if request.method.is_empty() {
        "GET"
    } else {
        &request.method
    };
    let host = if url.host.contains(':') {
        format!("[{}]", url.host)
    } else {
        url.host.clone()
    };
    let authority = if Some(port) == url.default_port() {
        host
    } else {
        format!("{host}:{port}")
    };

    let mut head = format!("{method} {} HTTP/1.1\r\nHost: {authority}\r\n", url.path);
    let has = |name: &str| {
        request
            .headers
            .iter()
            .any(|(key, _)| key.eq_ignore_ascii_case(name))
    };
    if !has("User-Agent") {
        head.push_str(&format!("User-Agent: {USER_AGENT}\r\n"));
    }
    if !has("Accept") {
        head.push_str("Accept: */*\r\n");
    }
    for (key, value) in &request.headers {
        let safe = |text: &str| !text.contains(['\r', '\n']);
        if safe(key) && safe(value) && !key.eq_ignore_ascii_case("Connection") {
            head.push_str(&format!("{key}: {value}\r\n"));
        }
    }
    if !request.body.is_empty() || matches!(method, "POST" | "PUT" | "PATCH") {
        head.push_str(&format!("Content-Length: {}\r\n", request.body.len()));
    }
    head.push_str("Connection: close\r\n\r\n");

    let mut bytes = head.into_bytes();
    bytes.extend_from_slice(&request.body);
    bytes
}

fn read_all(stream: &mut impl Read, head_only: bool) -> Result<Vec<u8>, Error> {
    read_limited(stream, MAX_RESPONSE_BYTES, head_only)
}

fn read_limited(stream: &mut impl Read, limit: u64, head_only: bool) -> Result<Vec<u8>, Error> {
    let mut raw = Vec::new();
    match stream.take(limit + 1).read_to_end(&mut raw) {
        Ok(_) => {}
        Err(error) if error.kind() == ErrorKind::UnexpectedEof && !raw.is_empty() => {
            let response = parse_response_for(&raw, head_only)?;
            if !head_only
                && !matches!(response.status, 100..=199 | 204 | 304)
                && response.header("Content-Length").is_none()
                && response.header("Transfer-Encoding").is_none()
            {
                return Err(Error::IncompleteResponse);
            }
        }
        Err(error) => return Err(error.into()),
    }
    if raw.len() as u64 > limit {
        return Err(Error::ResponseTooLarge);
    }
    Ok(raw)
}

#[cfg(test)]
fn parse_response(raw: &[u8]) -> Result<Response, Error> {
    parse_response_for(raw, false)
}

fn parse_response_for(raw: &[u8], head_only: bool) -> Result<Response, Error> {
    let split = raw
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .ok_or(Error::BadResponse)?;
    let head = std::str::from_utf8(&raw[..split]).map_err(|_| Error::BadResponse)?;
    let body = &raw[split + 4..];

    let mut lines = head.split("\r\n");
    let mut status_line = lines.next().ok_or(Error::BadResponse)?.splitn(3, ' ');
    if !status_line.next().unwrap_or("").starts_with("HTTP/") {
        return Err(Error::BadResponse);
    }
    let status = status_line
        .next()
        .and_then(|code| code.parse().ok())
        .ok_or(Error::BadResponse)?;
    let reason = status_line.next().unwrap_or("").to_owned();

    let headers: Vec<(String, String)> = lines
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim().to_owned(), value.trim().to_owned()))
        .collect();

    let mut response = Response {
        status,
        reason,
        headers,
        body: Vec::new(),
    };
    if head_only || matches!(status, 100..=199 | 204 | 304) {
        return Ok(response);
    }

    let chunked = response
        .header("Transfer-Encoding")
        .is_some_and(|value| value.to_ascii_lowercase().contains("chunked"));
    let length = response
        .header("Content-Length")
        .map(|value| value.parse::<usize>().map_err(|_| Error::BadResponse))
        .transpose()?;

    response.body = if chunked {
        decode_chunked(body)?
    } else if let Some(length) = length {
        body.get(..length)
            .ok_or(Error::IncompleteResponse)?
            .to_vec()
    } else {
        body.to_vec()
    };
    Ok(response)
}

fn decode_chunked(mut body: &[u8]) -> Result<Vec<u8>, Error> {
    let mut decoded = Vec::new();
    loop {
        let line_end = body
            .windows(2)
            .position(|window| window == b"\r\n")
            .ok_or(Error::BadResponse)?;
        let size = std::str::from_utf8(&body[..line_end]).map_err(|_| Error::BadResponse)?;
        let size = size.split(';').next().unwrap_or("").trim();
        let size = usize::from_str_radix(size, 16).map_err(|_| Error::BadResponse)?;
        if size == 0 {
            let trailers = &body[line_end + 2..];
            if !trailers.starts_with(b"\r\n")
                && !trailers.windows(4).any(|part| part == b"\r\n\r\n")
            {
                return Err(Error::IncompleteResponse);
            }
            return Ok(decoded);
        }

        let start = line_end + 2;
        let end = start
            .checked_add(size)
            .filter(|&end| end <= body.len())
            .ok_or(Error::BadResponse)?;
        decoded.extend_from_slice(&body[start..end]);
        if body.get(end..end + 2) != Some(b"\r\n") {
            return Err(Error::IncompleteResponse);
        }
        body = body.get(end + 2..).ok_or(Error::BadResponse)?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_incomplete_and_oversized_responses() {
        assert!(matches!(
            parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nabc"),
            Err(Error::IncompleteResponse)
        ));
        assert!(parse_response(b"HTTP/1.1 200 OK\r\nContent-Length: bad\r\n\r\nabc").is_err());
        assert!(matches!(
            read_limited(&mut &b"abcd"[..], 3, false),
            Err(Error::ResponseTooLarge)
        ));
        assert_eq!(read_limited(&mut &b"abc"[..], 3, false).unwrap(), b"abc");
        assert!(
            parse_response_for(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n", true)
                .unwrap()
                .body
                .is_empty()
        );
        assert!(
            parse_response(b"HTTP/1.1 304 Not Modified\r\nContent-Length: 5\r\n\r\n")
                .unwrap()
                .body
                .is_empty()
        );
        assert!(decode_chunked(b"1\r\na\r\n0\r\n").is_err());
    }

    #[test]
    fn parses_a_plain_response() {
        let response = parse_response(
            b"HTTP/1.1 201 Created\r\nContent-Type: text/plain\r\nContent-Length: 5\r\n\r\nhello!!",
        )
        .unwrap();
        assert_eq!(response.status, 201);
        assert_eq!(response.reason, "Created");
        assert_eq!(response.header("content-type"), Some("text/plain"));
        assert_eq!(response.body, b"hello");
    }

    #[test]
    fn decodes_chunked_bodies() {
        let response = parse_response(
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n4\r\nWiki\r\n5;x=1\r\npedia\r\n0\r\n\r\n",
        )
        .unwrap();
        assert_eq!(response.body, b"Wikipedia");
    }

    #[test]
    fn rejects_malformed_responses() {
        for raw in [
            &b""[..],
            b"garbage",
            b"NOPE 200 OK\r\n\r\n",
            b"HTTP/1.1 abc\r\n\r\n",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nFFFFFFFF\r\nx",
            b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\nzz\r\n",
        ] {
            assert!(parse_response(raw).is_err());
        }
    }

    #[test]
    fn builds_a_request_and_drops_header_injection() {
        let request = Request {
            method: "POST".to_owned(),
            url: "http://a.com:8080/x".to_owned(),
            headers: vec![
                ("X-Test".to_owned(), "1".to_owned()),
                ("X-Bad".to_owned(), "a\r\nInjected: yes".to_owned()),
            ],
            body: b"{}".to_vec(),
        };
        let url = Url::parse(&request.url).unwrap();
        let text = String::from_utf8(build_request(&request, &url, 8080)).unwrap();

        assert!(text.starts_with("POST /x HTTP/1.1\r\nHost: a.com:8080\r\n"));
        assert!(text.contains("X-Test: 1\r\n"));
        assert!(!text.contains("Injected"));
        assert!(text.contains("Content-Length: 2\r\n"));
        assert!(text.ends_with("\r\n\r\n{}"));
    }

    #[test]
    fn rejects_unsupported_schemes_before_connecting() {
        let request = Request {
            url: "ftp://example.com/x".to_owned(),
            ..Request::default()
        };
        assert!(matches!(send(&request), Err(Error::UnsupportedScheme(_))));
    }
}
