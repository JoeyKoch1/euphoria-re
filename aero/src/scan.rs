use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, ToSocketAddrs};
use std::sync::mpsc::Sender;
use std::sync::{Arc, Mutex};
use std::thread;

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::Error;
use crate::http::{Request, send};

const WORKERS: usize = 16;
const MAX_NAMES: usize = 2000;
const CERT_LOG_URL: &str = "https://crt.sh/?output=json&q=%25.";
const WILDCARD_PROBE: &str = "aero-wildcard-check-7f3a";
const COMMON_NAMES: &[&str] = &[
    "www", "api", "app", "admin", "auth", "beta", "blog", "cdn", "dev", "docs", "ftp", "git",
    "login", "m", "mail", "portal", "shop", "smtp", "staging", "static", "status", "test",
    "update", "vpn",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Source {
    CertificateLog,
    CommonName,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Found {
    pub name: String,
    pub source: Source,
    pub addresses: Vec<IpAddr>,
}

#[derive(Clone, Debug)]
pub enum ScanEvent {
    Found(Found),
    Warning(String),
    Done,
}

// Finds subdomains that are publicly logged or commonly named, which is not a complete list.
pub fn scan(domain: &str, events: &Sender<ScanEvent>) -> Result<(), Error> {
    if domain.parse::<IpAddr>().is_ok() {
        return Err(Error::NotADomain(domain.to_owned()));
    }

    let mut names: BTreeMap<String, Source> = BTreeMap::new();
    names.insert(domain.to_owned(), Source::CommonName);

    match certificate_names(domain) {
        Ok(logged) => {
            for name in logged.into_iter().take(MAX_NAMES) {
                names.insert(name, Source::CertificateLog);
            }
        }
        Err(error) => {
            let _ = events.send(ScanEvent::Warning(format!(
                "The certificate log lookup failed: {error}"
            )));
        }
    }

    if resolve(&format!("{WILDCARD_PROBE}.{domain}")).is_empty() {
        for common in COMMON_NAMES {
            names
                .entry(format!("{common}.{domain}"))
                .or_insert(Source::CommonName);
        }
    } else {
        let _ = events.send(ScanEvent::Warning(
            "This domain answers for any name, so name guessing was skipped".to_owned(),
        ));
    }

    resolve_all(names, events);
    let _ = events.send(ScanEvent::Done);
    Ok(())
}

fn resolve_all(names: BTreeMap<String, Source>, events: &Sender<ScanEvent>) {
    let queue = Arc::new(Mutex::new(names.into_iter().collect::<Vec<_>>()));
    let workers: Vec<_> = (0..WORKERS)
        .map(|_| {
            let queue = Arc::clone(&queue);
            let events = events.clone();
            thread::spawn(move || {
                loop {
                    let next = queue.lock().ok().and_then(|mut queue| queue.pop());
                    let Some((name, source)) = next else {
                        return;
                    };
                    let addresses = resolve(&name);
                    if !addresses.is_empty() || source == Source::CertificateLog {
                        let found = Found {
                            name,
                            source,
                            addresses,
                        };
                        let _ = events.send(ScanEvent::Found(found));
                    }
                }
            })
        })
        .collect();

    for worker in workers {
        let _ = worker.join();
    }
}

fn resolve(name: &str) -> Vec<IpAddr> {
    let addresses: BTreeSet<IpAddr> = (name, 443)
        .to_socket_addrs()
        .map(|found| found.map(|address| address.ip()).collect())
        .unwrap_or_default();
    addresses.into_iter().collect()
}

fn certificate_names(domain: &str) -> Result<BTreeSet<String>, Error> {
    let request = Request {
        method: "GET".to_owned(),
        url: format!("{CERT_LOG_URL}{domain}"),
        ..Request::default()
    };
    let capture = send(&request)?;
    let json = capture.json.ok_or(Error::BadResponse)?;
    Ok(parse_certificate_log(&json, domain))
}

pub(crate) fn parse_certificate_log(json: &Value, domain: &str) -> BTreeSet<String> {
    let suffix = format!(".{domain}");
    json.as_array()
        .into_iter()
        .flatten()
        .filter_map(|entry| entry.get("name_value").and_then(Value::as_str))
        .flat_map(str::lines)
        .map(|name| name.trim().trim_start_matches("*.").to_ascii_lowercase())
        .filter(|name| name == domain || name.ends_with(&suffix))
        .filter(|name| !name.contains(' ') && !name.contains('@'))
        .collect()
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;

    use super::*;

    #[test]
    fn reads_names_from_a_certificate_log() {
        let json = serde_json::json!([
            { "name_value": "api.example.com\n*.dev.example.com" },
            { "name_value": "example.com" },
            { "name_value": "other.net" },
            { "name_value": "notexample.com" },
            { "name_value": "admin@example.com" },
            { "other": 1 },
        ]);

        let names: Vec<String> = parse_certificate_log(&json, "example.com")
            .into_iter()
            .collect();
        assert_eq!(names, ["api.example.com", "dev.example.com", "example.com"]);
    }

    #[test]
    fn handles_unexpected_log_shapes() {
        assert!(parse_certificate_log(&serde_json::json!({ "a": 1 }), "x.com").is_empty());
    }

    #[test]
    fn refuses_to_scan_an_ip_address() {
        let (sender, _receiver) = mpsc::channel();
        assert!(matches!(
            scan("10.0.0.1", &sender),
            Err(Error::NotADomain(_))
        ));
    }

    #[test]
    fn resolves_localhost_without_touching_the_network() {
        assert!(!resolve("localhost").is_empty());
    }
}
