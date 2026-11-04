mod emulator;
mod http;
mod scan;
mod url;

pub use emulator::{Emulator, Hit, Route};
pub use http::{Capture, Request, Response, send};
pub use scan::{Found, ScanEvent, Source, scan};
pub use url::{Url, base_domain, extract_links, same_domain, to_loopback};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a usable URL: {0}")]
    BadUrl(String),
    #[error("only http and https are supported, not {0}")]
    UnsupportedScheme(String),
    #[error("could not connect to {0}: {1}")]
    Connect(String, std::io::Error),
    #[error("network error: {0}")]
    Io(#[from] std::io::Error),
    #[error("TLS error: {0}")]
    Tls(#[from] rustls::Error),
    #[error("the server sent a response Aero could not read")]
    BadResponse,
    #[error("{0} is an IP address, so it has no subdomains to scan")]
    NotADomain(String),
}
