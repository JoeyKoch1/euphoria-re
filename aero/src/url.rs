use std::net::IpAddr;

use crate::Error;

const SCHEMES: &[&str] = &["https://", "http://", "wss://", "ws://", "ftp://"];
const SECOND_LEVEL: &[&str] = &[
    "co.uk", "org.uk", "ac.uk", "gov.uk", "com.au", "net.au", "org.au", "co.nz", "co.jp", "or.jp",
    "ne.jp", "com.br", "com.cn", "net.cn", "org.cn", "co.in", "co.kr", "co.za", "com.mx", "com.tr",
    "com.ru", "com.tw", "com.hk", "com.sg",
];

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Url {
    pub scheme: String,
    pub host: String,
    pub port: Option<u16>,
    pub path: String,
}

impl Url {
    pub fn parse(text: &str) -> Result<Self, Error> {
        let bad = || Error::BadUrl(text.to_owned());
        let (scheme, rest) = text.split_once("://").ok_or_else(bad)?;
        let scheme = scheme.to_ascii_lowercase();

        let split = rest.find(['/', '?', '#']).unwrap_or(rest.len());
        let (authority, path) = rest.split_at(split);
        let authority = authority.rsplit('@').next().ok_or_else(bad)?;

        let (host, port) = if let Some(inner) = authority.strip_prefix('[') {
            let (host, tail) = inner.split_once(']').ok_or_else(bad)?;
            let port = tail
                .strip_prefix(':')
                .map(str::parse)
                .transpose()
                .map_err(|_| bad())?;
            (host, port)
        } else {
            match authority.split_once(':') {
                Some((host, port)) => (host, Some(port.parse().map_err(|_| bad())?)),
                None => (authority, None),
            }
        };

        let valid = !host.is_empty()
            && (host.parse::<IpAddr>().is_ok()
                || host.bytes().all(|byte| {
                    byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_')
                }));
        if !valid {
            return Err(bad());
        }

        let path = path.split('#').next().unwrap_or("");
        let path = if path.is_empty() {
            "/".to_owned()
        } else if path.starts_with('/') {
            path.to_owned()
        } else {
            format!("/{path}")
        };

        Ok(Self {
            scheme,
            host: host.to_ascii_lowercase(),
            port,
            path,
        })
    }

    pub fn default_port(&self) -> Option<u16> {
        match self.scheme.as_str() {
            "http" | "ws" => Some(80),
            "https" | "wss" => Some(443),
            "ftp" => Some(21),
            _ => None,
        }
    }
}

fn looks_like_host(host: &str) -> bool {
    host == "localhost"
        || host.parse::<IpAddr>().is_ok()
        || (host.contains('.')
            && host.rsplit('.').next().is_some_and(|tld| {
                tld.len() >= 2 && tld.bytes().all(|byte| byte.is_ascii_alphabetic())
            }))
}

fn clean(link: &str) -> &str {
    link.trim_end_matches([
        '.', ',', ';', ':', ')', ']', '}', '\'', '"', '>', '!', '?', '\\',
    ])
}

fn is_link_char(character: char) -> bool {
    !character.is_whitespace()
        && !character.is_control()
        && !matches!(
            character,
            '"' | '\'' | '<' | '>' | '`' | '{' | '}' | '|' | '^'
        )
}

pub fn extract_links(text: &str) -> Vec<String> {
    let lower = text.to_ascii_lowercase();
    let mut links = Vec::new();

    let mut at = 0;
    while at < lower.len() {
        let found = SCHEMES
            .iter()
            .filter_map(|scheme| lower[at..].find(scheme).map(|offset| at + offset))
            .min();
        let bare = lower[at..].find("www.").map(|offset| at + offset);

        let (start, prefix) = match (found, bare) {
            (Some(found), Some(bare)) if bare < found => (bare, "https://"),
            (Some(found), _) => (found, ""),
            (None, Some(bare)) => (bare, "https://"),
            (None, None) => break,
        };

        let end = text[start..]
            .find(|character| !is_link_char(character))
            .map_or(text.len(), |offset| start + offset);
        let link = format!("{prefix}{}", clean(&text[start..end]));
        if let Ok(url) = Url::parse(&link)
            && looks_like_host(&url.host)
            && !links.contains(&link)
        {
            links.push(link);
        }
        at = end.max(start + 1);
    }
    links
}

// Rebuilds a URL pointed at the loopback address (or a given emulator), keeping the scheme,
// port, and path so only the host changes.
pub fn to_loopback(url: &Url, emulator: Option<&str>) -> String {
    if let Some(address) = emulator {
        return format!("{address}{}", url.path);
    }
    let mut out = format!("{}://127.0.0.1", url.scheme);
    if let Some(port) = url.port {
        out.push_str(&format!(":{port}"));
    }
    out.push_str(&url.path);
    out
}

pub fn base_domain(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    if host.parse::<IpAddr>().is_ok() {
        return host;
    }

    let labels: Vec<&str> = host.split('.').collect();
    let keep = if labels.len() >= 3
        && SECOND_LEVEL.contains(&labels[labels.len() - 2..].join(".").as_str())
    {
        3
    } else {
        2
    };
    labels[labels.len().saturating_sub(keep)..].join(".")
}

pub fn same_domain(host: &str, domain: &str) -> bool {
    let (host, domain) = (host.to_ascii_lowercase(), domain.to_ascii_lowercase());
    host == domain || host.ends_with(&format!(".{domain}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_urls() {
        let url = Url::parse("HTTPS://user:pw@API.Example.com:8443/v1/x?y=1#top").unwrap();
        assert_eq!(url.scheme, "https");
        assert_eq!(url.host, "api.example.com");
        assert_eq!(url.port, Some(8443));
        assert_eq!(url.path, "/v1/x?y=1");

        assert_eq!(Url::parse("http://example.com").unwrap().path, "/");
        assert_eq!(Url::parse("http://[::1]:80/a").unwrap().host, "::1");
        assert!(Url::parse("not a url").is_err());
        assert!(Url::parse("http://").is_err());
        assert!(Url::parse("http://%s/path").is_err());
        assert!(Url::parse("http://a.com:notaport").is_err());
    }

    #[test]
    fn extracts_links_from_noisy_strings() {
        let text = "get \"https://api.example.com/v1/data?x=1\", or http://10.0.0.5:8080/a. See www.example.org/help)";
        assert_eq!(
            extract_links(text),
            [
                "https://api.example.com/v1/data?x=1",
                "http://10.0.0.5:8080/a",
                "https://www.example.org/help",
            ]
        );
    }

    #[test]
    fn rejects_templates_and_non_hosts_and_duplicates() {
        assert!(extract_links("http://%s/%d").is_empty());
        assert!(extract_links("https://").is_empty());
        assert!(extract_links("http://nothinghere/x").is_empty());
        assert_eq!(extract_links("http://a.com http://a.com").len(), 1);
    }

    #[test]
    fn redirects_a_url_to_loopback() {
        let url = Url::parse("https://api.example.com:8443/v1/x?y=1").unwrap();
        assert_eq!(to_loopback(&url, None), "https://127.0.0.1:8443/v1/x?y=1");
        assert_eq!(
            to_loopback(&url, Some("http://127.0.0.1:54321")),
            "http://127.0.0.1:54321/v1/x?y=1"
        );
        assert_eq!(
            to_loopback(&Url::parse("http://a.com/p").unwrap(), None),
            "http://127.0.0.1/p"
        );
    }

    #[test]
    fn finds_the_base_domain() {
        assert_eq!(base_domain("a.b.example.com"), "example.com");
        assert_eq!(base_domain("example.com"), "example.com");
        assert_eq!(base_domain("shop.example.co.uk"), "example.co.uk");
        assert_eq!(base_domain("10.0.0.5"), "10.0.0.5");
        assert_eq!(base_domain("localhost"), "localhost");
    }

    #[test]
    fn checks_domain_scope() {
        assert!(same_domain("api.example.com", "example.com"));
        assert!(same_domain("EXAMPLE.com", "example.com"));
        assert!(!same_domain("notexample.com", "example.com"));
        assert!(!same_domain("example.com.evil.net", "example.com"));
    }
}
