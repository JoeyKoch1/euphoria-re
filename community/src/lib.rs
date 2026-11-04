mod database;
mod marketplace;

use std::fs;
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub use database::{DUMP_SCHEMA, DumpFunction, PublicDump, export_dump, lookup};
pub use marketplace::{MarketPlugin, build_index, fetch_index, install};

const CONFIG_FILE: &str = "config.json";

// Everything here can be changed in config.json, so a fork or a mirror needs no rebuild.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Config {
    pub plugin_repo: String,
    pub database_repo: String,
    pub branch: String,
    pub raw_base: String,
    pub web_base: String,
    // Off until the user turns it on, because a lookup tells the server which file is open.
    pub automatic_lookups: bool,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            plugin_repo: "JoeyKoch1/euphoria-plugins".to_owned(),
            database_repo: "JoeyKoch1/euphoria-db".to_owned(),
            branch: "main".to_owned(),
            raw_base: "https://raw.githubusercontent.com".to_owned(),
            web_base: "https://github.com".to_owned(),
            automatic_lookups: false,
        }
    }
}

fn config_path() -> PathBuf {
    let plugins = euphoria_plugins::default_dir();
    plugins
        .parent()
        .map_or_else(|| PathBuf::from(CONFIG_FILE), |dir| dir.join(CONFIG_FILE))
}

impl Config {
    // A missing or broken file gives the defaults, since none of this is worth refusing to start.
    pub fn load() -> Self {
        fs::read(config_path())
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        let path = config_path();
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_vec_pretty(self)?;
        fs::write(&path, text).with_context(|| format!("cannot write {}", path.display()))
    }

    pub(crate) fn raw_url(&self, repo: &str, path: &str) -> String {
        format!(
            "{}/{repo}/{}/{path}",
            self.raw_base.trim_end_matches('/'),
            self.branch
        )
    }

    pub fn plugin_upload_url(&self) -> String {
        format!(
            "{}/{}/upload/{}/plugins",
            self.web_base.trim_end_matches('/'),
            self.plugin_repo,
            self.branch
        )
    }

    pub fn dump_upload_url(&self, sha256: &str) -> String {
        format!(
            "{}/{}/upload/{}/{}",
            self.web_base.trim_end_matches('/'),
            self.database_repo,
            self.branch,
            database::bucket(sha256)
        )
    }
}

// Ok(None) means the file simply is not there.
pub(crate) fn fetch(url: &str) -> Result<Option<String>> {
    let request = aero::Request {
        method: "GET".to_owned(),
        url: url.to_owned(),
        headers: vec![("User-Agent".to_owned(), "Euphoria".to_owned())],
        body: Vec::new(),
    };
    let capture = aero::send(&request).with_context(|| format!("could not reach {url}"))?;
    match capture.status {
        200 => Ok(Some(capture.body)),
        404 => Ok(None),
        status => bail!("{url} answered with status {status}"),
    }
}

#[cfg(test)]
pub(crate) mod test_server {
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::thread;

    use crate::Config;

    // Serves a fixed set of paths on a local port for as long as the test runs.
    pub fn start(files: Vec<(String, String)>) -> Config {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        thread::spawn(move || {
            for stream in listener.incoming().flatten() {
                let mut stream = stream;
                let mut buffer = [0u8; 4096];
                let read = stream.read(&mut buffer).unwrap_or(0);
                let head = String::from_utf8_lossy(&buffer[..read]).into_owned();
                let path = head.split_whitespace().nth(1).unwrap_or("").to_owned();
                let found = files.iter().find(|(name, _)| path.ends_with(name.as_str()));
                let (status, body) = match found {
                    Some((_, body)) => ("200 OK", body.as_str()),
                    None => ("404 Not Found", ""),
                };
                let reply = format!(
                    "HTTP/1.1 {status}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(reply.as_bytes());
            }
        });
        Config {
            raw_base: format!("http://127.0.0.1:{port}"),
            ..Config::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn config_files_may_leave_out_any_field() {
        let config: Config = serde_json::from_str(r#"{"branch": "dev"}"#).unwrap();
        assert_eq!(config.branch, "dev");
        assert_eq!(config.plugin_repo, Config::default().plugin_repo);
        assert!(!config.automatic_lookups);
    }

    #[test]
    fn builds_upload_addresses_from_the_config() {
        let config = Config::default();
        assert_eq!(
            config.plugin_upload_url(),
            "https://github.com/JoeyKoch1/euphoria-plugins/upload/main/plugins"
        );
        assert_eq!(
            config.dump_upload_url("abcdef"),
            "https://github.com/JoeyKoch1/euphoria-db/upload/main/dumps/ab"
        );
    }
}
