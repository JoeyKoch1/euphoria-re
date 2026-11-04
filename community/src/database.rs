use anyhow::{Context, Result, bail};
use euphoria_engine::Analysis;
use serde::{Deserialize, Serialize};

use crate::{Config, fetch};

pub const DUMP_SCHEMA: u32 = 1;
const DUMP_FOLDER: &str = "dumps";

// Holds what someone learned about a file and nothing from inside it: no bytes, disassembly,
// pseudocode, or strings. It is only useful to someone who already has the same file.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PublicDump {
    pub schema: u32,
    pub sha256: String,
    pub file_name: String,
    pub arch: String,
    pub tool: String,
    #[serde(default)]
    pub contributor: String,
    #[serde(default)]
    pub notes: String,
    #[serde(default)]
    pub tags: Vec<String>,
    pub functions: Vec<DumpFunction>,
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct DumpFunction {
    pub va: u64,
    pub size: u64,
    pub name: String,
}

pub(crate) fn bucket(sha256: &str) -> String {
    let prefix: String = sha256.chars().take(2).collect();
    format!("{DUMP_FOLDER}/{prefix}")
}

// Sends only the file's hash, and only when called. Ok(None) means nobody has shared this file.
pub fn lookup(config: &Config, sha256: &str) -> Result<Option<PublicDump>> {
    let sha256 = sha256.to_ascii_lowercase();
    if sha256.len() != 64 || !sha256.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        bail!("that is not a SHA-256 hash");
    }
    let path = format!("{}/{sha256}.json", bucket(&sha256));
    let url = config.raw_url(&config.database_repo, &path);
    let Some(text) = fetch(&url)? else {
        return Ok(None);
    };

    let dump: PublicDump = serde_json::from_str(&text).context("that dump is not valid")?;
    if !dump.sha256.eq_ignore_ascii_case(&sha256) {
        bail!("that dump describes a different file");
    }
    if dump.schema > DUMP_SCHEMA {
        bail!("that dump needs a newer version of Euphoria");
    }
    Ok(Some(dump))
}

// Only routines with a real name are worth sharing, since anyone can rediscover the rest.
pub fn export_dump(analysis: &Analysis) -> PublicDump {
    PublicDump {
        schema: DUMP_SCHEMA,
        sha256: analysis.sha256.clone(),
        file_name: analysis.file_name.clone(),
        arch: format!("{:?}", analysis.arch),
        tool: concat!("Euphoria ", env!("CARGO_PKG_VERSION")).to_owned(),
        contributor: String::new(),
        notes: String::new(),
        tags: Vec::new(),
        functions: analysis
            .functions
            .iter()
            .filter_map(|function| {
                Some(DumpFunction {
                    va: function.va,
                    size: function.size,
                    name: function.name.clone()?,
                })
            })
            .collect(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_server;

    const HASH: &str = "ab34567890123456789012345678901234567890123456789012345678901234";

    fn dump(sha256: &str, schema: u32) -> PublicDump {
        PublicDump {
            schema,
            sha256: sha256.to_owned(),
            file_name: "libfoo.so".to_owned(),
            arch: "X86_64".to_owned(),
            tool: "Euphoria".to_owned(),
            contributor: "ada".to_owned(),
            notes: "Built from upstream".to_owned(),
            tags: vec!["open-source".to_owned()],
            functions: vec![DumpFunction {
                va: 0x1000,
                size: 16,
                name: "init".to_owned(),
            }],
        }
    }

    fn serve(value: &PublicDump) -> Config {
        let path = format!("/dumps/ab/{HASH}.json");
        test_server::start(vec![(path, serde_json::to_string(value).unwrap())])
    }

    #[test]
    fn finds_a_shared_dump_by_hash() {
        let config = serve(&dump(HASH, DUMP_SCHEMA));
        let found = lookup(&config, HASH).unwrap().unwrap();
        assert_eq!(found.functions[0].name, "init");
    }

    #[test]
    fn a_file_nobody_shared_is_not_an_error() {
        let config = test_server::start(Vec::new());
        assert_eq!(lookup(&config, HASH).unwrap(), None);
    }

    #[test]
    fn rejects_a_dump_of_some_other_file() {
        let other = "cd34567890123456789012345678901234567890123456789012345678901234";
        let config = serve(&dump(other, DUMP_SCHEMA));
        assert!(lookup(&config, HASH).is_err());
    }

    #[test]
    fn rejects_dumps_from_a_newer_schema() {
        let config = serve(&dump(HASH, DUMP_SCHEMA + 1));
        assert!(lookup(&config, HASH).is_err());
    }

    #[test]
    fn refuses_anything_but_a_hash() {
        let config = test_server::start(Vec::new());
        assert!(lookup(&config, "../../etc/passwd").is_err());
    }
}
