use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use euphoria_engine::dataset::sha256_hex;
use euphoria_plugins::parse_meta;
use serde::{Deserialize, Serialize};

use crate::{Config, fetch};

const INDEX_FILE: &str = "index.json";
const PLUGIN_FOLDER: &str = "plugins";
const MAX_LISTED: usize = 5000;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct MarketPlugin {
    pub id: String,
    pub name: String,
    pub version: String,
    pub author: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub permissions: Vec<String>,
    pub sha256: String,
}

#[derive(Serialize, Deserialize)]
struct Index {
    plugins: Vec<MarketPlugin>,
}

// The id becomes a file name on the user's disk, so it gets a very short list of allowed characters.
fn is_safe_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || b"_-".contains(&byte))
}

fn is_hash(text: &str) -> bool {
    text.len() == 64 && text.bytes().all(|byte| byte.is_ascii_hexdigit())
}

pub fn fetch_index(config: &Config) -> Result<Vec<MarketPlugin>> {
    let url = config.raw_url(&config.plugin_repo, INDEX_FILE);
    let Some(text) = fetch(&url)? else {
        return Ok(Vec::new());
    };
    let index: Index = serde_json::from_str(&text).context("the plugin list is not valid")?;
    Ok(index
        .plugins
        .into_iter()
        .filter(|plugin| is_safe_id(&plugin.id) && is_hash(&plugin.sha256))
        .take(MAX_LISTED)
        .collect())
}

// Writes the plugin only after its contents match the hash in the list.
pub fn install(config: &Config, plugin: &MarketPlugin, dir: &Path) -> Result<PathBuf> {
    if !is_safe_id(&plugin.id) {
        bail!("this plugin has an unsafe name");
    }
    let path = format!("{PLUGIN_FOLDER}/{}.lua", plugin.id);
    let url = config.raw_url(&config.plugin_repo, &path);
    let Some(source) = fetch(&url)? else {
        bail!("{} is listed but its file is missing", plugin.name);
    };
    if !sha256_hex(source.as_bytes()).eq_ignore_ascii_case(&plugin.sha256) {
        bail!(
            "{} does not match its listed hash, so it was not installed",
            plugin.name
        );
    }

    fs::create_dir_all(dir)?;
    let target = dir.join(format!("{}.lua", plugin.id));
    fs::write(&target, source).with_context(|| format!("cannot write {}", target.display()))?;
    Ok(target)
}

// Rebuilds index.json in a checkout of the plugin repo from the headers of its plugins.
pub fn build_index(repo: &Path) -> Result<usize> {
    let folder = repo.join(PLUGIN_FOLDER);
    let mut plugins = Vec::new();
    for item in
        fs::read_dir(&folder).with_context(|| format!("cannot read {}", folder.display()))?
    {
        let path = item?.path();
        if path.extension().is_none_or(|extension| extension != "lua") {
            continue;
        }
        let id = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        if !is_safe_id(&id) {
            bail!("{id} needs a lowercase file name made of letters, digits, _ and -");
        }
        let bytes = fs::read(&path)?;
        let source = String::from_utf8(bytes)
            .with_context(|| format!("{} is not UTF-8 text", path.display()))?;
        let meta = parse_meta(&source, &format!("{id}.lua"));
        plugins.push(MarketPlugin {
            id,
            name: meta.name,
            version: meta.version,
            author: meta.author,
            description: meta.description,
            permissions: meta.permissions,
            sha256: sha256_hex(source.as_bytes()),
        });
    }
    plugins.sort_by(|a, b| a.id.cmp(&b.id));

    let count = plugins.len();
    let mut text = serde_json::to_string_pretty(&Index { plugins })?;
    text.push('\n');
    fs::write(repo.join(INDEX_FILE), text)?;
    Ok(count)
}

#[cfg(test)]
mod tests {
    use std::env;
    use std::process;

    use super::*;
    use crate::test_server;

    const SOURCE: &str = "-- @name Sample\n-- @version 1.2\n-- @author Ada\nprint('hi')\n";

    fn scratch(name: &str) -> PathBuf {
        let dir = env::temp_dir().join(format!("euphoria_market_{name}_{}", process::id()));
        let _ = fs::remove_dir_all(&dir);
        dir
    }

    fn listing(id: &str, hash: &str) -> MarketPlugin {
        MarketPlugin {
            id: id.to_owned(),
            name: "Sample".to_owned(),
            version: "1.2".to_owned(),
            author: "Ada".to_owned(),
            description: String::new(),
            permissions: Vec::new(),
            sha256: hash.to_owned(),
        }
    }

    #[test]
    fn lists_and_installs_a_plugin_that_matches_its_hash() {
        let hash = sha256_hex(SOURCE.as_bytes());
        let index = serde_json::to_string(&Index {
            plugins: vec![listing("sample", &hash)],
        })
        .unwrap();
        let config = test_server::start(vec![
            ("/index.json".to_owned(), index),
            ("/plugins/sample.lua".to_owned(), SOURCE.to_owned()),
        ]);

        let plugins = fetch_index(&config).unwrap();
        assert_eq!(plugins.len(), 1);

        let dir = scratch("install");
        let path = install(&config, &plugins[0], &dir).unwrap();
        assert_eq!(fs::read_to_string(path).unwrap(), SOURCE);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn refuses_a_file_that_differs_from_its_hash() {
        let config = test_server::start(vec![(
            "/plugins/sample.lua".to_owned(),
            "os.execute('bad')".to_owned(),
        )]);
        let dir = scratch("tampered");
        let wrong = sha256_hex(SOURCE.as_bytes());

        let error = install(&config, &listing("sample", &wrong), &dir).unwrap_err();
        assert!(error.to_string().contains("does not match"));
        assert!(!dir.join("sample.lua").exists());
    }

    #[test]
    fn drops_listings_that_could_escape_the_plugin_folder() {
        let good = "a".repeat(64);
        let index = serde_json::to_string(&Index {
            plugins: vec![
                listing("../../evil", &good),
                listing("BAD NAME", &good),
                listing("no_hash", "short"),
                listing("fine", &good),
            ],
        })
        .unwrap();
        let config = test_server::start(vec![("/index.json".to_owned(), index)]);

        let plugins = fetch_index(&config).unwrap();
        assert_eq!(plugins.len(), 1);
        assert_eq!(plugins[0].id, "fine");
    }

    #[test]
    fn an_empty_repo_is_an_empty_marketplace() {
        let config = test_server::start(Vec::new());
        assert!(fetch_index(&config).unwrap().is_empty());
    }

    #[test]
    fn builds_an_index_from_plugin_headers() {
        let repo = scratch("index");
        fs::create_dir_all(repo.join("plugins")).unwrap();
        fs::write(repo.join("plugins/sample.lua"), SOURCE).unwrap();
        fs::write(repo.join("plugins/notes.txt"), "ignored").unwrap();

        assert_eq!(build_index(&repo).unwrap(), 1);

        let index: Index =
            serde_json::from_slice(&fs::read(repo.join("index.json")).unwrap()).unwrap();
        assert_eq!(index.plugins[0].name, "Sample");
        assert_eq!(index.plugins[0].version, "1.2");
        assert_eq!(index.plugins[0].sha256, sha256_hex(SOURCE.as_bytes()));
        let _ = fs::remove_dir_all(repo);
    }
}
