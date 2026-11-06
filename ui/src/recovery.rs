use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::Project;

#[derive(Default, Serialize, Deserialize)]
struct Saved {
    #[serde(default)]
    sha256: String,
    #[serde(default)]
    names: BTreeMap<u64, String>,
    #[serde(default)]
    comments: BTreeMap<u64, String>,
}

fn directory() -> Option<PathBuf> {
    let base = if cfg!(windows) {
        std::env::var_os("LOCALAPPDATA").map(PathBuf::from)?
    } else {
        std::env::var_os("XDG_CACHE_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".cache")))?
    };
    Some(
        base.join(if cfg!(windows) {
            "Euphoria"
        } else {
            "euphoria"
        })
        .join("recovery"),
    )
}

fn file_for(sha256: &str) -> Option<PathBuf> {
    Some(directory()?.join(format!("{sha256}.json")))
}

// Autosaves after every edit so a crash does not lose names or comments that were never
// written into a .euph file. Saves nothing, and clears any older copy, when there is nothing.
pub fn save(project: &Project) {
    let Some(path) = file_for(&project.analysis.sha256) else {
        return;
    };
    if project.names.is_empty() && project.comments.is_empty() {
        let _ = std::fs::remove_file(path);
        return;
    }
    let saved = Saved {
        sha256: project.analysis.sha256.clone(),
        names: project.names.clone(),
        comments: project.comments.clone(),
    };
    let _ = write(&path, &saved);
}

// Saved annotations from a .euph file win, so recovery only fills in addresses that are still
// empty. The file is removed once read; later edits write a fresh copy.
pub fn restore(project: &mut Project) -> Option<String> {
    let path = file_for(&project.analysis.sha256)?;
    let bytes = std::fs::read(&path).ok()?;
    let saved: Saved = serde_json::from_slice(&bytes).ok()?;
    if !saved.sha256.is_empty() && saved.sha256 != project.analysis.sha256 {
        return None;
    }
    let restored = merge(saved, &mut project.names, &mut project.comments);
    let _ = std::fs::remove_file(path);
    (restored > 0).then(|| format!("Recovered {restored} unsaved edit(s) from the last session"))
}

pub fn discard(sha256: &str) {
    if let Some(path) = file_for(sha256) {
        let _ = std::fs::remove_file(path);
    }
}

fn merge(
    saved: Saved,
    names: &mut BTreeMap<u64, String>,
    comments: &mut BTreeMap<u64, String>,
) -> usize {
    let mut restored = 0;
    for (va, name) in saved.names {
        if let std::collections::btree_map::Entry::Vacant(slot) = names.entry(va) {
            slot.insert(name);
            restored += 1;
        }
    }
    for (va, text) in saved.comments {
        if let std::collections::btree_map::Entry::Vacant(slot) = comments.entry(va) {
            slot.insert(text);
            restored += 1;
        }
    }
    restored
}

fn write(path: &Path, saved: &Saved) -> std::io::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let bytes = serde_json::to_vec(saved).map_err(std::io::Error::other)?;
    std::fs::write(path, bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fills_only_addresses_the_saved_file_left_empty() {
        let mut names = BTreeMap::from([(0x10, "kept".to_owned())]);
        let mut comments = BTreeMap::new();
        let saved = Saved {
            sha256: String::new(),
            names: BTreeMap::from([(0x10, "stale".to_owned()), (0x20, "recovered".to_owned())]),
            comments: BTreeMap::from([(0x30, "note".to_owned())]),
        };

        assert_eq!(merge(saved, &mut names, &mut comments), 2);
        assert_eq!(names.get(&0x10).map(String::as_str), Some("kept"));
        assert_eq!(names.get(&0x20).map(String::as_str), Some("recovered"));
        assert_eq!(comments.get(&0x30).map(String::as_str), Some("note"));
    }

    #[test]
    fn writes_and_reads_a_recovery_file() {
        let dir = std::env::temp_dir().join(format!("euphoria_recovery_{}", std::process::id()));
        let path = dir.join("saved.json");
        let saved = Saved {
            sha256: "abc".into(),
            names: BTreeMap::from([(0x1000, "start".to_owned())]),
            comments: BTreeMap::new(),
        };
        write(&path, &saved).unwrap();

        let bytes = std::fs::read(&path).unwrap();
        let restored: Saved = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(restored.sha256, "abc");
        assert_eq!(
            restored.names.get(&0x1000).map(String::as_str),
            Some("start")
        );

        std::fs::remove_dir_all(dir).unwrap();
    }
}
