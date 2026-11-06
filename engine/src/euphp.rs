//! The `.euphp` patch file.
//!
//! A patch file records byte edits next to the module and offset they belong to, together with the
//! bytes that were there before, so an edit can be reversed or checked against a different copy of
//! the same build. The payload is UTF-8 JSON after a short magic header.

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};

pub const EXTENSION: &str = "euphp";
pub const VERSION: u32 = 1;

const MAGIC: &[u8] = b"EUPHP\x01";
const MAX_PATCHES: usize = 4096;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchFile {
    pub version: u32,
    pub target: PatchTarget,
    #[serde(default)]
    pub created_with: String,
    #[serde(default)]
    pub created_at: String,
    pub patches: Vec<PatchEntry>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchTarget {
    pub name: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub pid: u32,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PatchEntry {
    pub module: String,
    pub offset: u64,
    pub original: Vec<u8>,
    pub patched: Vec<u8>,
    #[serde(default)]
    pub note: String,
}

impl PatchFile {
    pub fn new(target: PatchTarget) -> Self {
        Self {
            version: VERSION,
            target,
            created_with: format!("Euphoria {}", env!("CARGO_PKG_VERSION")),
            created_at: String::new(),
            patches: Vec::new(),
        }
    }

    pub fn encode(&self) -> Result<Vec<u8>> {
        self.validate()?;
        let mut bytes = MAGIC.to_vec();
        serde_json::to_writer_pretty(&mut bytes, self).context("could not write the patch file")?;
        Ok(bytes)
    }

    pub fn decode(bytes: &[u8]) -> Result<Self> {
        let Some(payload) = bytes.strip_prefix(MAGIC) else {
            bail!("this is not a Euphoria patch file");
        };
        let file: Self =
            serde_json::from_slice(payload).context("the patch file is damaged or incomplete")?;
        file.validate()?;
        Ok(file)
    }

    fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION,
            "this patch file uses format version {}, but this build reads version {VERSION}",
            self.version
        );
        ensure!(!self.target.name.is_empty(), "the patch file has no target");
        ensure!(
            self.patches.len() <= MAX_PATCHES,
            "a patch file holds at most {MAX_PATCHES} edits"
        );
        for (index, patch) in self.patches.iter().enumerate() {
            let number = index + 1;
            ensure!(!patch.module.is_empty(), "edit {number} has no module");
            ensure!(
                !patch.original.is_empty(),
                "edit {number} replaces zero bytes"
            );
            ensure!(
                patch.original.len() == patch.patched.len(),
                "edit {number} changes {} bytes into {}",
                patch.original.len(),
                patch.patched.len()
            );
            ensure!(
                patch
                    .offset
                    .checked_add(patch.original.len() as u64)
                    .is_some(),
                "edit {number} runs past the end of the address space"
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> PatchFile {
        let mut file = PatchFile::new(PatchTarget {
            name: "game.exe".into(),
            path: r"C:\Games\game.exe".into(),
            pid: 4242,
        });
        file.created_at = "1760000000".into();
        file.patches.push(PatchEntry {
            module: "game.exe".into(),
            offset: 0x120,
            original: vec![0x75, 0x10],
            patched: vec![0xEB, 0x10],
            note: "Always take the local branch".into(),
        });
        file
    }

    #[test]
    fn round_trips_bytes_and_metadata() {
        let file = sample();
        let bytes = file.encode().unwrap();
        assert!(bytes.starts_with(MAGIC));
        assert_eq!(PatchFile::decode(&bytes).unwrap(), file);
    }

    #[test]
    fn rejects_files_without_the_magic_header() {
        let error = PatchFile::decode(br#"{"version":1}"#).unwrap_err();
        assert!(format!("{error:#}").contains("not a Euphoria patch file"));
    }

    #[test]
    fn rejects_edits_that_change_their_length() {
        let mut file = sample();
        file.patches[0].patched.push(0x90);
        let error = file.encode().unwrap_err();
        assert!(format!("{error:#}").contains("changes 2 bytes into 3"));
    }

    #[test]
    fn rejects_a_newer_format_version() {
        let mut file = sample();
        file.version = VERSION + 1;
        let error = file.encode().unwrap_err();
        assert!(format!("{error:#}").contains("format version"));
    }

    #[test]
    fn rejects_damaged_payloads() {
        let mut bytes = sample().encode().unwrap();
        bytes.truncate(MAGIC.len() + 3);
        assert!(PatchFile::decode(&bytes).is_err());
    }
}
