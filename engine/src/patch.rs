use anyhow::{Result, anyhow, ensure};
use serde::Serialize;
use std::io::Write;
use std::path::Path;

pub(crate) fn save_copy(source: &Path, destination: &Path, bytes: &[u8]) -> Result<()> {
    let check = || -> Result<()> {
        if destination.try_exists()? {
            ensure!(
                !same_file::is_same_file(source, destination)?,
                "choose a different file; the original cannot be overwritten"
            );
        }
        Ok(())
    };
    check()?;
    let parent = destination
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(bytes)?;
    temporary.as_file().sync_all()?;
    check()?;
    temporary.persist(destination)?;
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Patch {
    pub va: u64,
    pub offset: usize,
    pub before: Vec<u8>,
    pub after: Vec<u8>,
}

// Overwrites `original_len` bytes at `offset` with `replacement`, null-padded to the same length,
// so a shorter string (such as a redirected URL) stays inside the space the original used.
pub fn plan(
    data: &[u8],
    va: u64,
    offset: usize,
    original_len: usize,
    replacement: &[u8],
) -> Result<Patch> {
    let end = offset
        .checked_add(original_len)
        .filter(|&end| end <= data.len())
        .ok_or_else(|| anyhow!("that text runs past the end of the file"))?;
    ensure!(
        replacement.len() <= original_len,
        "the redirected address is {} bytes, longer than the {original_len} it would replace, so it will not fit",
        replacement.len()
    );
    ensure!(
        !replacement.contains(&0),
        "the redirected address cannot contain a null byte"
    );

    let mut after = replacement.to_vec();
    after.resize(original_len, 0);
    Ok(Patch {
        va,
        offset,
        before: data[offset..end].to_vec(),
        after,
    })
}

pub fn apply(data: &mut [u8], patches: &[Patch]) -> Result<()> {
    for patch in patches {
        let end = patch.offset + patch.before.len();
        ensure!(
            end <= data.len() && data[patch.offset..end] == patch.before[..],
            "the file no longer matches what this edit expected, so nothing was changed"
        );
    }
    for patch in patches {
        let end = patch.offset + patch.after.len();
        data[patch.offset..end].copy_from_slice(&patch.after);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn saves_copies_without_changing_the_source_or_its_aliases() {
        let dir = tempfile::tempdir().unwrap();
        let source = dir.path().join("original.bin");
        let alias = dir.path().join("alias.bin");
        let copy = dir.path().join("copy.bin");
        std::fs::write(&source, b"original").unwrap();
        std::fs::hard_link(&source, &alias).unwrap();
        assert!(save_copy(&source, &source, b"changed").is_err());
        assert!(save_copy(&source, &alias, b"changed").is_err());
        std::fs::write(&copy, b"old copy").unwrap();
        save_copy(&source, &copy, b"changed").unwrap();
        assert_eq!(std::fs::read(&source).unwrap(), b"original");
        assert_eq!(std::fs::read(&copy).unwrap(), b"changed");
    }

    #[test]
    fn plans_a_shorter_replacement_and_null_pads_the_rest() {
        let data = b"http://api.example.com/x".to_vec();
        let patch = plan(&data, 0x1000, 0, data.len(), b"http://127.0.0.1/x").unwrap();

        assert_eq!(patch.after.len(), data.len());
        assert!(patch.after.starts_with(b"http://127.0.0.1/x\0"));
        assert!(patch.after[18..].iter().all(|&byte| byte == 0));
        assert_eq!(patch.before, data);
    }

    #[test]
    fn refuses_a_replacement_that_is_too_long() {
        let error = plan(b"http://a.co/x", 0, 0, 13, b"http://127.0.0.1/x").unwrap_err();
        assert!(error.to_string().contains("will not fit"));
    }

    #[test]
    fn refuses_patches_past_the_end_of_the_file() {
        assert!(plan(b"short", 0, 2, 10, b"x").is_err());
    }

    #[test]
    fn applies_only_when_the_original_bytes_still_match() {
        let patch = plan(b"host.example/x", 0x2000, 0, 14, b"127.0.0.1/x").unwrap();

        let mut good = b"host.example/x".to_vec();
        apply(&mut good, std::slice::from_ref(&patch)).unwrap();
        assert_eq!(&good[..11], b"127.0.0.1/x");
        assert_eq!(&good[11..], b"\0\0\0");

        let mut changed = b"other.example/x".to_vec();
        assert!(apply(&mut changed, &[patch]).is_err());
        assert_eq!(changed, b"other.example/x");
    }
}
