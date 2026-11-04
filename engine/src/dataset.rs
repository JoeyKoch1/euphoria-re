use std::fs::{self, File};
use std::io::{BufWriter, Read, Write};
use std::path::Path;

use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};

pub const EXTENSION: &str = "euph";

const MAGIC: &[u8; 4] = b"EUPH";
const VERSION: u32 = 1;
const LEVEL: i32 = 19;
const WINDOW_LOG: u32 = 27;
const HEADER_LEN: usize = 8;
const MAX_META_BYTES: u64 = 256 * 1024 * 1024;
const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    pub file_name: String,
    pub sha256: String,
    #[serde(default)]
    pub extras: Value,
}

pub fn sha256_hex(data: &[u8]) -> String {
    Sha256::digest(data)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

pub fn is_dataset(data: &[u8]) -> bool {
    data.starts_with(MAGIC)
}

pub fn write(path: &Path, meta: &Meta, bytes: &[u8]) -> Result<u64> {
    let temporary = path.with_extension("euph.tmp");
    let result = write_file(&temporary, meta, bytes);
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
        return result;
    }

    fs::rename(&temporary, path).with_context(|| format!("cannot write {}", path.display()))?;
    result
}

fn write_file(path: &Path, meta: &Meta, bytes: &[u8]) -> Result<u64> {
    let file = File::create(path).with_context(|| format!("cannot write {}", path.display()))?;
    let mut output = BufWriter::new(file);
    output.write_all(MAGIC)?;
    output.write_all(&VERSION.to_le_bytes())?;

    let meta = serde_json::to_vec(meta)?;
    let mut encoder = zstd::stream::Encoder::new(output, LEVEL)?;
    encoder.long_distance_matching(true)?;
    encoder.window_log(WINDOW_LOG)?;
    encoder.write_all(&(meta.len() as u64).to_le_bytes())?;
    encoder.write_all(&meta)?;
    encoder.write_all(bytes)?;
    encoder.finish()?.flush()?;

    Ok(fs::metadata(path)?.len())
}

pub fn read(data: &[u8]) -> Result<(Meta, Vec<u8>)> {
    ensure!(
        data.len() >= HEADER_LEN && is_dataset(data),
        "not a .euph dataset"
    );
    let version = u32::from_le_bytes([data[4], data[5], data[6], data[7]]);
    if version != VERSION {
        bail!("this .euph file uses format {version}, and this build reads format {VERSION}");
    }

    let mut decoder = zstd::stream::Decoder::new(&data[HEADER_LEN..])?;
    decoder.window_log_max(WINDOW_LOG)?;
    let mut decoder = decoder.take(MAX_META_BYTES + MAX_FILE_BYTES);

    let mut length = [0u8; 8];
    decoder
        .read_exact(&mut length)
        .context("damaged .euph file")?;
    let length = u64::from_le_bytes(length);
    ensure!(length <= MAX_META_BYTES, "damaged .euph file");

    let mut meta = vec![0u8; length as usize];
    decoder
        .read_exact(&mut meta)
        .context("damaged .euph file")?;
    let meta: Meta = serde_json::from_slice(&meta).context("damaged .euph file")?;

    let mut bytes = Vec::new();
    decoder
        .read_to_end(&mut bytes)
        .context("damaged .euph file")?;
    ensure!(
        sha256_hex(&bytes) == meta.sha256,
        "this .euph file failed its integrity check"
    );
    Ok((meta, bytes))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn meta(bytes: &[u8]) -> Meta {
        Meta {
            file_name: "sample.exe".to_owned(),
            sha256: sha256_hex(bytes),
            extras: serde_json::json!({ "note": "kept" }),
        }
    }

    fn scratch(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("euphoria-{}-{name}.euph", std::process::id()))
    }

    #[test]
    fn hashes_match_a_known_value() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }

    #[test]
    fn round_trips_and_compresses() {
        let bytes: Vec<u8> = b"mov rax, rbx; ".repeat(50_000);
        let path = scratch("round-trip");

        let written = write(&path, &meta(&bytes), &bytes).unwrap();
        assert!((written as usize) < bytes.len() / 100);

        let stored = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        let (loaded, restored) = read(&stored).unwrap();
        assert_eq!(restored, bytes);
        assert_eq!(loaded, meta(&bytes));
    }

    #[test]
    fn rejects_corrupted_files() {
        let bytes = b"some program bytes".repeat(100);
        let path = scratch("corrupt");
        write(&path, &meta(&bytes), &bytes).unwrap();
        let mut stored = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();

        let middle = stored.len() / 2;
        stored[middle] ^= 0xFF;
        assert!(read(&stored).is_err());
        assert!(read(&stored[..12]).is_err());
        assert!(read(b"EUP").is_err());
    }

    #[test]
    fn rejects_a_wrong_hash_and_a_newer_version() {
        let bytes = b"payload".to_vec();
        let mut wrong = meta(&bytes);
        wrong.sha256 = sha256_hex(b"other");
        let path = scratch("wrong-hash");
        write(&path, &wrong, &bytes).unwrap();
        let mut stored = fs::read(&path).unwrap();
        fs::remove_file(&path).unwrap();
        assert!(read(&stored).is_err());

        stored[4] = 99;
        assert!(read(&stored).unwrap_err().to_string().contains("format 99"));
    }
}
