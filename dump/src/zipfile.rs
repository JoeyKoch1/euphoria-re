use std::collections::HashSet;
use std::io::{self, Write};
use std::time::{SystemTime, UNIX_EPOCH};

use flate2::Compression;
use flate2::write::DeflateEncoder;

const LOCAL_SIGNATURE: u32 = 0x0403_4B50;
const CENTRAL_SIGNATURE: u32 = 0x0201_4B50;
const END_SIGNATURE: u32 = 0x0605_4B50;
const END64_SIGNATURE: u32 = 0x0606_4B50;
const LOCATOR64_SIGNATURE: u32 = 0x0706_4B50;
const FLAG_UTF8: u16 = 0x0800;
const METHOD_STORED: u16 = 0;
const METHOD_DEFLATE: u16 = 8;
const VERSION: u16 = 45;
const ZIP64_EXTRA_ID: u16 = 1;
const MAX_U16: u64 = 0xFFFF;
const MAX_U32: u64 = 0xFFFF_FFFF;
const MIN_COMPRESS_BYTES: usize = 128;
const MAX_NAME_PART: usize = 120;
const RESERVED_NAMES: [&str; 22] = [
    "CON", "PRN", "AUX", "NUL", "COM1", "COM2", "COM3", "COM4", "COM5", "COM6", "COM7", "COM8",
    "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7", "LPT8", "LPT9",
];

pub(crate) struct Compressed {
    pub(crate) name: String,
    pub(crate) crc: u32,
    pub(crate) size: u64,
    pub(crate) method: u16,
    pub(crate) data: Vec<u8>,
}

// Runs on worker threads, so the slow part happens in parallel and the writer only copies bytes.
pub(crate) fn compress(name: String, bytes: Vec<u8>) -> io::Result<Compressed> {
    let mut hasher = crc32fast::Hasher::new();
    hasher.update(&bytes);
    let crc = hasher.finalize();
    let size = bytes.len() as u64;

    if bytes.len() >= MIN_COMPRESS_BYTES {
        let output = Vec::with_capacity(bytes.len() / 3);
        let mut encoder = DeflateEncoder::new(output, Compression::fast());
        encoder.write_all(&bytes)?;
        let packed = encoder.finish()?;
        if packed.len() < bytes.len() {
            return Ok(Compressed {
                name,
                crc,
                size,
                method: METHOD_DEFLATE,
                data: packed,
            });
        }
    }

    Ok(Compressed {
        name,
        crc,
        size,
        method: METHOD_STORED,
        data: bytes,
    })
}

struct CentralEntry {
    name: String,
    crc: u32,
    size: u32,
    packed: u32,
    method: u16,
    offset: u64,
}

pub(crate) struct ZipFile<W: Write> {
    out: W,
    offset: u64,
    entries: Vec<CentralEntry>,
    used: HashSet<String>,
    time: u16,
    date: u16,
}

impl<W: Write> ZipFile<W> {
    pub(crate) fn new(out: W) -> Self {
        let (time, date) = dos_now();
        Self {
            out,
            offset: 0,
            entries: Vec::new(),
            used: HashSet::new(),
            time,
            date,
        }
    }

    pub(crate) fn add(&mut self, file: Compressed) -> io::Result<u64> {
        let too_large = file.size >= MAX_U32 || file.data.len() as u64 >= MAX_U32;
        if too_large {
            return Err(io::Error::other(format!(
                "{} is too large for one dump entry",
                file.name
            )));
        }

        let name = self.unique_name(&file.name);
        let mut header = Vec::with_capacity(30 + name.len());
        put32(&mut header, LOCAL_SIGNATURE);
        put16(&mut header, VERSION);
        put16(&mut header, FLAG_UTF8);
        put16(&mut header, file.method);
        put16(&mut header, self.time);
        put16(&mut header, self.date);
        put32(&mut header, file.crc);
        put32(&mut header, file.data.len() as u32);
        put32(&mut header, file.size as u32);
        put16(&mut header, name.len() as u16);
        put16(&mut header, 0);
        header.extend_from_slice(name.as_bytes());

        self.out.write_all(&header)?;
        self.out.write_all(&file.data)?;

        let written = (header.len() + file.data.len()) as u64;
        self.entries.push(CentralEntry {
            name,
            crc: file.crc,
            size: file.size as u32,
            packed: file.data.len() as u32,
            method: file.method,
            offset: self.offset,
        });
        self.offset += written;
        Ok(written)
    }

    fn unique_name(&mut self, name: &str) -> String {
        let clean = safe_path(name);
        let mut candidate = clean.clone();
        let mut attempt = 1;
        while !self.used.insert(candidate.to_lowercase()) {
            attempt += 1;
            candidate = match clean.rsplit_once('.') {
                Some((stem, extension)) if !extension.contains('/') => {
                    format!("{stem}~{attempt}.{extension}")
                }
                _ => format!("{clean}~{attempt}"),
            };
        }
        candidate
    }

    pub(crate) fn finish(mut self) -> io::Result<u64> {
        let central_offset = self.offset;
        let mut central = Vec::new();
        for entry in &self.entries {
            write_central(&mut central, entry, self.time, self.date);
        }
        self.out.write_all(&central)?;

        let central_size = central.len() as u64;
        let count = self.entries.len() as u64;
        let end64_offset = central_offset + central_size;
        let needs_zip64 = count >= MAX_U16 || central_offset >= MAX_U32 || central_size >= MAX_U32;

        let mut end = Vec::new();
        if needs_zip64 {
            put32(&mut end, END64_SIGNATURE);
            put64(&mut end, 44);
            put16(&mut end, VERSION);
            put16(&mut end, VERSION);
            put32(&mut end, 0);
            put32(&mut end, 0);
            put64(&mut end, count);
            put64(&mut end, count);
            put64(&mut end, central_size);
            put64(&mut end, central_offset);

            put32(&mut end, LOCATOR64_SIGNATURE);
            put32(&mut end, 0);
            put64(&mut end, end64_offset);
            put32(&mut end, 1);
        }

        put32(&mut end, END_SIGNATURE);
        put16(&mut end, 0);
        put16(&mut end, 0);
        put16(&mut end, count.min(MAX_U16) as u16);
        put16(&mut end, count.min(MAX_U16) as u16);
        put32(&mut end, central_size.min(MAX_U32) as u32);
        put32(&mut end, central_offset.min(MAX_U32) as u32);
        put16(&mut end, 0);
        self.out.write_all(&end)?;
        self.out.flush()?;

        Ok(end64_offset + end.len() as u64)
    }
}

fn write_central(out: &mut Vec<u8>, entry: &CentralEntry, time: u16, date: u16) {
    let zip64 = entry.offset >= MAX_U32;
    put32(out, CENTRAL_SIGNATURE);
    put16(out, VERSION);
    put16(out, VERSION);
    put16(out, FLAG_UTF8);
    put16(out, entry.method);
    put16(out, time);
    put16(out, date);
    put32(out, entry.crc);
    put32(out, entry.packed);
    put32(out, entry.size);
    put16(out, entry.name.len() as u16);
    put16(out, if zip64 { 12 } else { 0 });
    put16(out, 0);
    put16(out, 0);
    put16(out, 0);
    put32(out, 0);
    put32(out, entry.offset.min(MAX_U32) as u32);
    out.extend_from_slice(entry.name.as_bytes());
    if zip64 {
        put16(out, ZIP64_EXTRA_ID);
        put16(out, 8);
        put64(out, entry.offset);
    }
}

// Names can come from the analyzed file, so this keeps them safe to extract on any system.
pub(crate) fn safe_path(name: &str) -> String {
    let parts: Vec<String> = name
        .split(['/', '\\'])
        .filter(|part| !part.is_empty() && *part != ".")
        .map(safe_part)
        .collect();
    if parts.is_empty() {
        "unnamed".to_owned()
    } else {
        parts.join("/")
    }
}

fn safe_part(part: &str) -> String {
    let mut clean: String = part
        .chars()
        .map(|character| {
            if character.is_control() || "<>:\"|?*".contains(character) {
                '_'
            } else {
                character
            }
        })
        .take(MAX_NAME_PART)
        .collect();

    let trimmed = clean.trim_end_matches(['.', ' ']).len();
    clean.truncate(trimmed);
    if clean.is_empty() {
        return "_".to_owned();
    }

    let stem = clean.split('.').next().unwrap_or("").to_ascii_uppercase();
    if RESERVED_NAMES.contains(&stem.as_str()) {
        clean.insert(0, '_');
    }
    clean
}

fn dos_now() -> (u16, u16) {
    let seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |time| time.as_secs());
    dos_time(seconds)
}

fn dos_time(seconds: u64) -> (u16, u16) {
    let days = (seconds / 86_400) as i64;
    let rest = seconds % 86_400;
    let (year, month, day) = civil_from_days(days);

    let time = ((rest / 3600) << 11) | (((rest % 3600) / 60) << 5) | ((rest % 60) / 2);
    let date = (((year - 1980).max(0) as u64) << 9) | ((month as u64) << 5) | day as u64;
    (time as u16, date as u16)
}

fn civil_from_days(days: i64) -> (i64, i64, i64) {
    let shifted = days + 719_468;
    let era = shifted.div_euclid(146_097);
    let day_of_era = shifted.rem_euclid(146_097);
    let year_of_era =
        (day_of_era - day_of_era / 1460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let shifted_month = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * shifted_month + 2) / 5 + 1;
    let month = if shifted_month < 10 {
        shifted_month + 3
    } else {
        shifted_month - 9
    };
    let year = year_of_era + era * 400 + i64::from(month <= 2);
    (year, month, day)
}

fn put16(out: &mut Vec<u8>, value: u16) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put32(out: &mut Vec<u8>, value: u32) {
    out.extend_from_slice(&value.to_le_bytes());
}

fn put64(out: &mut Vec<u8>, value: u64) {
    out.extend_from_slice(&value.to_le_bytes());
}

#[cfg(test)]
mod tests {
    use std::io::{Cursor, Read};

    use super::*;

    fn read_back(bytes: Vec<u8>) -> zip::ZipArchive<Cursor<Vec<u8>>> {
        zip::ZipArchive::new(Cursor::new(bytes)).unwrap()
    }

    fn add(zip: &mut ZipFile<&mut Vec<u8>>, name: &str, bytes: &[u8]) {
        zip.add(compress(name.to_owned(), bytes.to_vec()).unwrap())
            .unwrap();
    }

    #[test]
    fn writes_a_zip_other_tools_can_read() {
        let large = b"mov rax, rbx\n".repeat(5000);
        let mut out = Vec::new();
        let mut zip = ZipFile::new(&mut out);
        add(&mut zip, "small.txt", b"hello");
        add(&mut zip, "folder/large.txt", &large);
        add(&mut zip, "empty.txt", b"");
        let total = zip.finish().unwrap();
        assert_eq!(total, out.len() as u64);
        assert!(out.len() < large.len() / 5);

        let mut archive = read_back(out);
        assert_eq!(archive.len(), 3);

        let mut text = String::new();
        archive
            .by_name("small.txt")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "hello");

        let mut bytes = Vec::new();
        archive
            .by_name("folder/large.txt")
            .unwrap()
            .read_to_end(&mut bytes)
            .unwrap();
        assert_eq!(bytes, large);
    }

    #[test]
    fn stores_data_that_will_not_compress() {
        let random: Vec<u8> = (0..4096u32)
            .map(|i| (i.wrapping_mul(2_654_435_761) >> 24) as u8)
            .collect();
        let packed = compress("r".to_owned(), random.clone()).unwrap();
        assert_eq!(packed.method, METHOD_STORED);
        assert_eq!(packed.data, random);
    }

    #[test]
    fn handles_more_entries_than_a_plain_zip_allows() {
        let count = 70_000usize;
        let mut out = Vec::new();
        let mut zip = ZipFile::new(&mut out);
        for index in 0..count {
            add(&mut zip, &format!("f{index}"), b"x");
        }
        zip.finish().unwrap();

        let mut archive = read_back(out);
        assert_eq!(archive.len(), count);
        let mut text = String::new();
        archive
            .by_name("f69999")
            .unwrap()
            .read_to_string(&mut text)
            .unwrap();
        assert_eq!(text, "x");
    }

    #[test]
    fn keeps_names_that_differ_only_by_case_apart() {
        let mut out = Vec::new();
        let mut zip = ZipFile::new(&mut out);
        add(&mut zip, "smali/a.smali", b"1");
        add(&mut zip, "smali/A.smali", b"2");
        add(&mut zip, "smali/a.smali", b"3");
        zip.finish().unwrap();

        let archive = read_back(out);
        let mut names: Vec<&str> = archive.file_names().collect();
        names.sort_unstable();
        assert_eq!(
            names,
            ["smali/a.smali", "smali/a~2.smali", "smali/a~3.smali"]
        );
    }

    #[test]
    fn neutralizes_dangerous_names() {
        assert_eq!(safe_path("../../etc/passwd"), "_/_/etc/passwd");
        assert_eq!(safe_path("..\\..\\windows\\x.exe"), "_/_/windows/x.exe");
        assert_eq!(safe_path("/abs/path"), "abs/path");
        assert_eq!(safe_path("C:\\temp\\a"), "C_/temp/a");
        assert_eq!(safe_path("a/CON.txt"), "a/_CON.txt");
        assert_eq!(safe_path("a/nul"), "a/_nul");
        assert_eq!(safe_path("trail. "), "trail");
        assert_eq!(safe_path(""), "unnamed");
        assert_eq!(safe_path("a\u{1}b?"), "a_b_");
        assert_eq!(safe_path(&"x".repeat(500)).len(), MAX_NAME_PART);
    }

    #[test]
    fn converts_dates() {
        assert_eq!(civil_from_days(0), (1970, 1, 1));
        assert_eq!(civil_from_days(20_000), (2024, 10, 4));
        let (time, date) = dos_time(1_700_000_000);
        assert_eq!(date >> 9, 2023 - 1980);
        assert_eq!((date >> 5) & 0xF, 11);
        assert_eq!(date & 0x1F, 14);
        assert_eq!(time >> 11, 22);
    }
}
