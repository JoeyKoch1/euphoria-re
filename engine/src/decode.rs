use std::collections::{BTreeMap, BTreeSet};

use base64::Engine;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD};
use serde::Serialize;

use crate::Section;

const MIN_BASE64_RUN: usize = 16;
const MIN_DECODED_LEN: usize = 8;
const MIN_TEXT_RATIO: f32 = 0.95;

const XOR_SCAN_LIMIT: usize = 16 * 1024 * 1024;
const MIN_XOR_RUN: usize = 10;
const MAX_XOR_TEXT: usize = 200;
const MAX_XOR_HITS: usize = 2000;
const MIN_DISTINCT_CHARS: usize = 6;
const MIN_WORD_RATIO: f32 = 0.9;
const MIN_LETTER_RATIO: f32 = 0.6;
const MIN_COMMON_RATIO: f32 = 0.45;
const MIN_BIGRAM_RATIO: f32 = 0.6;
const MIN_ENGLISH_RATIO: f32 = 0.33;
const MIN_UNMARKED_LEN: usize = 16;
const CASE_FLIP_KEY: u8 = 0x20;
const COMMON_LETTERS: &[u8] = b"etaoinshrdlu ";
const COMMON_BIGRAMS: &[&[u8; 2]] = &[
    b"th", b"he", b"in", b"er", b"an", b"re", b"on", b"at", b"en", b"nd", b"ti", b"es", b"or",
    b"te", b"of", b"ed", b"is", b"it", b"al", b"ar", b"st", b"to", b"nt", b"ng", b"se", b"ha",
    b"as", b"ou", b"io", b"le", b"ve", b"co", b"me", b"de", b"hi", b"ri", b"ro", b"ic", b"ne",
    b"ea", b"ra", b"ce",
];
const TEXT_MARKERS: &[&[u8]] = &[
    b"http://",
    b"https://",
    b"www.",
    b".exe",
    b".dll",
    b"powershell",
    b"software\\",
    b"system32",
    b"kernel32",
    b"user32",
    b"password",
    b"mozilla",
    b"windows",
];

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct XorHit {
    pub va: u64,
    pub key: u8,
    pub text: String,
    pub score: f32,
}

fn is_printable(byte: u8) -> bool {
    (0x20..=0x7E).contains(&byte)
}

fn is_text_like(byte: u8) -> bool {
    is_printable(byte) || matches!(byte, b'\t' | b'\r' | b'\n')
}

fn decoded_text(bytes: &[u8]) -> Option<String> {
    if bytes.len() < MIN_DECODED_LEN {
        return None;
    }

    let wide =
        bytes.len().is_multiple_of(2) && bytes.iter().skip(1).step_by(2).all(|&byte| byte == 0);
    if wide {
        let units = bytes
            .as_chunks::<2>()
            .0
            .iter()
            .map(|pair| u16::from_le_bytes([pair[0], pair[1]]));
        let text: String = char::decode_utf16(units).collect::<Result<_, _>>().ok()?;
        let good = text.bytes().filter(|&byte| is_text_like(byte)).count();
        return (good as f32 >= text.len() as f32 * MIN_TEXT_RATIO).then_some(text);
    }

    let good = bytes.iter().filter(|&&byte| is_text_like(byte)).count();
    if (good as f32) < bytes.len() as f32 * MIN_TEXT_RATIO {
        return None;
    }
    String::from_utf8(bytes.to_vec()).ok()
}

fn decode_run(run: &str) -> Option<Vec<u8>> {
    if run.ends_with('=') {
        STANDARD.decode(run).ok()
    } else {
        STANDARD_NO_PAD.decode(run).ok()
    }
}

// Returns text only, so ordinary identifiers that happen to fit the alphabet do not match.
pub fn base64_text(value: &str) -> Option<String> {
    let is_alphabet = |byte: u8| byte.is_ascii_alphanumeric() || byte == b'+' || byte == b'/';
    let bytes = value.as_bytes();

    let mut at = 0;
    while at < bytes.len() {
        let len = bytes[at..]
            .iter()
            .take_while(|&&byte| is_alphabet(byte))
            .count();
        if len >= MIN_BASE64_RUN {
            let padding = bytes[at + len..]
                .iter()
                .take(2)
                .take_while(|&&byte| byte == b'=')
                .count();
            let run = &value[at..at + len + padding];
            if let Some(text) = decode_run(run).and_then(|decoded| decoded_text(&decoded)) {
                return Some(text);
            }
        }
        at += len.max(1);
    }
    None
}

pub fn xor(bytes: &[u8], key: &[u8]) -> Vec<u8> {
    if key.is_empty() {
        return bytes.to_vec();
    }
    bytes
        .iter()
        .zip(key.iter().cycle())
        .map(|(byte, key)| byte ^ key)
        .collect()
}

pub fn parse_hex(text: &str) -> Option<Vec<u8>> {
    let digits: Vec<u8> = text
        .trim()
        .trim_start_matches("0x")
        .bytes()
        .filter(|byte| !byte.is_ascii_whitespace())
        .collect();
    if digits.is_empty() || !digits.len().is_multiple_of(2) {
        return None;
    }
    digits
        .as_chunks::<2>()
        .0
        .iter()
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok())
        .collect()
}

fn score_candidate(raw: &[u8], key: u8) -> Option<(String, f32)> {
    let raw = &raw[..raw.len().min(MAX_XOR_TEXT)];
    if text_score(raw).is_some() {
        return None;
    }

    let text = xor(raw, &[key]);
    let score = text_score(&text)?;
    String::from_utf8(text).ok().map(|text| (text, score))
}

fn text_score(text: &[u8]) -> Option<f32> {
    let count = text.len() as f32;

    let mut seen = [false; 256];
    let mut letters = 0;
    let mut wordy = 0;
    let mut common = 0;
    for &byte in text {
        seen[usize::from(byte)] = true;
        letters += usize::from(byte.is_ascii_alphabetic());
        wordy += usize::from(byte.is_ascii_alphanumeric() || b" ./:_-\\".contains(&byte));
        common += usize::from(COMMON_LETTERS.contains(&byte.to_ascii_lowercase()));
    }

    let distinct = seen.iter().filter(|&&flag| flag).count();
    if distinct < MIN_DISTINCT_CHARS
        || (wordy as f32) < count * MIN_WORD_RATIO
        || (letters as f32) < count * MIN_LETTER_RATIO
        || (common as f32) < count * MIN_COMMON_RATIO
    {
        return None;
    }

    let bigrams: BTreeSet<&[u8]> = text.windows(2).collect();
    if (bigrams.len() as f32) < (count - 1.0) * MIN_BIGRAM_RATIO {
        return None;
    }

    let lower = text.to_ascii_lowercase();
    let english = lower
        .windows(2)
        .filter(|pair| {
            COMMON_BIGRAMS
                .iter()
                .any(|bigram| bigram.as_slice() == *pair)
        })
        .count() as f32
        / (count - 1.0);
    let marked = TEXT_MARKERS
        .iter()
        .any(|marker| lower.windows(marker.len()).any(|window| window == *marker));
    if !marked && (text.len() < MIN_UNMARKED_LEN || english < MIN_ENGLISH_RATIO) {
        return None;
    }

    Some(english + f32::from(u8::from(marked)))
}

// Tries every single-byte key over data sections, up to XOR_SCAN_LIMIT bytes in total.
pub fn scan_xor(data: &[u8], sections: &[Section]) -> Vec<XorHit> {
    let mut regions = Vec::new();
    let mut budget = XOR_SCAN_LIMIT;
    for section in sections.iter().filter(|section| !section.executable) {
        let start = section.offset as usize;
        let end = start.saturating_add(section.size as usize).min(data.len());
        if let Some(bytes) = data.get(start..end) {
            let bytes = &bytes[..bytes.len().min(budget)];
            budget -= bytes.len();
            regions.push((section.va, bytes));
        }
    }

    let mut best: BTreeMap<u64, XorHit> = BTreeMap::new();
    for key in (1..=255u8).filter(|&key| key != CASE_FLIP_KEY) {
        let mut printable = [false; 256];
        for byte in 0..=255u8 {
            printable[usize::from(byte)] = is_printable(byte ^ key);
        }
        printable[0] = false;

        for &(va, bytes) in &regions {
            let mut at = 0;
            while at < bytes.len() {
                let len = bytes[at..]
                    .iter()
                    .take_while(|&&byte| printable[usize::from(byte)])
                    .count();
                if len >= MIN_XOR_RUN
                    && let Some((text, score)) = score_candidate(&bytes[at..at + len], key)
                {
                    let hit = XorHit {
                        va: va + at as u64,
                        key,
                        text,
                        score,
                    };
                    let slot = best.entry(hit.va).or_insert_with(|| hit.clone());
                    if hit.score > slot.score {
                        *slot = hit;
                    }
                }
                at += len.max(1);
            }
        }
    }

    let mut hits: Vec<XorHit> = best.into_values().collect();
    hits.sort_by(|a, b| b.score.total_cmp(&a.score));
    hits.truncate(MAX_XOR_HITS);
    hits
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_base64_text() {
        assert_eq!(
            base64_text("SGVsbG8gZnJvbSBFdXBob3JpYQ=="),
            Some("Hello from Euphoria".into())
        );
    }

    #[test]
    fn finds_base64_inside_a_longer_string() {
        let value = "token=aHR0cDovL2V4YW1wbGUuY29tL3BhdGg=;";
        assert_eq!(base64_text(value), Some("http://example.com/path".into()));
    }

    #[test]
    fn decodes_utf16_base64() {
        let encoded = STANDARD.encode(
            "cmd /c whoami"
                .encode_utf16()
                .flat_map(u16::to_le_bytes)
                .collect::<Vec<u8>>(),
        );
        assert_eq!(base64_text(&encoded), Some("cmd /c whoami".into()));
    }

    #[test]
    fn ignores_identifiers_and_alphabets_that_only_look_like_base64() {
        for value in [
            "GetModuleHandleW",
            "InitializeCriticalSection",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/",
            "short",
        ] {
            assert_eq!(base64_text(value), None, "{value}");
        }
    }

    #[test]
    fn xor_is_reversible_and_repeats_the_key() {
        let encoded = xor(b"attack", &[0x12, 0x34]);
        assert_eq!(encoded[0], b'a' ^ 0x12);
        assert_eq!(encoded[1], b't' ^ 0x34);
        assert_eq!(encoded[2], b't' ^ 0x12);
        assert_eq!(xor(&encoded, &[0x12, 0x34]), b"attack");
    }

    #[test]
    fn parses_hex_keys() {
        assert_eq!(parse_hex("0x5A"), Some(vec![0x5A]));
        assert_eq!(parse_hex("de ad BE EF"), Some(vec![0xDE, 0xAD, 0xBE, 0xEF]));
        assert_eq!(parse_hex("abc"), None);
        assert_eq!(parse_hex("zz"), None);
        assert_eq!(parse_hex(""), None);
    }

    fn data_section(len: usize) -> Section {
        Section {
            va: 0x2000,
            offset: 0,
            size: len as u64,
            executable: false,
        }
    }

    #[test]
    fn scan_recovers_a_single_byte_xor_string() {
        let secret = xor(b"http://example.com/payload", &[0x5A]);
        let mut data = vec![0u8; 64];
        data[16..16 + secret.len()].copy_from_slice(&secret);

        let hits = scan_xor(&data, &[data_section(data.len())]);
        let hit = hits
            .iter()
            .find(|hit| hit.key == 0x5A)
            .expect("no hit for the real key");
        assert_eq!(hit.va, 0x2010);
        assert_eq!(hit.text, "http://example.com/payload");
    }

    #[test]
    fn scan_skips_plain_text_and_zero_runs() {
        let mut data = vec![0u8; 128];
        data[8..40].copy_from_slice(b"this text is not encoded at all!");

        assert!(scan_xor(&data, &[data_section(data.len())]).is_empty());
    }

    #[test]
    fn scan_skips_repeating_table_data() {
        let pattern = b"Dnts".repeat(16);
        let data = xor(&pattern, &[0x8C]);

        assert!(scan_xor(&data, &[data_section(data.len())]).is_empty());
    }

    #[test]
    fn scan_ignores_code_sections() {
        let data = xor(b"http://example.com/payload", &[0x5A]);
        let code = Section {
            executable: true,
            ..data_section(data.len())
        };
        assert!(scan_xor(&data, &[code]).is_empty());
    }
}
