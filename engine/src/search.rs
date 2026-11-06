use crate::Section;

const MAX_PATTERN_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Part {
    Byte(u8),
    Any,
}

impl Part {
    fn matches(self, byte: u8) -> bool {
        match self {
            Self::Byte(expected) => expected == byte,
            Self::Any => true,
        }
    }
}

// A byte pattern where `??` or `?` stands for any byte, like `48 8B ?? 89` or `488B??89`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Pattern {
    parts: Vec<Part>,
    anchor: Option<(usize, u8)>,
}

impl Pattern {
    pub fn parse(input: &str) -> Result<Self, String> {
        let text = input.trim();
        if text.is_empty() {
            return Err("Enter a pattern such as 48 8B ?? 89".to_owned());
        }
        let parts = if text.chars().any(char::is_whitespace) {
            parse_tokens(text)?
        } else {
            parse_compact(text)?
        };
        if parts.is_empty() {
            return Err("Enter at least one byte".to_owned());
        }
        if parts.len() > MAX_PATTERN_BYTES {
            return Err(format!("Patterns are limited to {MAX_PATTERN_BYTES} bytes"));
        }
        let anchor = parts
            .iter()
            .enumerate()
            .find_map(|(index, part)| match part {
                Part::Byte(byte) => Some((index, *byte)),
                Part::Any => None,
            })
            .ok_or("Include at least one known byte, since ?? matches everything")?;
        Ok(Self {
            parts,
            anchor: Some(anchor),
        })
    }

    pub fn len(&self) -> usize {
        self.parts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.parts.is_empty()
    }

    pub fn text(&self) -> String {
        self.parts
            .iter()
            .map(|part| match part {
                Part::Byte(byte) => format!("{byte:02X}"),
                Part::Any => "??".to_owned(),
            })
            .collect::<Vec<_>>()
            .join(" ")
    }

    fn matches(&self, window: &[u8]) -> bool {
        self.parts
            .iter()
            .zip(window)
            .all(|(part, &byte)| part.matches(byte))
    }
}

fn parse_tokens(text: &str) -> Result<Vec<Part>, String> {
    text.split_whitespace().map(parse_token).collect()
}

fn parse_token(token: &str) -> Result<Part, String> {
    let token = token
        .strip_prefix("0x")
        .or_else(|| token.strip_prefix("0X"))
        .unwrap_or(token);
    if token == "?" || token == "??" || token == "*" {
        return Ok(Part::Any);
    }
    if token.len() != 2 {
        return Err(format!("'{token}' is not a byte; use two hex digits or ??"));
    }
    u8::from_str_radix(token, 16)
        .map(Part::Byte)
        .map_err(|_| format!("'{token}' is not a byte; use two hex digits or ??"))
}

fn parse_compact(text: &str) -> Result<Vec<Part>, String> {
    let text = text
        .strip_prefix("0x")
        .or_else(|| text.strip_prefix("0X"))
        .unwrap_or(text);
    if !text.len().is_multiple_of(2) {
        return Err("Hex patterns need an even number of digits".to_owned());
    }
    let chars: Vec<char> = text.chars().collect();
    chars
        .chunks(2)
        .map(|pair| {
            if pair.iter().all(|digit| *digit == '?' || *digit == '*') {
                return Ok(Part::Any);
            }
            let token: String = pair.iter().collect();
            u8::from_str_radix(&token, 16)
                .map(Part::Byte)
                .map_err(|_| format!("'{token}' is not a byte; use two hex digits or ??"))
        })
        .collect()
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ByteMatch {
    pub va: u64,
    pub offset: u64,
    pub section: usize,
}

// Scans only the stored section ranges, so a match always has a real address and file offset.
pub fn find(data: &[u8], sections: &[Section], pattern: &Pattern, limit: usize) -> Vec<ByteMatch> {
    let mut found = Vec::new();
    if pattern.is_empty() || limit == 0 {
        return found;
    }
    let width = pattern.len();
    let anchor = pattern.anchor;

    for (index, section) in sections.iter().enumerate() {
        let Ok(start) = usize::try_from(section.offset) else {
            continue;
        };
        let Ok(size) = usize::try_from(section.size) else {
            continue;
        };
        let end = start.saturating_add(size).min(data.len());
        if start >= end || end - start < width {
            continue;
        }
        let window = &data[start..end];

        for (at, slice) in window.windows(width).enumerate() {
            if let Some((offset, byte)) = anchor
                && slice[offset] != byte
            {
                continue;
            }
            if !pattern.matches(slice) {
                continue;
            }
            found.push(ByteMatch {
                va: section.va + at as u64,
                offset: section.offset + at as u64,
                section: index,
            });
            if found.len() >= limit {
                return found;
            }
        }
    }
    found
}

#[cfg(test)]
mod tests {
    use super::*;

    fn section(va: u64, offset: u64, size: u64) -> Section {
        Section {
            va,
            offset,
            size,
            executable: true,
        }
    }

    #[test]
    fn parses_spaced_and_compact_patterns() {
        let spaced = Pattern::parse("48 8B ?? 89").unwrap();
        let compact = Pattern::parse("488B??89").unwrap();
        assert_eq!(spaced, compact);
        assert_eq!(spaced.text(), "48 8B ?? 89");

        assert_eq!(Pattern::parse("0x90 0XCC").unwrap().len(), 2);
        assert_eq!(Pattern::parse("48 8b ? 89").unwrap(), compact);
    }

    #[test]
    fn rejects_malformed_patterns() {
        assert!(Pattern::parse("").is_err());
        assert!(Pattern::parse("4").is_err());
        assert!(Pattern::parse("48 8B GG").is_err());
        assert!(Pattern::parse("488B8").is_err());
        assert!(Pattern::parse("?? ?? ??").is_err());
    }

    #[test]
    fn finds_wildcard_matches_with_addresses() {
        let data = [
            0x00, 0x48, 0x8B, 0x11, 0x89, 0x48, 0x8B, 0x22, 0x89, 0xCC, 0x48, 0x8B, 0x33, 0x89,
        ];
        let sections = [section(0x1000, 0, data.len() as u64)];
        let pattern = Pattern::parse("48 8B ?? 89").unwrap();

        let hits = find(&data, &sections, &pattern, 10);
        let addresses: Vec<u64> = hits.iter().map(|hit| hit.va).collect();
        assert_eq!(addresses, [0x1001, 0x1005, 0x100a]);
        assert_eq!(hits[0].offset, 1);
        assert_eq!(hits[0].section, 0);
    }

    #[test]
    fn stays_inside_sections_and_respects_the_limit() {
        let data = [0x90; 16];
        let sections = [section(0x2000, 0, 8), section(0x4000, 8, 8)];
        let pattern = Pattern::parse("90").unwrap();

        let hits = find(&data, &sections, &pattern, 5);
        assert_eq!(hits.len(), 5);
        assert!(hits.iter().all(|hit| hit.va < 0x2008));

        let all = find(&data, &sections, &pattern, 100);
        assert_eq!(all.len(), 16);
        assert_eq!(all[8].va, 0x4000);
        assert_eq!(all[8].offset, 8);
    }

    #[test]
    fn ignores_wildcard_only_matches_outside_data() {
        let data = [0xAA; 4];
        let pattern = Pattern::parse("AA BB").unwrap();
        assert!(find(&data, &[section(0, 0, 4)], &pattern, 10).is_empty());
        assert!(find(&data, &[section(0, 1024, 4)], &pattern, 10).is_empty());
    }
}
