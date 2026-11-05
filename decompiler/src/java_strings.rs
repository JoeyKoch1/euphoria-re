//! Java/DEX modified UTF-8 decoding (the input excludes the zero terminator).

use std::fmt::Write;

/// Validates the encoded UTF-16 length. Isolated surrogates, which DEX permits
/// but Rust strings cannot hold, are retained as Java-style `\uXXXX` escapes.
pub fn decode_mutf8(bytes: &[u8], utf16_size: u32) -> Option<String> {
    let mut units = Vec::new();
    let mut at = 0;
    while at < bytes.len() {
        let first = bytes[at];
        at += 1;
        let unit = match first {
            1..=0x7f => u16::from(first),
            0xc0..=0xdf => {
                let second = *bytes.get(at)?;
                at += 1;
                if second & 0xc0 != 0x80 {
                    return None;
                }
                let value = (u16::from(first & 0x1f) << 6) | u16::from(second & 0x3f);
                if value < 0x80 && value != 0 {
                    return None;
                }
                value
            }
            0xe0..=0xef => {
                let second = *bytes.get(at)?;
                let third = *bytes.get(at + 1)?;
                at += 2;
                if second & 0xc0 != 0x80 || third & 0xc0 != 0x80 {
                    return None;
                }
                let value = (u16::from(first & 0x0f) << 12)
                    | (u16::from(second & 0x3f) << 6)
                    | u16::from(third & 0x3f);
                if value < 0x800 {
                    return None;
                }
                value
            }
            _ => return None,
        };
        units.push(unit);
        if units.len() > utf16_size as usize {
            return None;
        }
    }
    if units.len() != utf16_size as usize {
        return None;
    }
    let mut text = String::new();
    for decoded in char::decode_utf16(units) {
        match decoded {
            Ok(ch) => text.push(ch),
            Err(error) => {
                let _ = write!(text, "\\u{:04x}", error.unpaired_surrogate());
            }
        }
    }
    Some(text)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_java_strings() {
        assert_eq!(decode_mutf8(b"Hello", 5).as_deref(), Some("Hello"));
        assert_eq!(decode_mutf8(&[0xc0, 0x80], 1).as_deref(), Some("\0"));
        assert_eq!(decode_mutf8("é水".as_bytes(), 2).as_deref(), Some("é水"));
        assert_eq!(
            decode_mutf8(&[0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80], 2).as_deref(),
            Some("😀")
        );
        assert_eq!(
            decode_mutf8(&[0xed, 0xa0, 0x80], 1).as_deref(),
            Some("\\ud800")
        );
        assert_eq!(decode_mutf8(&[], 0).as_deref(), Some(""));
    }

    #[test]
    fn rejects_malformed_encoding_and_lengths() {
        for bytes in [
            &[0][..],
            &[0xc1, 0x81],
            &[0xe0, 0x80, 0x80],
            &[0xc2],
            &[0xe1, 0x80],
            &[0xc2, 0x41],
            &[0x80],
            "😀".as_bytes(),
        ] {
            assert_eq!(decode_mutf8(bytes, 1), None);
        }
        assert_eq!(decode_mutf8(b"a", 0), None);
        assert_eq!(decode_mutf8(b"a", 2), None);
    }
}
