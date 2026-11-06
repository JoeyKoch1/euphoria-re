use std::fmt::Write;

use anyhow::{Result, bail};
use serde::Serialize;

const CHUNK_XML: u16 = 0x0003;
const CHUNK_STRINGS: u16 = 0x0001;
const CHUNK_RESOURCE_MAP: u16 = 0x0180;
const CHUNK_START_ELEMENT: u16 = 0x0102;
const CHUNK_END_ELEMENT: u16 = 0x0103;
const FLAG_UTF8: u32 = 0x100;
const ATTRIBUTE_SIZE: usize = 20;
const NO_INDEX: u32 = 0xFFFF_FFFF;
const MAX_STRINGS: usize = 2_000_000;

const TYPE_REFERENCE: u8 = 0x01;
const TYPE_STRING: u8 = 0x03;
const TYPE_INT_HEX: u8 = 0x11;
const TYPE_BOOL: u8 = 0x12;

const KNOWN_ATTRIBUTES: &[(u32, &str)] = &[
    (0x0101_0003, "name"),
    (0x0101_000F, "debuggable"),
    (0x0101_0010, "exported"),
    (0x0101_020C, "minSdkVersion"),
    (0x0101_021B, "versionCode"),
    (0x0101_021C, "versionName"),
    (0x0101_0270, "targetSdkVersion"),
    (0x0101_0280, "allowBackup"),
    (0x0101_04EC, "usesCleartextTraffic"),
];

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Component {
    pub kind: String,
    pub name: String,
    pub exported: Option<bool>,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Manifest {
    pub package: String,
    pub version_name: String,
    pub version_code: String,
    pub min_sdk: String,
    pub target_sdk: String,
    pub debuggable: bool,
    pub allow_backup: Option<bool>,
    pub cleartext_traffic: Option<bool>,
    pub permissions: Vec<String>,
    pub components: Vec<Component>,
    // Fully qualified, resolved against the package. Some APKs have no launcher at all.
    pub launcher_activity: Option<String>,
}

struct Attribute {
    name: String,
    value: String,
}

struct Reader<'a> {
    data: &'a [u8],
}

impl Reader<'_> {
    fn u16_at(&self, at: usize) -> Option<u16> {
        let bytes = self.data.get(at..at.checked_add(2)?)?;
        Some(u16::from_le_bytes([bytes[0], bytes[1]]))
    }

    fn u32_at(&self, at: usize) -> Option<u32> {
        let bytes = self.data.get(at..at.checked_add(4)?)?;
        Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }
}

fn read_strings(reader: &Reader<'_>, chunk: usize) -> Option<Vec<String>> {
    let count = reader.u32_at(chunk + 8)? as usize;
    let flags = reader.u32_at(chunk + 16)?;
    let start = chunk.checked_add(reader.u32_at(chunk + 20)? as usize)?;
    let header = usize::from(reader.u16_at(chunk + 2)?);
    if count > MAX_STRINGS {
        return None;
    }

    let mut strings = Vec::with_capacity(count.min(4096));
    for index in 0..count {
        let offset = reader.u32_at(chunk + header + index * 4)? as usize;
        let at = start.checked_add(offset)?;
        let value = if flags & FLAG_UTF8 != 0 {
            read_utf8(reader.data, at)
        } else {
            read_utf16(reader, at)
        };
        strings.push(value.unwrap_or_default());
    }
    Some(strings)
}

fn read_utf8(data: &[u8], at: usize) -> Option<String> {
    let read_length = |at: &mut usize| -> Option<usize> {
        let first = *data.get(*at)?;
        *at += 1;
        if first & 0x80 == 0 {
            return Some(usize::from(first));
        }
        let second = *data.get(*at)?;
        *at += 1;
        Some((usize::from(first & 0x7F) << 8) | usize::from(second))
    };

    let mut at = at;
    read_length(&mut at)?;
    let length = read_length(&mut at)?;
    let bytes = data.get(at..at.checked_add(length)?)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn read_utf16(reader: &Reader<'_>, at: usize) -> Option<String> {
    let first = reader.u16_at(at)?;
    let (length, mut at) = if first & 0x8000 != 0 {
        let low = reader.u16_at(at + 2)?;
        (
            (usize::from(first & 0x7FFF) << 16) | usize::from(low),
            at + 4,
        )
    } else {
        (usize::from(first), at + 2)
    };

    let mut units = Vec::with_capacity(length.min(4096));
    for _ in 0..length {
        units.push(reader.u16_at(at)?);
        at += 2;
    }
    Some(String::from_utf16_lossy(&units))
}

fn attribute_value(value_type: u8, data: u32, raw: Option<&String>) -> String {
    if let Some(text) = raw {
        return text.clone();
    }
    match value_type {
        TYPE_STRING => String::new(),
        TYPE_REFERENCE => format!("@{data:#010x}"),
        TYPE_BOOL => (data != 0).to_string(),
        TYPE_INT_HEX => format!("{data:#x}"),
        _ => (data as i32).to_string(),
    }
}

fn escape(text: &str) -> String {
    text.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn find<'a>(attributes: &'a [Attribute], name: &str) -> Option<&'a str> {
    attributes
        .iter()
        .find(|attribute| attribute.name == name)
        .map(|attribute| attribute.value.as_str())
}

fn apply(manifest: &mut Manifest, element: &str, attributes: &[Attribute]) {
    let text = |name: &str| find(attributes, name).unwrap_or("").to_owned();
    let flag = |name: &str| find(attributes, name).map(|value| value == "true");

    match element {
        "manifest" => {
            manifest.package = text("package");
            manifest.version_name = text("versionName");
            manifest.version_code = text("versionCode");
        }
        "uses-sdk" => {
            manifest.min_sdk = text("minSdkVersion");
            manifest.target_sdk = text("targetSdkVersion");
        }
        "application" => {
            manifest.debuggable = flag("debuggable").unwrap_or(false);
            manifest.allow_backup = flag("allowBackup");
            manifest.cleartext_traffic = flag("usesCleartextTraffic");
        }
        "uses-permission" | "uses-permission-sdk-23" => {
            let name = text("name");
            if !name.is_empty() && !manifest.permissions.contains(&name) {
                manifest.permissions.push(name);
            }
        }
        "activity" | "activity-alias" | "service" | "receiver" | "provider" => {
            manifest.components.push(Component {
                kind: element.to_owned(),
                name: text("name"),
                exported: flag("exported"),
            });
        }
        _ => {}
    }
}

// Android stores the manifest as binary XML. Tampered files often have broken headers, so this
// walks whatever chunks it can read and keeps what it finds.
pub(crate) fn parse(data: &[u8]) -> Result<(Manifest, String)> {
    let reader = Reader { data };
    if reader.u16_at(0) != Some(CHUNK_XML) {
        bail!("this is not a binary XML file");
    }

    let mut strings = Vec::new();
    let mut resources: Vec<u32> = Vec::new();
    let mut manifest = Manifest::default();
    let mut xml = String::new();
    let mut depth = 0usize;
    let mut elements: Vec<String> = Vec::new();
    let mut component: Option<String> = None;
    let mut filter_main = false;
    let mut filter_launcher = false;

    let mut at = usize::from(reader.u16_at(2).unwrap_or(8));
    while let (Some(kind), Some(size)) = (reader.u16_at(at), reader.u32_at(at + 4)) {
        let size = size as usize;
        if size < 8 {
            break;
        }

        match kind {
            CHUNK_STRINGS => strings = read_strings(&reader, at).unwrap_or_default(),
            CHUNK_RESOURCE_MAP => {
                resources = (at + 8..at + size)
                    .step_by(4)
                    .map_while(|position| reader.u32_at(position))
                    .collect();
            }
            CHUNK_START_ELEMENT => {
                let lookup = |index: u32| strings.get(index as usize);
                let name = reader
                    .u32_at(at + 20)
                    .and_then(lookup)
                    .cloned()
                    .unwrap_or_default();
                let attributes = read_attributes(&reader, at, &strings, &resources);

                track_launcher(
                    &name,
                    &attributes,
                    &mut component,
                    &mut filter_main,
                    &mut filter_launcher,
                );
                apply(&mut manifest, &name, &attributes);
                let _ = write!(xml, "{}<{name}", "  ".repeat(depth));
                for attribute in &attributes {
                    let _ = write!(xml, " {}=\"{}\"", attribute.name, escape(&attribute.value));
                }
                xml.push_str(">\n");
                depth += 1;
                elements.push(name);
            }
            CHUNK_END_ELEMENT => {
                depth = depth.saturating_sub(1);
                let name = reader
                    .u32_at(at + 20)
                    .and_then(|index| strings.get(index as usize))
                    .map_or("", String::as_str);
                let closed = elements.pop().unwrap_or_else(|| name.to_owned());
                if closed == "intent-filter" {
                    if filter_main
                        && filter_launcher
                        && manifest.launcher_activity.is_none()
                        && let Some(component) = &component
                    {
                        manifest.launcher_activity =
                            Some(resolve_component(&manifest.package, component));
                    }
                    filter_main = false;
                    filter_launcher = false;
                } else if closed == "activity" || closed == "activity-alias" {
                    component = None;
                }
                let _ = writeln!(xml, "{}</{name}>", "  ".repeat(depth));
            }
            _ => {}
        }

        let Some(next) = at.checked_add(size) else {
            break;
        };
        at = next;
    }

    Ok((manifest, xml))
}

// The launcher is not an attribute; it is an activity whose intent-filter declares MAIN and
// LAUNCHER. Keeping this here means the analyzer and the Android runtime share one parser.
fn track_launcher(
    element: &str,
    attributes: &[Attribute],
    component: &mut Option<String>,
    filter_main: &mut bool,
    filter_launcher: &mut bool,
) {
    match element {
        "activity" | "activity-alias" => {
            *component = find(attributes, "name").map(str::to_owned);
        }
        "intent-filter" => {
            *filter_main = false;
            *filter_launcher = false;
        }
        "action" => {
            if find(attributes, "name") == Some("android.intent.action.MAIN") {
                *filter_main = true;
            }
        }
        "category" => {
            if matches!(
                find(attributes, "name"),
                Some(
                    "android.intent.category.LAUNCHER"
                        | "android.intent.category.LEANBACK_LAUNCHER"
                )
            ) {
                *filter_launcher = true;
            }
        }
        _ => {}
    }
}

fn resolve_component(package: &str, name: &str) -> String {
    if package.is_empty() {
        name.to_owned()
    } else if name.starts_with('.') {
        format!("{package}{name}")
    } else if name.contains('.') {
        name.to_owned()
    } else {
        format!("{package}.{name}")
    }
}

fn read_attributes(
    reader: &Reader<'_>,
    chunk: usize,
    strings: &[String],
    resources: &[u32],
) -> Vec<Attribute> {
    let start = usize::from(reader.u16_at(chunk + 24).unwrap_or(20));
    let count = usize::from(reader.u16_at(chunk + 28).unwrap_or(0));
    let base = chunk + 16 + start;

    (0..count)
        .map_while(|index| {
            let at = base + index * ATTRIBUTE_SIZE;
            let name_index = reader.u32_at(at + 4)?;
            let raw = reader.u32_at(at + 8)?;
            let value_type = reader.u32_at(at + 12)?.to_le_bytes()[3];
            let value_data = reader.u32_at(at + 16)?;

            let known = resources.get(name_index as usize).and_then(|id| {
                KNOWN_ATTRIBUTES
                    .iter()
                    .find(|(known, _)| known == id)
                    .map(|(_, name)| (*name).to_owned())
            });
            let stored = strings.get(name_index as usize).cloned();
            let name = known
                .or(stored.filter(|name| !name.is_empty()))
                .unwrap_or_else(|| format!("attr{name_index}"));

            let raw_text = (raw != NO_INDEX)
                .then(|| strings.get(raw as usize))
                .flatten();
            let value = if value_type == TYPE_STRING {
                strings
                    .get(value_data as usize)
                    .cloned()
                    .unwrap_or_default()
            } else {
                attribute_value(value_type, value_data, raw_text)
            };
            Some(Attribute { name, value })
        })
        .collect()
}

pub(crate) mod sample {
    use super::*;

    const TYPE_INT: u8 = 0x10;

    fn put16(out: &mut Vec<u8>, value: u16) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn put32(out: &mut Vec<u8>, value: u32) {
        out.extend_from_slice(&value.to_le_bytes());
    }

    fn string_pool(strings: &[&str]) -> Vec<u8> {
        let mut body = Vec::new();
        let mut offsets = Vec::new();
        for text in strings {
            offsets.push(body.len() as u32);
            put16(&mut body, text.len() as u16);
            for unit in text.encode_utf16() {
                put16(&mut body, unit);
            }
            put16(&mut body, 0);
        }
        while body.len() % 4 != 0 {
            body.push(0);
        }

        let header = 28u32;
        let start = header + strings.len() as u32 * 4;
        let mut chunk = Vec::new();
        put16(&mut chunk, CHUNK_STRINGS);
        put16(&mut chunk, header as u16);
        put32(&mut chunk, start + body.len() as u32);
        put32(&mut chunk, strings.len() as u32);
        put32(&mut chunk, 0);
        put32(&mut chunk, 0);
        put32(&mut chunk, start);
        put32(&mut chunk, 0);
        for offset in offsets {
            put32(&mut chunk, offset);
        }
        chunk.extend_from_slice(&body);
        chunk
    }

    fn start(name: u32, attributes: &[(u32, u8, u32)]) -> Vec<u8> {
        let mut chunk = Vec::new();
        put16(&mut chunk, CHUNK_START_ELEMENT);
        put16(&mut chunk, 16);
        put32(&mut chunk, 36 + attributes.len() as u32 * 20);
        put32(&mut chunk, 1);
        put32(&mut chunk, NO_INDEX);
        put32(&mut chunk, NO_INDEX);
        put32(&mut chunk, name);
        put16(&mut chunk, 20);
        put16(&mut chunk, 20);
        put16(&mut chunk, attributes.len() as u16);
        put16(&mut chunk, 0);
        put16(&mut chunk, 0);
        put16(&mut chunk, 0);
        for &(attribute, value_type, data) in attributes {
            put32(&mut chunk, NO_INDEX);
            put32(&mut chunk, attribute);
            put32(
                &mut chunk,
                if value_type == TYPE_STRING {
                    data
                } else {
                    NO_INDEX
                },
            );
            put16(&mut chunk, 8);
            chunk.push(0);
            chunk.push(value_type);
            put32(&mut chunk, data);
        }
        chunk
    }

    fn end(name: u32) -> Vec<u8> {
        let mut chunk = Vec::new();
        put16(&mut chunk, CHUNK_END_ELEMENT);
        put16(&mut chunk, 16);
        put32(&mut chunk, 24);
        put32(&mut chunk, 1);
        put32(&mut chunk, NO_INDEX);
        put32(&mut chunk, NO_INDEX);
        put32(&mut chunk, name);
        chunk
    }

    pub(crate) fn sample_manifest() -> Vec<u8> {
        let names = [
            "name",
            "versionCode",
            "versionName",
            "minSdkVersion",
            "targetSdkVersion",
            "debuggable",
            "exported",
            "package",
            "manifest",
            "uses-sdk",
            "uses-permission",
            "application",
            "activity",
            "com.example.app",
            "1.2.3",
            "android.permission.INTERNET",
            "android.permission.READ_SMS",
            ".MainActivity",
            "intent-filter",
            "action",
            "android.intent.action.MAIN",
            "category",
            "android.intent.category.LAUNCHER",
        ];
        let resources: [u32; 7] = [
            0x0101_0003,
            0x0101_021B,
            0x0101_021C,
            0x0101_020C,
            0x0101_0270,
            0x0101_000F,
            0x0101_0010,
        ];

        let mut body = string_pool(&names);
        put16(&mut body, CHUNK_RESOURCE_MAP);
        put16(&mut body, 8);
        put32(&mut body, 8 + resources.len() as u32 * 4);
        for id in resources {
            put32(&mut body, id);
        }
        body.extend(start(
            8,
            &[(1, TYPE_INT, 7), (2, TYPE_STRING, 14), (7, TYPE_STRING, 13)],
        ));
        body.extend(start(9, &[(3, TYPE_INT, 21), (4, TYPE_INT, 34)]));
        body.extend(end(9));
        body.extend(start(10, &[(0, TYPE_STRING, 15)]));
        body.extend(end(10));
        body.extend(start(10, &[(0, TYPE_STRING, 16)]));
        body.extend(end(10));
        body.extend(start(11, &[(5, TYPE_BOOL, 0xFFFF_FFFF)]));
        body.extend(start(
            12,
            &[(0, TYPE_STRING, 17), (6, TYPE_BOOL, 0xFFFF_FFFF)],
        ));
        body.extend(start(18, &[]));
        body.extend(start(19, &[(0, TYPE_STRING, 20)]));
        body.extend(end(19));
        body.extend(start(21, &[(0, TYPE_STRING, 22)]));
        body.extend(end(21));
        body.extend(end(18));
        body.extend(end(12));
        body.extend(end(11));
        body.extend(end(8));

        let mut file = Vec::new();
        put16(&mut file, CHUNK_XML);
        put16(&mut file, 8);
        put32(&mut file, 8 + body.len() as u32);
        file.extend(body);
        file
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::sample::sample_manifest;
    use super::*;

    #[test]
    fn reads_the_manifest() {
        let (manifest, xml) = parse(&sample_manifest()).unwrap();

        assert_eq!(manifest.package, "com.example.app");
        assert_eq!(manifest.version_name, "1.2.3");
        assert_eq!(manifest.version_code, "7");
        assert_eq!(manifest.min_sdk, "21");
        assert_eq!(manifest.target_sdk, "34");
        assert!(manifest.debuggable);
        assert_eq!(
            manifest.permissions,
            ["android.permission.INTERNET", "android.permission.READ_SMS"]
        );
        assert_eq!(manifest.components[0].kind, "activity");
        assert_eq!(manifest.components[0].name, ".MainActivity");
        assert_eq!(manifest.components[0].exported, Some(true));
        assert_eq!(
            manifest.launcher_activity.as_deref(),
            Some("com.example.app.MainActivity")
        );

        assert!(xml.contains("<manifest"));
        assert!(xml.contains("package=\"com.example.app\""));
        assert!(xml.contains("  <application debuggable=\"true\">"));
        assert!(xml.contains("<intent-filter>"));
        assert!(xml.trim_end().ends_with("</manifest>"));
    }

    #[test]
    fn launcher_names_are_qualified_against_the_package() {
        assert_eq!(resolve_component("a.b", ".Main"), "a.b.Main");
        assert_eq!(resolve_component("a.b", "Main"), "a.b.Main");
        assert_eq!(resolve_component("a.b", "x.y.Main"), "x.y.Main");
        assert_eq!(resolve_component("", ".Main"), ".Main");
    }

    #[test]
    fn reads_utf8_string_pools() {
        let data = [3u8, 3, b'a', b'b', b'c', 0];
        assert_eq!(read_utf8(&data, 0).as_deref(), Some("abc"));
        assert_eq!(read_utf8(&[3, 3, b'a'], 0), None);

        let mut long = vec![0x81, 0x90, 0x81, 0x90];
        long.extend(std::iter::repeat_n(b'x', 0x190));
        assert_eq!(read_utf8(&long, 0).map(|text| text.len()), Some(0x190));
    }

    #[test]
    fn survives_damage_anywhere_in_the_file() {
        let good = sample_manifest();
        assert!(parse(b"not xml").is_err());
        for cut in 0..good.len() {
            let _ = parse(&good[..cut]);
        }
        for at in 0..good.len() {
            for flip in [0xFF, 0x80, 0x01] {
                let mut bad = good.clone();
                bad[at] ^= flip;
                let _ = parse(&bad);
            }
        }
    }
}
