mod axml;
mod dalvik;
mod dex;

use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result, ensure};
use euphoria_engine::{base64_text, dataset::sha256_hex, entropy};
use serde::Serialize;
use zip::ZipArchive;

pub use axml::{Component, Manifest};
pub use dalvik::Insn;
pub use dex::{Class, ClassLine, Code, Dex, Field, Method};

const MAX_ENTRY_BYTES: u64 = 1024 * 1024 * 1024;
const V2_SIGNATURE_MAGIC: &[u8] = b"APK Sig Block 42";
const SIGNATURE_SEARCH_BYTES: usize = 64 * 1024 * 1024;
const DANGEROUS_PERMISSIONS: &[&str] = &[
    "READ_SMS",
    "SEND_SMS",
    "RECEIVE_SMS",
    "READ_CONTACTS",
    "WRITE_CONTACTS",
    "READ_CALL_LOG",
    "WRITE_CALL_LOG",
    "CALL_PHONE",
    "RECORD_AUDIO",
    "CAMERA",
    "ACCESS_FINE_LOCATION",
    "ACCESS_COARSE_LOCATION",
    "ACCESS_BACKGROUND_LOCATION",
    "READ_EXTERNAL_STORAGE",
    "WRITE_EXTERNAL_STORAGE",
    "MANAGE_EXTERNAL_STORAGE",
    "READ_PHONE_STATE",
    "BIND_ACCESSIBILITY_SERVICE",
    "BIND_DEVICE_ADMIN",
    "REQUEST_INSTALL_PACKAGES",
    "SYSTEM_ALERT_WINDOW",
    "QUERY_ALL_PACKAGES",
];
const PROTECTOR_LIBRARIES: &[(&str, &str)] = &[
    ("libjiagu", "Qihoo 360 Jiagu"),
    ("libsecexe", "Bangcle"),
    ("libsecmain", "Bangcle"),
    ("libdexhelper", "SecNeo"),
    ("libshell", "Tencent Legu"),
];

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    pub compressed: u64,
    pub crc32: u32,
}

#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct NativeLibrary {
    pub path: String,
    pub abi: String,
    pub size: u64,
    pub sha256: String,
    pub entropy: f32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize)]
pub struct Signing {
    pub v1_files: Vec<String>,
    pub v2_or_later: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ApkString {
    pub dex: usize,
    pub index: usize,
    pub value: String,
    pub base64: Option<String>,
}

pub struct Apk {
    pub file_name: String,
    pub sha256: String,
    pub data: Arc<Vec<u8>>,
    pub files: Vec<FileEntry>,
    pub manifest: Manifest,
    pub manifest_xml: String,
    pub dexes: Vec<Dex>,
    pub natives: Vec<NativeLibrary>,
    pub signing: Signing,
    pub protectors: Vec<String>,
    pub strings: Vec<ApkString>,
    pub warnings: Vec<String>,
}

pub fn is_dangerous_permission(permission: &str) -> bool {
    let short = permission.rsplit('.').next().unwrap_or(permission);
    DANGEROUS_PERMISSIONS.contains(&short)
}

pub fn is_apk(path: &Path) -> bool {
    let named_apk = path
        .extension()
        .is_some_and(|extension| extension.eq_ignore_ascii_case("apk"));
    if named_apk {
        return true;
    }

    let Ok(file) = fs::File::open(path) else {
        return false;
    };
    let mut head = [0u8; 2];
    let is_zip = (&file).read_exact(&mut head).is_ok() && head == *b"PK";
    is_zip
        && ZipArchive::new(file).is_ok_and(|archive| {
            archive
                .file_names()
                .any(|name| name.is_ok_and(|name| name == "AndroidManifest.xml"))
        })
}

impl Apk {
    pub fn open(path: &Path) -> Result<Self> {
        let data = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        Self::parse(file_name, data)
    }

    pub fn parse(file_name: String, data: Vec<u8>) -> Result<Self> {
        let mut archive =
            ZipArchive::new(Cursor::new(&data)).context("this APK is not a readable zip file")?;

        let mut apk = Self {
            file_name,
            sha256: sha256_hex(&data),
            files: Vec::new(),
            manifest: Manifest::default(),
            manifest_xml: String::new(),
            dexes: Vec::new(),
            natives: Vec::new(),
            signing: Signing::default(),
            protectors: Vec::new(),
            strings: Vec::new(),
            warnings: Vec::new(),
            data: Arc::new(Vec::new()),
        };

        for index in 0..archive.len() {
            let mut entry = match archive.by_index(index) {
                Ok(entry) => entry,
                Err(error) => {
                    apk.warnings.push(format!("Entry {index}: {error}"));
                    continue;
                }
            };
            let name = match entry.name() {
                Ok(name) => name.into_owned(),
                Err(error) => {
                    apk.warnings.push(format!("Entry {index}: {error}"));
                    continue;
                }
            };
            apk.files.push(FileEntry {
                name: name.clone(),
                size: entry.size(),
                compressed: entry.compressed_size(),
                crc32: entry.crc32(),
            });

            if is_v1_signature(&name) {
                apk.signing.v1_files.push(name.clone());
            }
            if !wanted(&name) {
                continue;
            }

            match read_entry_bytes(&mut entry, MAX_ENTRY_BYTES) {
                Ok(bytes) => apk.read_entry(&name, bytes),
                Err(error) => apk.warnings.push(format!("{name}: {error}")),
            }
        }

        apk.signing.v2_or_later = has_v2_signature(&data);
        apk.find_protectors();
        apk.dexes.sort_by(|a, b| a.name.cmp(&b.name));
        apk.collect_strings();
        apk.data = Arc::new(data);
        Ok(apk)
    }

    fn read_entry(&mut self, name: &str, bytes: Vec<u8>) {
        if name == "AndroidManifest.xml" {
            match axml::parse(&bytes) {
                Ok((manifest, xml)) => {
                    self.manifest = manifest;
                    self.manifest_xml = xml;
                }
                Err(error) => self.warnings.push(format!("{name}: {error}")),
            }
        } else if name.ends_with(".so") {
            self.natives.push(NativeLibrary {
                path: name.to_owned(),
                abi: name.split('/').nth(1).unwrap_or("").to_owned(),
                size: bytes.len() as u64,
                sha256: sha256_hex(&bytes),
                entropy: entropy(&bytes),
            });
        } else {
            match Dex::parse(name, bytes) {
                Ok(dex) => self.dexes.push(dex),
                Err(error) => self.warnings.push(format!("{name}: {error}")),
            }
        }
    }

    fn find_protectors(&mut self) {
        let mut found = BTreeSet::new();
        for library in &self.natives {
            let file = library.path.rsplit('/').next().unwrap_or("").to_lowercase();
            for (prefix, name) in PROTECTOR_LIBRARIES {
                if file.starts_with(prefix) {
                    found.insert((*name).to_owned());
                }
            }
        }
        self.protectors = found.into_iter().collect();
    }

    fn collect_strings(&mut self) {
        for (dex_index, dex) in self.dexes.iter().enumerate() {
            for (index, value) in dex.strings.iter().enumerate() {
                self.strings.push(ApkString {
                    dex: dex_index,
                    index,
                    value: value.clone(),
                    base64: base64_text(value),
                });
            }
        }
    }

    pub fn class_count(&self) -> usize {
        self.dexes.iter().map(|dex| dex.classes.len()).sum()
    }

    pub fn method_count(&self) -> usize {
        self.dexes
            .iter()
            .flat_map(|dex| &dex.classes)
            .map(|class| class.methods.len())
            .sum()
    }

    // Sorted and de-duplicated, because one .so per ABI is common and only the set matters.
    pub fn native_abis(&self) -> Vec<String> {
        let mut abis: Vec<String> = self
            .natives
            .iter()
            .map(|library| library.abi.clone())
            .filter(|abi| !abi.is_empty())
            .collect();
        abis.sort();
        abis.dedup();
        abis
    }

    pub fn for_each_file(
        &self,
        mut visit: impl FnMut(&str, u64, &mut dyn Read) -> Result<()>,
    ) -> Result<()> {
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        for index in 0..archive.len() {
            let mut entry = archive
                .by_index(index)
                .with_context(|| format!("cannot read APK entry {index}"))?;
            if entry.is_dir() {
                continue;
            }
            let name = entry.name()?.into_owned();
            let size = entry.size();
            ensure!(
                size <= MAX_ENTRY_BYTES,
                "{name} exceeds the APK entry limit of {MAX_ENTRY_BYTES} bytes"
            );
            visit(&name, size, &mut entry).with_context(|| format!("cannot export {name}"))?;
        }
        Ok(())
    }

    pub fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        let mut entry = archive.by_name(name)?;
        read_entry_bytes(&mut entry, MAX_ENTRY_BYTES).with_context(|| format!("cannot read {name}"))
    }
}

fn read_entry_bytes(reader: &mut impl Read, limit: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    reader.take(limit + 1).read_to_end(&mut bytes)?;
    ensure!(
        bytes.len() as u64 <= limit,
        "APK entry exceeds the limit of {limit} bytes"
    );
    Ok(bytes)
}

fn wanted(name: &str) -> bool {
    let is_dex = !name.contains('/') && name.starts_with("classes") && name.ends_with(".dex");
    let is_native = name.starts_with("lib/") && name.ends_with(".so");
    is_dex || is_native || name == "AndroidManifest.xml"
}

fn is_v1_signature(name: &str) -> bool {
    name.starts_with("META-INF/")
        && [".RSA", ".DSA", ".EC"]
            .iter()
            .any(|extension| name.to_ascii_uppercase().ends_with(extension))
}

fn has_v2_signature(data: &[u8]) -> bool {
    let start = data.len().saturating_sub(SIGNATURE_SEARCH_BYTES);
    data[start..]
        .windows(V2_SIGNATURE_MAGIC.len())
        .any(|window| window == V2_SIGNATURE_MAGIC)
}

pub mod samples {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use crate::{axml, dex};

    pub fn demo_apk() -> Vec<u8> {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default();
        let files: [(&str, Vec<u8>); 4] = [
            ("AndroidManifest.xml", axml::sample::sample_manifest()),
            ("classes.dex", dex::sample::sample_dex()),
            (
                "lib/arm64-v8a/libjiagu.so",
                vec![0x7F, b'E', b'L', b'F', 1, 2],
            ),
            ("META-INF/CERT.RSA", vec![1, 2, 3]),
        ];
        for (name, bytes) in files {
            writer.start_file(name, options).unwrap();
            writer.write_all(&bytes).unwrap();
        }
        writer.finish().unwrap().into_inner()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_oversized_entries_instead_of_truncating() {
        assert_eq!(read_entry_bytes(&mut &b"abc"[..], 3).unwrap(), b"abc");
        assert!(read_entry_bytes(&mut &b"abcd"[..], 3).is_err());
    }

    #[test]
    fn string_indexes_follow_sorted_dexes() {
        use std::io::Write;
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        for (name, value) in [
            ("classes2.dex", b"second".as_slice()),
            ("classes.dex", b"first".as_slice()),
        ] {
            let mut dex = dex::sample::sample_dex();
            let offset = dex.len() as u32;
            dex[0x70..0x74].copy_from_slice(&offset.to_le_bytes());
            dex.push(value.len() as u8);
            dex.extend_from_slice(value);
            dex.push(0);
            writer
                .start_file(name, zip::write::SimpleFileOptions::default())
                .unwrap();
            writer.write_all(&dex).unwrap();
        }
        let apk = Apk::parse("multi.apk".into(), writer.finish().unwrap().into_inner()).unwrap();
        assert_eq!(apk.dexes[0].name, "classes.dex");
        assert_eq!(apk.strings[0].value, "first");
        for found in &apk.strings {
            assert_eq!(found.value, apk.dexes[found.dex].string(found.index as u32));
        }
        assert!(
            apk.for_each_file(|_, _, _| anyhow::bail!("read failed"))
                .is_err()
        );
    }

    #[test]
    fn reads_a_whole_apk() {
        let apk = Apk::parse("app.apk".to_owned(), samples::demo_apk()).unwrap();

        assert_eq!(apk.warnings, Vec::<String>::new());
        assert_eq!(apk.files.len(), 4);
        assert_eq!(apk.manifest.package, "com.example.app");
        assert_eq!(apk.class_count(), 1);
        assert_eq!(apk.method_count(), 1);
        assert_eq!(apk.natives[0].abi, "arm64-v8a");
        assert_eq!(apk.native_abis(), ["arm64-v8a"]);
        assert_eq!(
            apk.manifest.launcher_activity.as_deref(),
            Some("com.example.app.MainActivity")
        );
        assert_eq!(apk.protectors, ["Qihoo 360 Jiagu"]);
        assert_eq!(apk.signing.v1_files, ["META-INF/CERT.RSA"]);
        assert!(!apk.signing.v2_or_later);
        assert_eq!(apk.read_file("META-INF/CERT.RSA").unwrap(), [1, 2, 3]);
        assert!(
            apk.strings
                .iter()
                .any(|entry| entry.value == "https://example.com/api")
        );
    }

    #[test]
    fn decodes_java_strings_through_apk_loading() {
        use std::io::Write;

        let mut dex = dex::sample::sample_dex();
        let offset = dex.len() as u32;
        dex[0x70..0x74].copy_from_slice(&offset.to_le_bytes());
        // Three UTF-16 units: embedded null followed by a surrogate pair.
        dex.extend_from_slice(&[3, 0xc0, 0x80, 0xed, 0xa0, 0xbd, 0xed, 0xb8, 0x80, 0]);
        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        writer
            .start_file("classes.dex", zip::write::SimpleFileOptions::default())
            .unwrap();
        writer.write_all(&dex).unwrap();
        let apk = Apk::parse("java.apk".to_owned(), writer.finish().unwrap().into_inner()).unwrap();
        assert_eq!(apk.strings[0].value, "\0😀");
        assert_eq!(apk.dexes[0].string(0), "\0😀");
    }

    #[test]
    fn finds_base64_in_dex_strings() {
        let apk = Apk::parse("app.apk".to_owned(), samples::demo_apk()).unwrap();
        let hit = apk.strings.iter().find(|s| s.base64.is_some()).unwrap();
        assert_eq!(hit.base64.as_deref(), Some("Hello from Euphoria"));
    }

    #[test]
    fn flags_dangerous_permissions() {
        assert!(is_dangerous_permission("android.permission.READ_SMS"));
        assert!(!is_dangerous_permission("android.permission.INTERNET"));
    }

    #[test]
    fn rejects_files_that_are_not_zips() {
        assert!(Apk::parse("x.apk".to_owned(), vec![0; 100]).is_err());
    }

    #[test]
    fn keeps_going_when_parts_of_the_apk_are_broken() {
        use std::io::Write;

        let mut writer = zip::ZipWriter::new(Cursor::new(Vec::new()));
        let options = zip::write::SimpleFileOptions::default();
        for name in ["classes.dex", "AndroidManifest.xml"] {
            writer.start_file(name, options).unwrap();
            writer.write_all(b"not valid").unwrap();
        }
        let bytes = writer.finish().unwrap().into_inner();

        let apk = Apk::parse("x.apk".to_owned(), bytes).unwrap();
        assert_eq!(apk.warnings.len(), 2);
        assert!(apk.dexes.is_empty());
    }
}
