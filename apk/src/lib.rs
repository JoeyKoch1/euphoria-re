mod axml;
mod dalvik;
mod dex;

use std::collections::BTreeSet;
use std::fs;
use std::io::{Cursor, Read};
use std::path::Path;
use std::sync::Arc;

use anyhow::{Context, Result};
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

            let mut bytes = Vec::new();
            if let Err(error) = (&mut entry).take(MAX_ENTRY_BYTES).read_to_end(&mut bytes) {
                apk.warnings.push(format!("{name}: {error}"));
                continue;
            }
            apk.read_entry(&name, bytes);
        }

        apk.signing.v2_or_later = has_v2_signature(&data);
        apk.find_protectors();
        apk.collect_strings();
        apk.dexes.sort_by(|a, b| a.name.cmp(&b.name));
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

    // Unpacks a run of entries by position, skipping folders and anything unreadable.
    pub fn read_files(&self, range: std::ops::Range<usize>) -> Result<Vec<(String, Vec<u8>)>> {
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        let mut files = Vec::new();
        for index in range {
            let Ok(entry) = archive.by_index(index) else {
                continue;
            };
            if entry.is_dir() {
                continue;
            }
            let Ok(name) = entry.name().map(|name| name.into_owned()) else {
                continue;
            };
            let mut bytes = Vec::new();
            if entry.take(MAX_ENTRY_BYTES).read_to_end(&mut bytes).is_ok() {
                files.push((name, bytes));
            }
        }
        Ok(files)
    }

    pub fn read_file(&self, name: &str) -> Result<Vec<u8>> {
        let mut archive = ZipArchive::new(Cursor::new(self.data.as_slice()))?;
        let entry = archive.by_name(name)?;
        let mut bytes = Vec::new();
        entry.take(MAX_ENTRY_BYTES).read_to_end(&mut bytes)?;
        Ok(bytes)
    }
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

#[cfg(test)]
pub(crate) mod test_data {
    use std::io::Write;

    use zip::ZipWriter;
    use zip::write::SimpleFileOptions;

    use crate::{axml, dex};

    pub(crate) fn sample_apk() -> Vec<u8> {
        let mut writer = ZipWriter::new(std::io::Cursor::new(Vec::new()));
        let options = SimpleFileOptions::default();
        let files: [(&str, Vec<u8>); 4] = [
            ("AndroidManifest.xml", axml::tests::sample_manifest()),
            ("classes.dex", dex::tests::sample_dex()),
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
    fn reads_a_whole_apk() {
        let apk = Apk::parse("app.apk".to_owned(), test_data::sample_apk()).unwrap();

        assert_eq!(apk.warnings, Vec::<String>::new());
        assert_eq!(apk.files.len(), 4);
        assert_eq!(apk.manifest.package, "com.example.app");
        assert_eq!(apk.class_count(), 1);
        assert_eq!(apk.method_count(), 1);
        assert_eq!(apk.natives[0].abi, "arm64-v8a");
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
    fn finds_base64_in_dex_strings() {
        let apk = Apk::parse("app.apk".to_owned(), test_data::sample_apk()).unwrap();
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
