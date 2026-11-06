pub mod dataset;
mod decode;
pub mod euphp;
mod graph;
mod inspect;
mod listing;
mod patch;
pub mod search;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result, bail};
pub use decode::{XorHit, base64_text, parse_hex, scan_xor, xor};
use euphoria_capi::Session;
pub use euphoria_capi::{Arch, Section};
pub use graph::{Block, Cfg, Edge, EdgeKind, GraphLayout, Placement, Route, layout};
use iced_x86::{Decoder, DecoderOptions, FlowControl, OpKind};
pub use inspect::{
    Confidence, Detection, Inspection, Overview, PACKED_ENTROPY, RoutineSummary, SectionReport,
    entropy, entropy_label, overview,
};
pub use listing::{Flow, Line, Listing, Row, StringEntry, Token, TokenKind, Xref, XrefKind};
pub use patch::Patch;
pub use search::{ByteMatch, Pattern};
use serde::Serialize;

#[derive(Clone, Debug, Serialize)]
pub struct Function {
    pub va: u64,
    pub size: u64,
    pub name: Option<String>,
}

#[derive(Serialize)]
pub struct Analysis {
    pub path: PathBuf,
    pub arch: Arch,
    pub entry: u64,
    pub sections: Vec<Section>,
    pub functions: Vec<Function>,
    pub section_names: Vec<String>,
    pub import_count: usize,
    pub imports: Vec<String>,
    pub iat: BTreeMap<u64, String>,
    pub image_base: u64,
    pub is_pe: bool,
    pub file_name: String,
    pub sha256: String,
    #[serde(skip)]
    pub extras: serde_json::Value,
    #[serde(skip)]
    pub data: Arc<Vec<u8>>,
}

impl Analysis {
    pub fn open(path: &Path) -> Result<Self> {
        let contents = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        if dataset::is_dataset(&contents) {
            let (meta, bytes) = dataset::read(&contents)?;
            return Self::from_bytes(path, bytes, meta.file_name, meta.extras);
        }

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        Self::from_bytes(path, contents, file_name, serde_json::Value::Null)
    }

    // Loads a module from its file on disk, rewrites the preferred image base to where the module
    // is loaded in a live process, and copies each section's bytes from that process so listing
    // and decompilation see the code that is actually mapped, not the older file.
    pub fn open_live<F>(path: &Path, image_base: u64, read: F) -> Result<Self>
    where
        F: Fn(u64, usize) -> Vec<u8>,
    {
        let contents = fs::read(path).with_context(|| format!("cannot read {}", path.display()))?;
        let mut data = rebase_pe(contents, image_base)
            .with_context(|| format!("{} is not a PE image", path.display()))?;
        {
            let image = euphoria_formats::parse(&data)?;
            for section in &image.sections {
                let size = usize::try_from(section.size).unwrap_or(usize::MAX);
                let offset = usize::try_from(section.offset).unwrap_or(usize::MAX);
                if size == 0 || offset >= data.len() {
                    continue;
                }
                let available = size.min(data.len() - offset);
                let mapped = read(section.va, available);
                let copied = mapped.len().min(available);
                if copied > 0 {
                    data[offset..offset + copied].copy_from_slice(&mapped[..copied]);
                }
            }
        }

        let file_name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        Self::from_bytes(path, data, file_name, serde_json::Value::Null)
    }

    fn from_bytes(
        path: &Path,
        data: Vec<u8>,
        file_name: String,
        extras: serde_json::Value,
    ) -> Result<Self> {
        let mut image = euphoria_formats::parse(&data)?;
        let mut session = Session::analyze(image.view())?;
        if let Some(bits) = decoder_bits(image.arch) {
            for _ in 0..MAX_SEED_PASSES {
                let functions: Vec<(u64, u64)> = session
                    .functions()
                    .iter()
                    .map(|function| (function.va, function.size))
                    .collect();
                if discover_seeds(&data, &mut image, &functions, bits) == 0 {
                    break;
                }
                session = Session::analyze(image.view())?;
            }
        }

        let functions = session
            .functions()
            .iter()
            .map(|function| Function {
                va: function.va,
                size: function.size,
                name: image.symbols.get(&function.va).cloned(),
            })
            .collect();

        Ok(Self {
            path: path.to_owned(),
            arch: image.arch,
            entry: image.entry,
            functions,
            sections: image.sections,
            section_names: image.section_names,
            import_count: image.imports.len(),
            imports: image.imports,
            iat: image.iat,
            image_base: image.image_base,
            is_pe: image.is_pe,
            file_name,
            sha256: dataset::sha256_hex(&data),
            extras,
            data: Arc::new(data),
        })
    }

    // Saves the whole program plus `extras`, so the dataset reopens without the original file.
    pub fn save_dataset(&self, path: &Path, extras: serde_json::Value) -> Result<u64> {
        let meta = dataset::Meta {
            file_name: self.file_name.clone(),
            sha256: self.sha256.clone(),
            extras,
        };
        dataset::write(&path.with_extension(dataset::EXTENSION), &meta, &self.data)
    }

    pub fn inspect(&self) -> Inspection {
        inspect::inspect(
            &self.data,
            self.entry,
            &self.sections,
            &self.section_names,
            self.import_count,
        )
    }

    pub fn file_offset(&self, va: u64) -> Option<usize> {
        let section = self
            .sections
            .iter()
            .find(|s| va >= s.va && va - s.va < s.size)?;
        usize::try_from(section.offset + (va - section.va)).ok()
    }

    // Plans an edit that redirects the string at `va` to `replacement`, for example a URL pointed
    // at the local emulator. The edit applies only to a saved copy, never to the original file.
    pub fn plan_patch(&self, va: u64, original_len: usize, replacement: &str) -> Result<Patch> {
        let offset = self
            .file_offset(va)
            .context("that address is not inside a stored section")?;
        patch::plan(&self.data, va, offset, original_len, replacement.as_bytes())
    }

    pub fn save_patched(&self, path: &Path, patches: &[Patch]) -> Result<()> {
        let mut data = (*self.data).clone();
        patch::apply(&mut data, patches)?;
        patch::save_copy(&self.path, path, &data)
    }

    pub fn read(&self, va: u64, len: usize) -> Option<&[u8]> {
        let section = self
            .sections
            .iter()
            .find(|s| va >= s.va && va - s.va < s.size)?;
        let start = usize::try_from(section.offset + (va - section.va)).ok()?;
        let available = usize::try_from(section.size - (va - section.va)).ok()?;
        let end = start
            .saturating_add(len.min(available))
            .min(self.data.len());
        self.data.get(start..end)
    }

    pub fn search(&self, pattern: &Pattern, limit: usize) -> Vec<ByteMatch> {
        search::find(&self.data, &self.sections, pattern, limit)
    }

    pub fn function_containing(&self, va: u64) -> Option<&Function> {
        let index = self
            .functions
            .partition_point(|f| f.va <= va)
            .checked_sub(1)?;
        let function = &self.functions[index];
        (va - function.va < function.size).then_some(function)
    }

    pub fn resolve(&self, target: &str) -> Option<u64> {
        let hex = target.strip_prefix("0x").unwrap_or(target);
        u64::from_str_radix(hex, 16).ok().or_else(|| {
            self.functions
                .iter()
                .find(|function| function.name.as_deref() == Some(target))
                .map(|function| function.va)
        })
    }

    pub fn listing(&self) -> Listing {
        Listing::build(&self.data, self.arch, &self.sections, &self.functions)
    }

    pub fn iat_name_is(&self, name: &str) -> bool {
        self.iat.values().any(|import| import == name)
    }

    pub fn is_read_only(&self, va: u64) -> bool {
        self.sections
            .iter()
            .zip(&self.section_names)
            .find(|(section, _)| va >= section.va && va - section.va < section.size)
            .is_some_and(|(_, name)| name.contains("rdata") || name.contains("rodata"))
    }

    pub fn function_at(&self, va: u64) -> Option<&Function> {
        let index = self.functions.binary_search_by_key(&va, |f| f.va).ok()?;
        Some(&self.functions[index])
    }
}

const MAX_SEED_PASSES: usize = 3;
const MAX_DISCOVERED_SEEDS: usize = 8192;
const MAX_SCAN_BYTES: u64 = 1 << 20;

fn decoder_bits(arch: Arch) -> Option<u32> {
    match arch {
        Arch::X86_64 => Some(64),
        Arch::X86 => Some(32),
        Arch::Aarch64 => None,
    }
}

fn code_at<'a>(data: &'a [u8], sections: &[Section], va: u64, len: usize) -> Option<&'a [u8]> {
    let section = sections
        .iter()
        .find(|section| va >= section.va && va - section.va < section.size)?;
    let start = usize::try_from(section.offset + (va - section.va)).ok()?;
    let available = usize::try_from(section.size - (va - section.va)).ok()?;
    let end = start.checked_add(len.min(available))?.min(data.len());
    data.get(start..end)
}

fn is_executable(sections: &[Section], va: u64) -> bool {
    sections
        .iter()
        .any(|section| section.executable && va >= section.va && va - section.va < section.size)
}

fn call_targets(
    data: &[u8],
    sections: &[Section],
    bits: u32,
    start: u64,
    size: u64,
    seeds: &mut Vec<u64>,
) {
    let size = size.min(MAX_SCAN_BYTES);
    let Some(bytes) = code_at(
        data,
        sections,
        start,
        usize::try_from(size).unwrap_or(usize::MAX),
    ) else {
        return;
    };
    let end = start.saturating_add(size);
    let mut decoder = Decoder::with_ip(bits, bytes, start, DecoderOptions::NONE);
    while decoder.can_decode() {
        let instruction = decoder.decode();
        if instruction.ip() >= end || instruction.is_invalid() {
            break;
        }
        if instruction.flow_control() != FlowControl::Call {
            continue;
        }
        if !matches!(
            instruction.op0_kind(),
            OpKind::NearBranch64 | OpKind::NearBranch32
        ) {
            continue;
        }
        let target = instruction.near_branch_target();
        // A direct call target is a routine start even when a prologue scan has already put it
        // inside a larger, wrongly sized range. Otherwise one false prologue can swallow every
        // callee that follows it in a stripped binary.
        if is_executable(sections, target) {
            seeds.push(target);
        }
    }
}

fn discover_seeds(
    data: &[u8],
    image: &mut euphoria_formats::Image<'_>,
    functions: &[(u64, u64)],
    bits: u32,
) -> usize {
    let mut found = Vec::new();
    for &(start, size) in functions {
        call_targets(data, &image.sections, bits, start, size, &mut found);
        if found.len() >= MAX_DISCOVERED_SEEDS {
            break;
        }
    }
    found.sort_unstable();
    found.dedup();

    let mut added = 0;
    for seed in found {
        if image.add_seed(seed) {
            added += 1;
            if added >= MAX_DISCOVERED_SEEDS {
                break;
            }
        }
    }
    added
}

// A mapped module sits at a different base than its file's preferred base. Rewriting the PE
// optional header is enough for every address the analysis reports to match the live process.
fn rebase_pe(mut data: Vec<u8>, image_base: u64) -> Result<Vec<u8>> {
    let pe_offset = u32_at(&data, 0x3C).context("the DOS header has no PE offset")? as usize;
    let signature = data
        .get(pe_offset..pe_offset + 4)
        .context("the PE offset points outside the file")?;
    if signature != b"PE\0\0" {
        bail!("no PE signature");
    }
    let optional = pe_offset + 4 + 20;
    match u16_at(&data, optional).context("the optional header is missing")? {
        0x10B => {
            let base =
                u32::try_from(image_base).context("a 32-bit module cannot be loaded above 4 GB")?;
            write_at(&mut data, optional + 28, &base.to_le_bytes())?;
        }
        0x20B => write_at(&mut data, optional + 24, &image_base.to_le_bytes())?,
        other => bail!("unsupported optional header magic {other:#x}"),
    }
    Ok(data)
}

fn u16_at(data: &[u8], at: usize) -> Option<u16> {
    let bytes = data.get(at..at.checked_add(2)?)?;
    Some(u16::from_le_bytes([bytes[0], bytes[1]]))
}

fn u32_at(data: &[u8], at: usize) -> Option<u32> {
    let bytes = data.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
}

fn write_at(data: &mut [u8], at: usize, bytes: &[u8]) -> Result<()> {
    let end = at
        .checked_add(bytes.len())
        .context("header offset overflow")?;
    let target = data.get_mut(at..end).context("the header is truncated")?;
    target.copy_from_slice(bytes);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pe_stub(magic: u16, base: u64) -> Vec<u8> {
        let pe = 0x80usize;
        let optional = pe + 4 + 20;
        let mut data = vec![0u8; 0x200];
        data[0x3C..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        data[pe..pe + 4].copy_from_slice(b"PE\0\0");
        data[optional..optional + 2].copy_from_slice(&magic.to_le_bytes());
        if magic == 0x20B {
            data[optional + 24..optional + 32].copy_from_slice(&base.to_le_bytes());
        } else {
            data[optional + 28..optional + 32].copy_from_slice(&(base as u32).to_le_bytes());
        }
        data
    }

    #[test]
    fn rebases_32_and_64_bit_pe_headers() {
        let rebased = rebase_pe(pe_stub(0x20B, 0x1_4000_0000), 0x7FF6_1234_0000).unwrap();
        assert_eq!(
            u64::from_le_bytes(rebased[0x80 + 24 + 24..0x80 + 24 + 32].try_into().unwrap()),
            0x7FF6_1234_0000
        );

        let rebased = rebase_pe(pe_stub(0x10B, 0x0040_0000), 0x1000_0000).unwrap();
        assert_eq!(
            u32::from_le_bytes(rebased[0x80 + 24 + 28..0x80 + 24 + 32].try_into().unwrap()),
            0x1000_0000
        );
    }

    #[test]
    fn rejects_files_that_are_not_pe_images() {
        assert!(rebase_pe(vec![0; 64], 0x1000).is_err());
        let mut stub = pe_stub(0x20B, 0x1_4000_0000);
        stub[0x80..0x84].copy_from_slice(b"NOPE");
        assert!(rebase_pe(stub, 0x1000).is_err());
    }

    #[test]
    fn survives_damaged_binaries() {
        let data =
            std::fs::read(Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/hello.exe"))
                .unwrap();
        let dir = std::env::temp_dir().join(format!("euphoria_damaged_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();

        let lengths = [
            0usize,
            1,
            2,
            4,
            16,
            64,
            0x100,
            0x400,
            0x1000,
            data.len() / 2,
            data.len() - 1,
        ];
        for length in lengths {
            let path = dir.join(format!("truncated_{length}.exe"));
            std::fs::write(&path, &data[..length.min(data.len())]).unwrap();
            let opened = Analysis::open(&path);
            if length <= 64 {
                assert!(opened.is_err(), "accepted a {length}-byte image");
            }
        }

        for offset in (0..0x100).chain([0x200, 0x400, data.len() / 2, data.len() - 1]) {
            let mut damaged = data.clone();
            damaged[offset] ^= 0xFF;
            let path = dir.join(format!("flipped_{offset}.exe"));
            std::fs::write(&path, &damaged).unwrap();
            let _ = Analysis::open(&path);
        }

        std::fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn overlays_mapped_section_bytes_over_the_file_image() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("../samples/hello.exe");
        let plain = Analysis::open(&path).unwrap();
        let live_base = 0x7FF6_0000_0000u64;
        let live = Analysis::open_live(&path, live_base, |_, len| vec![0xCC; len]).unwrap();

        assert_eq!(
            live.entry.wrapping_sub(plain.entry),
            live_base.wrapping_sub(plain.image_base)
        );
        let section = live
            .sections
            .iter()
            .find(|section| section.executable && section.size > 0)
            .unwrap();
        let offset = usize::try_from(section.offset).unwrap();
        assert_eq!(live.data[offset], 0xCC);
    }
}
