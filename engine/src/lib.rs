pub mod dataset;
mod decode;
mod graph;
mod inspect;
mod listing;
mod patch;

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
pub use decode::{XorHit, base64_text, parse_hex, scan_xor, xor};
use euphoria_capi::Session;
pub use euphoria_capi::{Arch, Section};
pub use graph::{Block, Cfg, Edge, EdgeKind, GraphLayout, Placement, Route, layout};
pub use inspect::{
    Confidence, Detection, Inspection, PACKED_ENTROPY, SectionReport, entropy, entropy_label,
};
pub use listing::{Flow, Line, Listing, Row, StringEntry, Token, TokenKind, Xref, XrefKind};
pub use patch::Patch;
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

    fn from_bytes(
        path: &Path,
        data: Vec<u8>,
        file_name: String,
        extras: serde_json::Value,
    ) -> Result<Self> {
        let image = euphoria_formats::parse(&data)?;
        let session = Session::analyze(image.view())?;

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

    fn file_offset(&self, va: u64) -> Option<usize> {
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
