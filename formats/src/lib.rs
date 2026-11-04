use std::collections::BTreeMap;

use euphoria_capi::{Arch, ImageView, Section};
use object::pe::IMAGE_SCN_MEM_EXECUTE;
use object::{
    Architecture, ExportTarget, NameOrOrdinal, Object, ObjectSection, ObjectSymbol, SectionFlags,
    SectionKind,
};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("not a readable binary: {0}")]
    Malformed(#[from] object::Error),
    #[error("unsupported architecture: {0:?}")]
    UnsupportedArch(Architecture),
}

pub struct Image<'a> {
    pub data: &'a [u8],
    pub arch: Arch,
    pub entry: u64,
    pub sections: Vec<Section>,
    pub section_names: Vec<String>,
    pub imports: Vec<String>,
    pub symbols: BTreeMap<u64, String>,
    seeds: Vec<u64>,
}

impl Image<'_> {
    pub fn view(&self) -> ImageView<'_> {
        ImageView {
            arch: self.arch,
            entry: self.entry,
            data: self.data,
            sections: &self.sections,
            seeds: &self.seeds,
        }
    }
}

pub fn parse(data: &[u8]) -> Result<Image<'_>, Error> {
    let file = object::File::parse(data)?;

    let arch = match file.architecture() {
        Architecture::X86_64 => Arch::X86_64,
        Architecture::Aarch64 => Arch::Aarch64,
        Architecture::I386 => Arch::X86,
        other => return Err(Error::UnsupportedArch(other)),
    };

    let sections = file
        .sections()
        .map(|section| {
            let (offset, size) = section.file_range().unwrap_or((0, 0));
            Section {
                va: section.address(),
                offset,
                size,
                executable: is_executable(&section),
            }
        })
        .collect();

    let section_names = file
        .sections()
        .map(|section| section.name().unwrap_or_default().to_owned())
        .collect();
    let imports = file
        .imports()
        .into_iter()
        .flatten()
        .map(|import| {
            format!(
                "{}!{}",
                String::from_utf8_lossy(import.library()),
                String::from_utf8_lossy(import.name())
            )
        })
        .collect();

    let mut symbols = BTreeMap::new();
    for symbol in file.symbols().chain(file.dynamic_symbols()) {
        if symbol.is_definition()
            && symbol.kind() == object::SymbolKind::Text
            && let Ok(name) = symbol.name()
        {
            symbols.insert(symbol.address(), name.to_owned());
        }
    }
    for export in file.exports().into_iter().flatten().flatten() {
        if let (ExportTarget::Address { address }, NameOrOrdinal::Name(name)) =
            (export.target(), export.name())
        {
            symbols
                .entry(address)
                .or_insert_with(|| String::from_utf8_lossy(name).into_owned());
        }
    }

    Ok(Image {
        data,
        arch,
        entry: file.entry(),
        sections,
        section_names,
        imports,
        seeds: symbols.keys().copied().collect(),
        symbols,
    })
}

fn is_executable<'data>(section: &impl ObjectSection<'data>) -> bool {
    let code_flag = matches!(
        section.flags(),
        SectionFlags::Coff { characteristics }
            if characteristics & IMAGE_SCN_MEM_EXECUTE == IMAGE_SCN_MEM_EXECUTE
    );
    section.kind() == SectionKind::Text || code_flag
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_the_running_test_binary() {
        let data = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        let image = parse(&data).unwrap();

        assert_eq!(image.arch, Arch::X86_64);
        assert!(
            image
                .sections
                .iter()
                .any(|s| s.executable && image.entry >= s.va && image.entry - s.va < s.size)
        );
    }

    #[test]
    fn rejects_garbage() {
        assert!(matches!(parse(&[0u8; 64]), Err(Error::Malformed(_))));
    }
}
