use std::collections::BTreeMap;

use euphoria_capi::{Arch, ImageView, Section};
use object::pe::IMAGE_SCN_MEM_EXECUTE;
use object::read::pe::{ImageNtHeaders, ImageThunkData, PeFile};
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
    // Where the loader stores each imported address, so a call through one can be named.
    pub iat: BTreeMap<u64, String>,
    pub image_base: u64,
    pub is_pe: bool,
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

    pub fn add_seed(&mut self, va: u64) -> bool {
        if self.seeds.contains(&va) {
            return false;
        }
        self.seeds.push(va);
        true
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
        .flatten()
        .map(|import| {
            let library = String::from_utf8_lossy(import.library());
            match import.name() {
                NameOrOrdinal::Name(name) => {
                    format!("{library}!{}", String::from_utf8_lossy(name))
                }
                NameOrOrdinal::Ordinal(ordinal) => format!("{library}!#{ordinal}"),
            }
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

    let iat = match &file {
        object::File::Pe32(pe) => import_slots(pe),
        object::File::Pe64(pe) => import_slots(pe),
        _ => BTreeMap::new(),
    };
    let is_pe = matches!(file, object::File::Pe32(_) | object::File::Pe64(_));

    Ok(Image {
        data,
        arch,
        iat,
        image_base: file.relative_address_base(),
        is_pe,
        entry: file.entry(),
        sections,
        section_names,
        imports,
        seeds: symbols.keys().copied().collect(),
        symbols,
    })
}

fn import_slots<Pe: ImageNtHeaders>(file: &PeFile<'_, Pe>) -> BTreeMap<u64, String> {
    let mut slots = BTreeMap::new();
    let Ok(Some(table)) = file.import_table() else {
        return slots;
    };
    let Ok(mut descriptors) = table.descriptors() else {
        return slots;
    };
    let base = file.relative_address_base();
    let width = if file.is_64() { 8 } else { 4 };
    while let Ok(Some(descriptor)) = descriptors.next() {
        let library = table
            .name(descriptor.name.get(object::LittleEndian))
            .map(String::from_utf8_lossy)
            .unwrap_or_default();
        let first = descriptor.first_thunk.get(object::LittleEndian);
        let original = descriptor.original_first_thunk.get(object::LittleEndian);
        let source = if original != 0 { original } else { first };
        let Ok(mut thunks) = table.thunks(source) else {
            continue;
        };
        let mut slot = base + u64::from(first);
        while let Ok(Some(thunk)) = thunks.next::<Pe>() {
            let name = if thunk.is_ordinal() {
                format!("{library}!#{}", thunk.ordinal())
            } else {
                let name = table
                    .hint_name(thunk.address())
                    .map(|(_, name)| String::from_utf8_lossy(name).into_owned())
                    .unwrap_or_default();
                format!("{library}!{name}")
            };
            slots.insert(slot, name);
            slot += width;
        }
    }
    slots
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

    #[test]
    fn never_panics_on_damaged_images() {
        let magics: [&[u8]; 5] = [
            b"MZ",
            b"\x7fELF",
            &[0xCF, 0xFA, 0xED, 0xFE],
            &[0xCE, 0xFA, 0xED, 0xFE],
            &[0x50, 0x4B, 0x03, 0x04],
        ];
        for magic in magics {
            for length in [0, 1, 4, 8, 16, 64, 512] {
                let mut bytes = vec![0u8; length];
                let take = magic.len().min(length);
                bytes[..take].copy_from_slice(&magic[..take]);
                let _ = parse(&bytes);
            }
        }

        let data = std::fs::read(std::env::current_exe().unwrap()).unwrap();
        for length in [
            0,
            1,
            2,
            4,
            16,
            64,
            0x100,
            0x200,
            0x400,
            data.len() / 2,
            data.len() - 1,
        ] {
            let _ = parse(&data[..length.min(data.len())]);
        }
        for seed in 0..64u8 {
            let mut bytes = data[..data.len().min(2048)].to_vec();
            for (index, byte) in bytes.iter_mut().enumerate() {
                *byte ^= seed.wrapping_add(index as u8);
            }
            let _ = parse(&bytes);
        }
    }
}
