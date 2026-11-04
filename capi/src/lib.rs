mod abi;

use std::ffi::{CString, NulError};
use std::path::Path;
use std::ptr::{self, NonNull};
use std::slice;

pub use abi::{EU_ABI_VERSION, EuArch as Arch, EuFunction as Function, EuSection as Section};
use abi::{EuImage, EuSession, EuStatus};

#[derive(Debug, thiserror::Error)]
pub enum Error {
    #[error("invalid argument passed to the native core")]
    InvalidArgument,
    #[error("the native core ran out of memory")]
    OutOfMemory,
    #[error("the native core could not read or write a file")]
    Io,
    #[error("internal error in the native core")]
    Internal,
    #[error("path contains a nul byte")]
    Path(#[from] NulError),
}

fn check(status: EuStatus) -> Result<(), Error> {
    match status {
        EuStatus::Ok => Ok(()),
        EuStatus::InvalidArgument => Err(Error::InvalidArgument),
        EuStatus::OutOfMemory => Err(Error::OutOfMemory),
        EuStatus::Io => Err(Error::Io),
        EuStatus::Internal => Err(Error::Internal),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct ImageView<'a> {
    pub arch: Arch,
    pub entry: u64,
    pub data: &'a [u8],
    pub sections: &'a [Section],
    pub seeds: &'a [u64],
}

pub struct Session(NonNull<EuSession>);

impl Session {
    pub fn analyze(image: ImageView<'_>) -> Result<Self, Error> {
        let raw = EuImage {
            arch: image.arch,
            entry: image.entry,
            data: image.data.as_ptr(),
            data_len: image.data.len(),
            sections: image.sections.as_ptr(),
            section_count: image.sections.len(),
            seeds: image.seeds.as_ptr(),
            seed_count: image.seeds.len(),
        };

        let mut out = ptr::null_mut();
        check(unsafe { abi::eu_session_analyze(&raw, &mut out) })?;
        NonNull::new(out).map(Self).ok_or(Error::Internal)
    }

    pub fn functions(&self) -> &[Function] {
        let mut count = 0;
        let data = unsafe { abi::eu_session_functions(self.0.as_ptr(), &mut count) };
        if count == 0 {
            return &[];
        }
        unsafe { slice::from_raw_parts(data, count) }
    }

    pub fn save(&self, path: &Path) -> Result<(), Error> {
        let path = CString::new(path.as_os_str().as_encoded_bytes())?;
        check(unsafe { abi::eu_session_save(self.0.as_ptr(), path.as_ptr()) })
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        unsafe { abi::eu_session_free(self.0.as_ptr()) }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROLOGUE: [u8; 4] = [0x55, 0x48, 0x89, 0xE5];

    fn analyze(data: &[u8], sections: &[Section], seeds: &[u64], entry: u64) -> Vec<Function> {
        Session::analyze(ImageView {
            arch: Arch::X86_64,
            entry,
            data,
            sections,
            seeds,
        })
        .unwrap()
        .functions()
        .to_vec()
    }

    fn text(size: u64) -> Section {
        Section {
            va: 0x1000,
            offset: 0,
            size,
            executable: true,
        }
    }

    #[test]
    fn finds_entry_seeds_and_prologues_and_sizes_them() {
        let mut data = vec![0x90; 0x80];
        data[0x10..0x14].copy_from_slice(&PROLOGUE);
        data[0x40..0x44].copy_from_slice(&PROLOGUE);

        let functions = analyze(&data, &[text(0x80)], &[0x1060], 0x1000);

        let expected = [
            (0x1000, 0x10),
            (0x1010, 0x30),
            (0x1040, 0x20),
            (0x1060, 0x20),
        ]
        .map(|(va, size)| Function { va, size });
        assert_eq!(functions, expected);
    }

    #[test]
    fn finds_both_32_bit_prologues() {
        let mut data = vec![0x90; 0x40];
        data[0x10..0x13].copy_from_slice(&[0x55, 0x8B, 0xEC]);
        data[0x20..0x23].copy_from_slice(&[0x55, 0x89, 0xE5]);

        let functions = Session::analyze(ImageView {
            arch: Arch::X86,
            entry: 0x1000,
            data: &data,
            sections: &[text(0x40)],
            seeds: &[],
        })
        .unwrap();
        let starts: Vec<u64> = functions.functions().iter().map(|f| f.va).collect();
        assert_eq!(starts, [0x1000, 0x1010, 0x1020]);
    }

    #[test]
    fn ignores_addresses_outside_executable_sections() {
        let functions = analyze(&[0x90; 0x10], &[text(0x10)], &[0x5000, 0xFFF], 0x1010);
        assert!(functions.is_empty());
    }

    #[test]
    fn survives_a_section_that_points_past_the_file() {
        let section = Section {
            va: 0x1000,
            offset: 0x1000,
            size: u64::MAX,
            executable: true,
        };
        assert!(analyze(&[0x90; 0x10], &[section], &[], 0).is_empty());
    }
}
