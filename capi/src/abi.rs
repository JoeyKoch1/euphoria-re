use std::ffi::c_char;

use serde::Serialize;

pub const EU_ABI_VERSION: u32 = 1;

#[repr(C)]
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EuStatus {
    Ok,
    InvalidArgument,
    OutOfMemory,
    Io,
    Internal,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EuArch {
    X86_64,
    Aarch64,
    X86,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct EuSection {
    pub va: u64,
    pub offset: u64,
    pub size: u64,
    pub executable: bool,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EuFunction {
    pub va: u64,
    pub size: u64,
}

#[repr(C)]
pub struct EuImage {
    pub arch: EuArch,
    pub entry: u64,
    pub data: *const u8,
    pub data_len: usize,
    pub sections: *const EuSection,
    pub section_count: usize,
    pub seeds: *const u64,
    pub seed_count: usize,
}

pub struct EuSession;

#[allow(improper_ctypes)]
unsafe extern "C" {
    pub fn eu_session_analyze(image: *const EuImage, out: *mut *mut EuSession) -> EuStatus;
    pub fn eu_session_functions(session: *const EuSession, count: *mut usize) -> *const EuFunction;
    pub fn eu_session_save(session: *const EuSession, path: *const c_char) -> EuStatus;
    pub fn eu_session_free(session: *mut EuSession);
}
