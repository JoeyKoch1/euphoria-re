use super::{LiveModule, ProcessInfo, Region, ThreadContext};

pub struct ProcessHandle;

const UNSUPPORTED: &str = "Attaching to live processes runs on 64-bit Windows for now.";

pub fn open(_pid: u32) -> Result<(ProcessHandle, bool, String), String> {
    Err(UNSUPPORTED.to_owned())
}

pub fn processes() -> Vec<ProcessInfo> {
    Vec::new()
}

pub fn modules(_pid: u32) -> Vec<LiveModule> {
    Vec::new()
}

pub fn threads(_pid: u32) -> Vec<u32> {
    Vec::new()
}

pub fn contexts(_handle: &ProcessHandle, _pid: u32) -> Vec<ThreadContext> {
    Vec::new()
}

pub fn regions(_handle: &ProcessHandle) -> Vec<Region> {
    Vec::new()
}

pub fn handle_count(_handle: &ProcessHandle) -> Option<u32> {
    None
}

pub fn is_alive(_handle: &ProcessHandle) -> bool {
    false
}

pub fn read(_handle: &ProcessHandle, _address: u64, _len: usize) -> Vec<u8> {
    Vec::new()
}

pub fn write(_handle: &ProcessHandle, _address: u64, _bytes: &[u8]) -> Result<(), String> {
    Err(UNSUPPORTED.to_owned())
}

pub fn suspend(_pid: u32) -> Result<usize, String> {
    Err(UNSUPPORTED.to_owned())
}

pub fn resume(_pid: u32) -> Result<usize, String> {
    Err(UNSUPPORTED.to_owned())
}

pub fn kill(_pid: u32) -> Result<(), String> {
    Err(UNSUPPORTED.to_owned())
}

pub fn dll_users(_name: &str) -> Vec<(ProcessInfo, LiveModule)> {
    Vec::new()
}
