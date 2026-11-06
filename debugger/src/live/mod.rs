//! Read and edit a live process without taking it over.
//!
//! Attaching here opens a normal process handle, so the target keeps running. It never suspends
//! threads or installs a debugger, which makes it safe to inspect a program that is already doing
//! something else.

#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;
#[cfg(all(windows, target_arch = "x86_64"))]
use windows as sys;

#[cfg(not(all(windows, target_arch = "x86_64")))]
mod sys;

pub const MAX_READ: usize = 1 << 20;
pub const MAX_WRITE: usize = 1 << 20;

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ProcessInfo {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveModule {
    pub base: u64,
    pub size: u64,
    pub name: String,
    pub path: String,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ThreadContext {
    pub id: u32,
    pub ip: u64,
    pub sp: u64,
    pub bp: u64,
    pub registers: Vec<(&'static str, u64)>,
    pub error: Option<String>,
}

impl LiveModule {
    pub fn contains(&self, address: u64) -> bool {
        address >= self.base && address - self.base < self.size
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub base: u64,
    pub size: u64,
    pub state: u32,
    pub protect: u32,
    pub kind: u32,
}

impl Region {
    pub const COMMITTED: u32 = 0x1000;
    pub const PRIVATE: u32 = 0x2_0000;
    pub const MAPPED: u32 = 0x4_0000;
    pub const IMAGE: u32 = 0x100_0000;

    pub fn committed(&self) -> bool {
        self.state & Self::COMMITTED != 0
    }

    pub fn executable(&self) -> bool {
        matches!(self.protect & 0xFF, 0x10 | 0x20 | 0x40 | 0x80)
    }

    pub fn guard(&self) -> bool {
        self.protect & 0x100 != 0
    }

    pub fn private(&self) -> bool {
        self.kind == Self::PRIVATE
    }

    pub fn image(&self) -> bool {
        self.kind == Self::IMAGE
    }

    pub fn mapped(&self) -> bool {
        self.kind == Self::MAPPED
    }

    pub fn protection(&self) -> &'static str {
        match self.protect & 0xFF {
            0x01 => "no access",
            0x02 => "read",
            0x04 => "read/write",
            0x08 => "write copy",
            0x10 => "execute",
            0x20 => "execute/read",
            0x40 => "execute/read/write",
            0x80 => "execute/write copy",
            _ => "other",
        }
    }
}

// Consecutive pages with the same attributes are easier to read as one span.
pub fn merge_regions(regions: Vec<Region>) -> Vec<Region> {
    let mut merged: Vec<Region> = Vec::with_capacity(regions.len());
    for region in regions {
        if let Some(last) = merged.last_mut()
            && last.base.saturating_add(last.size) == region.base
            && last.state == region.state
            && last.protect == region.protect
            && last.kind == region.kind
        {
            last.size = last.size.saturating_add(region.size);
            continue;
        }
        merged.push(region);
    }
    merged
}

pub fn basename(path: &str) -> &str {
    path.rsplit(['\\', '/'])
        .next()
        .filter(|name| !name.is_empty())
        .unwrap_or(path)
}

pub fn find_module(modules: &[LiveModule], name: &str) -> Option<usize> {
    let query = name.trim();
    if query.is_empty() {
        return None;
    }
    modules
        .iter()
        .position(|module| {
            module.name.eq_ignore_ascii_case(query) || module.path.eq_ignore_ascii_case(query)
        })
        .or_else(|| {
            let query = query.to_ascii_lowercase();
            let matches: Vec<usize> = modules
                .iter()
                .enumerate()
                .filter(|(_, module)| {
                    module.path.to_ascii_lowercase().ends_with(&query)
                        || module.name.to_ascii_lowercase().ends_with(&query)
                })
                .map(|(index, _)| index)
                .collect();
            (matches.len() == 1).then(|| matches[0])
        })
}

pub fn module_at(modules: &[LiveModule], address: u64) -> Option<usize> {
    modules.iter().position(|module| module.contains(address))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Target {
    pub module: Option<usize>,
    pub address: u64,
}

// Accepts `module.dll+0x1234`, a module name by itself, or an absolute address.
pub fn resolve_target(modules: &[LiveModule], text: &str) -> Result<Target, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("Enter an address such as game.exe+0x1234".to_owned());
    }
    if let Some((name, offset)) = text.split_once('+') {
        let index = find_module(modules, name)
            .ok_or_else(|| format!("No loaded module called {}", name.trim()))?;
        let module = &modules[index];
        let offset = parse_hex(offset.trim())?;
        let address = module
            .base
            .checked_add(offset)
            .ok_or_else(|| "That offset is too large".to_owned())?;
        if !module.contains(address) {
            return Err(format!(
                "{}+{offset:#x} is outside {}, which is {} bytes",
                module.name, module.name, module.size
            ));
        }
        return Ok(Target {
            module: Some(index),
            address,
        });
    }

    if let Some(index) = find_module(modules, text) {
        return Ok(Target {
            module: Some(index),
            address: modules[index].base,
        });
    }

    let address = parse_hex(text)?;
    Ok(Target {
        module: module_at(modules, address),
        address,
    })
}

pub fn parse_hex(text: &str) -> Result<u64, String> {
    let digits: String = text
        .trim()
        .trim_start_matches("0x")
        .trim_start_matches("0X")
        .chars()
        .filter(|&c| c != '_')
        .collect();
    if digits.is_empty() {
        return Err("Enter a hexadecimal number".to_owned());
    }
    u64::from_str_radix(&digits, 16).map_err(|_| format!("'{digits}' is not a hexadecimal number"))
}

pub struct LiveProcess {
    pid: u32,
    name: String,
    path: String,
    writable: bool,
    modules: Vec<LiveModule>,
    handle: sys::ProcessHandle,
}

impl LiveProcess {
    pub fn open(pid: u32) -> Result<Self, String> {
        let (handle, writable, path) = sys::open(pid)?;
        let name = basename(&path).to_owned();
        let name = if name.is_empty() {
            format!("process {pid}")
        } else {
            name
        };
        let mut process = Self {
            pid,
            name,
            path,
            writable,
            modules: Vec::new(),
            handle,
        };
        process.refresh_modules();
        Ok(process)
    }

    pub fn pid(&self) -> u32 {
        self.pid
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub fn writable(&self) -> bool {
        self.writable
    }

    pub fn modules(&self) -> &[LiveModule] {
        &self.modules
    }

    pub fn refresh_modules(&mut self) {
        self.modules = sys::modules(self.pid);
    }

    pub fn threads(&self) -> Vec<u32> {
        sys::threads(self.pid)
    }

    // Each thread is suspended, read, and resumed while this call runs.
    pub fn contexts(&self) -> Vec<ThreadContext> {
        sys::contexts(&self.handle, self.pid)
    }

    // The target keeps running between calls; these are the only actions that change that.
    pub fn suspend(&self) -> Result<usize, String> {
        sys::suspend(self.pid)
    }

    pub fn resume(&self) -> Result<usize, String> {
        sys::resume(self.pid)
    }

    pub fn kill(&self) -> Result<(), String> {
        sys::kill(self.pid)
    }

    pub fn regions(&self) -> Vec<Region> {
        sys::regions(&self.handle)
    }

    pub fn handle_count(&self) -> Option<u32> {
        sys::handle_count(&self.handle)
    }

    pub fn is_alive(&self) -> bool {
        sys::is_alive(&self.handle)
    }

    pub fn read(&self, address: u64, len: usize) -> Vec<u8> {
        sys::read(&self.handle, address, len.min(MAX_READ))
    }

    pub fn write(&self, address: u64, bytes: &[u8]) -> Result<(), String> {
        if bytes.is_empty() {
            return Ok(());
        }
        if !self.writable {
            return Err(
                "This process was opened read-only, so memory cannot be changed".to_owned(),
            );
        }
        if bytes.len() > MAX_WRITE {
            return Err(format!("Writes are limited to {MAX_WRITE} bytes"));
        }
        sys::write(&self.handle, address, bytes)
    }
}

pub fn processes() -> Vec<ProcessInfo> {
    sys::processes()
}

pub fn process_by_name(name: &str) -> Option<ProcessInfo> {
    processes()
        .into_iter()
        .find(|process| process.name.eq_ignore_ascii_case(name))
}

// Every process that currently has a module with this file name loaded.
pub fn dll_users(name: &str) -> Vec<(ProcessInfo, LiveModule)> {
    sys::dll_users(name)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn modules() -> Vec<LiveModule> {
        vec![
            LiveModule {
                base: 0x1_4000_0000,
                size: 0x1000,
                name: "game.exe".into(),
                path: r"C:\Games\game.exe".into(),
            },
            LiveModule {
                base: 0x7FF8_0000_0000,
                size: 0x20_0000,
                name: "kernel32.dll".into(),
                path: r"C:\Windows\System32\kernel32.dll".into(),
            },
            LiveModule {
                base: 0x7FF8_0010_0000,
                size: 0x1000,
                name: "notes.dll".into(),
                path: r"C:\Tools\notes.dll".into(),
            },
        ]
    }

    #[test]
    fn resolves_module_offsets_and_absolute_addresses() {
        let list = modules();
        let target = resolve_target(&list, "game.exe+0x120").unwrap();
        assert_eq!(target.module, Some(0));
        assert_eq!(target.address, 0x1_4000_0120);

        let absolute = resolve_target(&list, "0x7ff800000100").unwrap();
        assert_eq!(absolute.module, Some(1));
        assert_eq!(absolute.address, 0x7FF8_0000_0100);

        let base_only = resolve_target(&list, "notes.dll").unwrap();
        assert_eq!(base_only.address, 0x7FF8_0010_0000);
    }

    #[test]
    fn rejects_offsets_outside_the_module() {
        assert!(resolve_target(&modules(), "game.exe+0x2000").is_err());
        assert!(resolve_target(&modules(), "missing.dll+0").is_err());
        assert!(resolve_target(&modules(), "not a number").is_err());
    }

    #[test]
    fn finds_modules_by_name_or_path_suffix() {
        let list = modules();
        assert_eq!(find_module(&list, "KERNEL32.DLL"), Some(1));
        assert_eq!(
            find_module(&list, r"C:\Windows\System32\kernel32.dll"),
            Some(1)
        );
        assert_eq!(find_module(&list, "ystem32\\kernel32.dll"), Some(1));
        assert_eq!(find_module(&list, "nothing.dll"), None);
    }

    #[test]
    fn merges_only_adjacent_regions_with_matching_attributes() {
        let region = |base, size, protect| Region {
            base,
            size,
            state: Region::COMMITTED,
            protect,
            kind: Region::PRIVATE,
        };
        let merged = merge_regions(vec![
            region(0x1000, 0x1000, 0x04),
            region(0x2000, 0x1000, 0x04),
            region(0x3000, 0x1000, 0x20),
            region(0x5000, 0x1000, 0x20),
        ]);
        assert_eq!(merged.len(), 3);
        assert_eq!(merged[0].size, 0x2000);
        assert_eq!(merged[1].protect, 0x20);
        assert_eq!(merged[2].base, 0x5000);
    }

    #[test]
    fn parses_hex_with_prefixes_and_separators() {
        assert_eq!(parse_hex("0x1_0000"), Ok(0x1_0000));
        assert_eq!(parse_hex("FF"), Ok(0xFF));
        assert!(parse_hex("").is_err());
        assert!(parse_hex("zz").is_err());
    }

    #[test]
    fn names_the_basename_of_windows_and_unix_paths() {
        assert_eq!(
            basename(r"C:\Windows\System32\kernel32.dll"),
            "kernel32.dll"
        );
        assert_eq!(basename("/usr/lib/libc.so"), "libc.so");
        assert_eq!(basename(""), "");
    }
}
