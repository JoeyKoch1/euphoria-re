use std::ffi::c_void;
use std::io;
use std::mem;

use windows_sys::Win32::Foundation::{CloseHandle, GetLastError, HANDLE, INVALID_HANDLE_VALUE};
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, FlushInstructionCache, GetThreadContext, ReadProcessMemory, WOW64_CONTEXT,
    Wow64GetThreadContext, WriteProcessMemory,
};
use windows_sys::Win32::System::Diagnostics::ToolHelp::{
    CreateToolhelp32Snapshot, MODULEENTRY32W, Module32FirstW, Module32NextW, PROCESSENTRY32W,
    Process32FirstW, Process32NextW, TH32CS_SNAPMODULE, TH32CS_SNAPMODULE32, TH32CS_SNAPPROCESS,
    TH32CS_SNAPTHREAD, THREADENTRY32, Thread32First, Thread32Next,
};
use windows_sys::Win32::System::Memory::{MEMORY_BASIC_INFORMATION, VirtualQueryEx};
use windows_sys::Win32::System::Threading::{
    GetExitCodeProcess, GetProcessHandleCount, IsWow64Process, OpenProcess, OpenThread,
    PROCESS_NAME_WIN32, PROCESS_QUERY_INFORMATION, PROCESS_QUERY_LIMITED_INFORMATION,
    PROCESS_TERMINATE, PROCESS_VM_OPERATION, PROCESS_VM_READ, PROCESS_VM_WRITE,
    QueryFullProcessImageNameW, ResumeThread, SuspendThread, THREAD_GET_CONTEXT,
    THREAD_QUERY_INFORMATION, THREAD_SUSPEND_RESUME, TerminateProcess,
};

use super::{LiveModule, ProcessInfo, Region, ThreadContext, basename, merge_regions};

const ERROR_BAD_LENGTH: u32 = 24;
const IMAGE_BUFFER: usize = 1024;
const STILL_ACTIVE: u32 = 259;
const CONTEXT_FLAGS_64: u32 = 0x0010_0003;
const CONTEXT_FLAGS_32: u32 = 0x0001_0007;

// GetThreadContext wants a CONTEXT that is aligned for its vector registers.
#[repr(align(16))]
struct AlignedContext(CONTEXT);

pub struct ProcessHandle(HANDLE);

impl Drop for ProcessHandle {
    fn drop(&mut self) {
        unsafe { CloseHandle(self.0) };
    }
}

fn last_error() -> u32 {
    unsafe { GetLastError() }
}

fn system_error(what: &str, code: u32) -> String {
    format!(
        "{what} failed: {}",
        io::Error::from_raw_os_error(code as i32)
    )
}

fn wide_string(buffer: &[u16]) -> String {
    let length = buffer
        .iter()
        .position(|&unit| unit == 0)
        .unwrap_or(buffer.len());
    String::from_utf16_lossy(&buffer[..length])
}

pub fn open(pid: u32) -> Result<(ProcessHandle, bool, String), String> {
    let full =
        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION;
    let mut handle = unsafe { OpenProcess(full, 0, pid) };
    let mut writable = true;
    if handle.is_null() {
        handle =
            unsafe { OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ, 0, pid) };
        writable = false;
    }
    if handle.is_null() {
        return Err(system_error(
            &format!("Attaching to process {pid}"),
            last_error(),
        ));
    }

    let mut buffer = [0u16; IMAGE_BUFFER];
    let mut length = buffer.len() as u32;
    let path = if unsafe {
        QueryFullProcessImageNameW(handle, PROCESS_NAME_WIN32, buffer.as_mut_ptr(), &mut length)
    } != 0
    {
        String::from_utf16_lossy(&buffer[..length as usize])
    } else {
        String::new()
    };

    Ok((ProcessHandle(handle), writable, path))
}

fn snapshot(flags: u32, pid: u32) -> Result<HANDLE, String> {
    let mut code = 0;
    for _ in 0..4 {
        let handle = unsafe { CreateToolhelp32Snapshot(flags, pid) };
        if handle != INVALID_HANDLE_VALUE {
            return Ok(handle);
        }
        code = last_error();
        if code != ERROR_BAD_LENGTH {
            break;
        }
    }
    Err(system_error("Listing process information", code))
}

pub fn processes() -> Vec<ProcessInfo> {
    let Ok(snapshot) = snapshot(TH32CS_SNAPPROCESS, 0) else {
        return Vec::new();
    };
    let mut entry = PROCESSENTRY32W {
        dwSize: mem::size_of::<PROCESSENTRY32W>() as u32,
        ..Default::default()
    };
    let mut list = Vec::new();
    if unsafe { Process32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            let pid = entry.th32ProcessID;
            let name = wide_string(&entry.szExeFile);
            if pid != 0 && !name.is_empty() {
                list.push(ProcessInfo {
                    pid,
                    name,
                    path: String::new(),
                });
            }
            if unsafe { Process32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) };

    list.sort_by(|left, right| {
        left.name
            .to_ascii_lowercase()
            .cmp(&right.name.to_ascii_lowercase())
            .then(left.pid.cmp(&right.pid))
    });
    list
}

pub fn modules(pid: u32) -> Vec<LiveModule> {
    let Ok(snapshot) = snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid) else {
        return Vec::new();
    };
    let mut entry = MODULEENTRY32W {
        dwSize: mem::size_of::<MODULEENTRY32W>() as u32,
        ..Default::default()
    };
    let mut list = Vec::new();
    if unsafe { Module32FirstW(snapshot, &mut entry) } != 0 {
        loop {
            list.push(LiveModule {
                base: entry.modBaseAddr as u64,
                size: u64::from(entry.modBaseSize),
                name: wide_string(&entry.szModule),
                path: wide_string(&entry.szExePath),
            });
            if unsafe { Module32NextW(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) };

    list.sort_by_key(|module| module.base);
    list
}

pub fn threads(pid: u32) -> Vec<u32> {
    let Ok(snapshot) = snapshot(TH32CS_SNAPTHREAD, 0) else {
        return Vec::new();
    };
    let mut entry = THREADENTRY32 {
        dwSize: mem::size_of::<THREADENTRY32>() as u32,
        ..Default::default()
    };
    let mut list = Vec::new();
    if unsafe { Thread32First(snapshot, &mut entry) } != 0 {
        loop {
            if entry.th32OwnerProcessID == pid {
                list.push(entry.th32ThreadID);
            }
            if unsafe { Thread32Next(snapshot, &mut entry) } == 0 {
                break;
            }
        }
    }
    unsafe { CloseHandle(snapshot) };
    list.sort_unstable();
    list
}

// Pauses each thread just long enough to copy its registers. This is the only place that suspends
// threads without being asked to, and every thread is resumed before returning.
pub fn contexts(handle: &ProcessHandle, pid: u32) -> Vec<ThreadContext> {
    let mut wow64 = 0;
    let bits32 = unsafe { IsWow64Process(handle.0, &mut wow64) } != 0 && wow64 != 0;
    threads(pid)
        .into_iter()
        .map(|id| context_of(id, bits32))
        .collect()
}

fn context_of(id: u32, bits32: bool) -> ThreadContext {
    let handle = unsafe {
        OpenThread(
            THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
            0,
            id,
        )
    };
    if handle.is_null() {
        return ThreadContext {
            id,
            error: Some(system_error("Opening a thread", last_error())),
            ..ThreadContext::default()
        };
    }

    let suspended = unsafe { SuspendThread(handle) } != u32::MAX;
    let context = if bits32 {
        let mut c: WOW64_CONTEXT = unsafe { mem::zeroed() };
        c.ContextFlags = CONTEXT_FLAGS_32;
        if unsafe { Wow64GetThreadContext(handle, &mut c) } != 0 {
            Some(ThreadContext {
                id,
                ip: u64::from(c.Eip),
                sp: u64::from(c.Esp),
                bp: u64::from(c.Ebp),
                registers: vec![
                    ("eax", u64::from(c.Eax)),
                    ("ebx", u64::from(c.Ebx)),
                    ("ecx", u64::from(c.Ecx)),
                    ("edx", u64::from(c.Edx)),
                    ("esi", u64::from(c.Esi)),
                    ("edi", u64::from(c.Edi)),
                    ("ebp", u64::from(c.Ebp)),
                    ("esp", u64::from(c.Esp)),
                    ("eip", u64::from(c.Eip)),
                    ("eflags", u64::from(c.EFlags)),
                ],
                error: None,
            })
        } else {
            None
        }
    } else {
        let mut c: AlignedContext = unsafe { mem::zeroed() };
        c.0.ContextFlags = CONTEXT_FLAGS_64;
        if unsafe { GetThreadContext(handle, &mut c.0) } != 0 {
            let c = &c.0;
            Some(ThreadContext {
                id,
                ip: c.Rip,
                sp: c.Rsp,
                bp: c.Rbp,
                registers: vec![
                    ("rax", c.Rax),
                    ("rbx", c.Rbx),
                    ("rcx", c.Rcx),
                    ("rdx", c.Rdx),
                    ("rsi", c.Rsi),
                    ("rdi", c.Rdi),
                    ("rbp", c.Rbp),
                    ("rsp", c.Rsp),
                    ("r8", c.R8),
                    ("r9", c.R9),
                    ("r10", c.R10),
                    ("r11", c.R11),
                    ("r12", c.R12),
                    ("r13", c.R13),
                    ("r14", c.R14),
                    ("r15", c.R15),
                    ("rip", c.Rip),
                    ("eflags", u64::from(c.EFlags)),
                ],
                error: None,
            })
        } else {
            None
        }
    };
    let code = if context.is_none() { last_error() } else { 0 };

    if suspended {
        unsafe { ResumeThread(handle) };
    }
    unsafe { CloseHandle(handle) };

    context.unwrap_or_else(|| ThreadContext {
        id,
        error: Some(system_error("Reading a thread context", code)),
        ..ThreadContext::default()
    })
}

// Suspends or resumes every thread in the process, returning how many changed.
fn change_threads(pid: u32, suspend: bool) -> Result<usize, String> {
    let ids = threads(pid);
    if ids.is_empty() {
        return Err(format!("No threads of process {pid} could be opened"));
    }
    let mut changed = 0;
    let mut code = 0;
    for id in ids {
        let handle = unsafe { OpenThread(THREAD_SUSPEND_RESUME, 0, id) };
        if handle.is_null() {
            code = last_error();
            continue;
        }
        let result = unsafe {
            if suspend {
                SuspendThread(handle)
            } else {
                ResumeThread(handle)
            }
        };
        unsafe { CloseHandle(handle) };
        if result == u32::MAX {
            code = last_error();
        } else {
            changed += 1;
        }
    }
    if changed == 0 {
        let action = if suspend { "Suspending" } else { "Resuming" };
        return Err(system_error(action, code));
    }
    Ok(changed)
}

pub fn suspend(pid: u32) -> Result<usize, String> {
    change_threads(pid, true)
}

pub fn resume(pid: u32) -> Result<usize, String> {
    change_threads(pid, false)
}

pub fn kill(pid: u32) -> Result<(), String> {
    let handle = unsafe { OpenProcess(PROCESS_TERMINATE, 0, pid) };
    if handle.is_null() {
        return Err(system_error(
            &format!("Opening process {pid} to stop it"),
            last_error(),
        ));
    }
    let stopped = unsafe { TerminateProcess(handle, 1) };
    let code = last_error();
    unsafe { CloseHandle(handle) };
    if stopped == 0 {
        return Err(system_error(&format!("Stopping process {pid}"), code));
    }
    Ok(())
}

pub fn regions(handle: &ProcessHandle) -> Vec<Region> {
    let mut address = 0u64;
    let mut list = Vec::new();
    loop {
        let mut info: MEMORY_BASIC_INFORMATION = unsafe { mem::zeroed() };
        let written = unsafe {
            VirtualQueryEx(
                handle.0,
                address as *const c_void,
                &mut info,
                mem::size_of::<MEMORY_BASIC_INFORMATION>(),
            )
        };
        if written == 0 {
            break;
        }
        let base = info.BaseAddress as u64;
        let size = info.RegionSize as u64;
        if size == 0 {
            break;
        }
        list.push(Region {
            base,
            size,
            state: info.State,
            protect: info.Protect,
            kind: info.Type,
        });
        address = base.saturating_add(size);
        if address == 0 {
            break;
        }
    }
    merge_regions(list)
}

pub fn handle_count(handle: &ProcessHandle) -> Option<u32> {
    let mut count = 0;
    (unsafe { GetProcessHandleCount(handle.0, &mut count) } != 0).then_some(count)
}

pub fn is_alive(handle: &ProcessHandle) -> bool {
    let mut code = STILL_ACTIVE;
    (unsafe { GetExitCodeProcess(handle.0, &mut code) }) != 0 && code == STILL_ACTIVE
}

pub fn read(handle: &ProcessHandle, address: u64, len: usize) -> Vec<u8> {
    let mut bytes = vec![0u8; len];
    let mut total = 0;
    while total < len {
        let page_left = 0x1000 - ((address as usize + total) & 0xFFF);
        let chunk = page_left.min(len - total);
        let mut got = 0;
        let ok = unsafe {
            ReadProcessMemory(
                handle.0,
                (address + total as u64) as *const c_void,
                bytes[total..].as_mut_ptr().cast(),
                chunk,
                &mut got,
            )
        };
        if ok == 0 || got == 0 {
            break;
        }
        total += got;
    }
    bytes.truncate(total);
    bytes
}

pub fn write(handle: &ProcessHandle, address: u64, bytes: &[u8]) -> Result<(), String> {
    let mut total = 0;
    while total < bytes.len() {
        let page_left = 0x1000 - ((address as usize + total) & 0xFFF);
        let chunk = page_left.min(bytes.len() - total);
        let mut written = 0;
        let ok = unsafe {
            WriteProcessMemory(
                handle.0,
                (address + total as u64) as *const c_void,
                bytes[total..].as_ptr().cast(),
                chunk,
                &mut written,
            )
        };
        if ok == 0 || written != chunk {
            return Err(system_error(
                &format!("Writing at {:#x}", address + total as u64),
                last_error(),
            ));
        }
        total += written;
    }
    unsafe { FlushInstructionCache(handle.0, address as *const c_void, bytes.len()) };
    Ok(())
}

pub fn dll_users(name: &str) -> Vec<(ProcessInfo, LiveModule)> {
    let wanted = name.to_ascii_lowercase();
    let mut users = Vec::new();
    for process in processes() {
        if users.len() >= 128 {
            break;
        }
        let list = modules(process.pid);
        let found = list.iter().find(|module| {
            basename(&module.path).eq_ignore_ascii_case(&wanted)
                || module.name.eq_ignore_ascii_case(&wanted)
        });
        let Some(module) = found else {
            continue;
        };
        let exe = list
            .iter()
            .find(|module| module.name.eq_ignore_ascii_case(&process.name))
            .map(|module| module.path.clone())
            .unwrap_or_default();
        users.push((
            ProcessInfo {
                pid: process.pid,
                name: process.name,
                path: exe,
            },
            module.clone(),
        ));
    }
    users
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn attaches_to_the_current_process() {
        let pid = std::process::id();
        let (handle, writable, path) = open(pid).expect("open own process");
        assert!(writable, "a process may always edit itself");
        assert!(is_alive(&handle));
        assert!(
            path.to_ascii_lowercase().ends_with(".exe"),
            "unexpected image path {path:?}"
        );
        assert!(handle_count(&handle).is_some_and(|count| count > 0));

        let list = modules(pid);
        let image = list
            .iter()
            .find(|module| module.name.to_ascii_lowercase().ends_with(".exe"))
            .expect("the executable is a loaded module");
        assert_eq!(read(&handle, image.base, 2), b"MZ");

        assert!(threads(pid).contains(&current_thread()));
        let memory = regions(&handle);
        assert!(!memory.is_empty());
        assert!(memory.iter().any(Region::executable));
        assert!(
            memory.iter().any(|region| {
                image.base >= region.base && image.base - region.base < region.size
            })
        );
    }

    #[test]
    fn finds_running_processes_and_dll_users() {
        let pid = std::process::id();
        assert!(processes().iter().any(|process| process.pid == pid));

        let users = dll_users("kernel32.dll");
        assert!(
            users.iter().any(|(process, module)| process.pid == pid
                && module.name.eq_ignore_ascii_case("kernel32.dll")),
            "the test process loads kernel32.dll"
        );
    }

    fn current_thread() -> u32 {
        use windows_sys::Win32::System::Threading::GetCurrentThreadId;
        unsafe { GetCurrentThreadId() }
    }
}
