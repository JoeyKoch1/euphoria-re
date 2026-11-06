use std::collections::BTreeMap;
use std::ffi::{OsStr, c_void};
use std::mem;
use std::os::windows::ffi::OsStrExt;
use std::path::Path;
use std::ptr;
use std::sync::mpsc::{Receiver, Sender, TryRecvError};

use iced_x86::{Decoder, DecoderOptions, FlowControl, Instruction};
use windows_sys::Win32::Foundation::{
    CloseHandle, DBG_CONTINUE, DBG_EXCEPTION_NOT_HANDLED, EXCEPTION_BREAKPOINT,
    EXCEPTION_SINGLE_STEP, GetLastError, HANDLE, STATUS_WX86_BREAKPOINT, STATUS_WX86_SINGLE_STEP,
};
use windows_sys::Win32::Storage::FileSystem::GetFinalPathNameByHandleW;
use windows_sys::Win32::System::Diagnostics::Debug::{
    CONTEXT, CREATE_PROCESS_DEBUG_EVENT, CREATE_THREAD_DEBUG_EVENT, ContinueDebugEvent,
    DEBUG_EVENT, DebugBreakProcess, EXCEPTION_DEBUG_EVENT, EXIT_PROCESS_DEBUG_EVENT,
    EXIT_THREAD_DEBUG_EVENT, FlushInstructionCache, GetThreadContext, LOAD_DLL_DEBUG_EVENT,
    OUTPUT_DEBUG_STRING_EVENT, RIP_EVENT, ReadProcessMemory, SetThreadContext,
    UNLOAD_DLL_DEBUG_EVENT, WOW64_CONTEXT, WaitForDebugEvent, Wow64GetThreadContext,
    Wow64SetThreadContext, WriteProcessMemory,
};
use windows_sys::Win32::System::Threading::{
    CREATE_NEW_CONSOLE, CREATE_NO_WINDOW, CreateProcessW, DEBUG_ONLY_THIS_PROCESS,
    PROCESS_INFORMATION, STARTUPINFOW, TerminateProcess,
};

use crate::{
    CODE_LINES, Command, Event, Launch, Module, STACK_SLOTS, Snapshot, StopReason, disassemble,
};

const WAIT_MILLISECONDS: u32 = 20;
const CONTEXT_FLAGS_64: u32 = 0x0010_0003;
const CONTEXT_FLAGS_32: u32 = 0x0001_0007;
const TRAP_FLAG: u32 = 0x100;
const INT3: u8 = 0xCC;
const MAX_INSTRUCTION: usize = 15;
const MAX_MEMORY_READ: usize = 1 << 20;
const MAX_DEBUG_STRING: usize = 4096;
const PRINT_EXCEPTION: u32 = 0x4001_0006;
const PRINT_EXCEPTION_WIDE: u32 = 0x4001_000A;
const THREAD_NAME_EXCEPTION: u32 = 0x406D_1388;

#[repr(align(16))]
struct Aligned(CONTEXT);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Goal {
    Run,
    StepOne,
    StepOut,
}

struct Breakpoint {
    original: u8,
    user: bool,
}

struct Debugger {
    launch: Launch,
    commands: Receiver<Command>,
    events: Sender<Event>,
    process: HANDLE,
    threads: BTreeMap<u32, HANDLE>,
    breakpoints: BTreeMap<u64, Breakpoint>,
    modules: BTreeMap<u64, Module>,
    delta: i64,
    goal: Goal,
    temporary: Option<u64>,
    rearm: Option<u64>,
    at_entry: bool,
    pause_pending: bool,
    stopping: bool,
    seen_native_break: bool,
    seen_wow_break: bool,
    pending: Option<(u32, u32)>,
    pass_exception: bool,
    event_thread: u32,
    view_thread: u32,
    exception_reason: Option<StopReason>,
}

pub fn run(launch: Launch, commands: Receiver<Command>, events: Sender<Event>) {
    let mut debugger = Debugger {
        launch,
        commands,
        events,
        process: ptr::null_mut(),
        threads: BTreeMap::new(),
        breakpoints: BTreeMap::new(),
        modules: BTreeMap::new(),
        delta: 0,
        goal: Goal::Run,
        temporary: None,
        rearm: None,
        at_entry: true,
        pause_pending: false,
        stopping: false,
        seen_native_break: false,
        seen_wow_break: false,
        pending: None,
        pass_exception: false,
        event_thread: 0,
        view_thread: 0,
        exception_reason: None,
    };
    if let Err(message) = debugger.spawn() {
        debugger.emit(Event::Failed(message));
        return;
    }
    debugger.main_loop();
}

fn wide(text: &OsStr) -> Vec<u16> {
    text.encode_wide().chain(Some(0)).collect()
}

fn system_error(what: &str) -> String {
    let code = unsafe { GetLastError() };
    format!(
        "{what} failed: {}",
        std::io::Error::from_raw_os_error(code as i32)
    )
}

fn file_name_of(handle: HANDLE) -> String {
    let mut buffer = [0u16; 1024];
    let length =
        unsafe { GetFinalPathNameByHandleW(handle, buffer.as_mut_ptr(), buffer.len() as u32, 0) }
            as usize;
    if length == 0 || length >= buffer.len() {
        return String::new();
    }
    let path = String::from_utf16_lossy(&buffer[..length]);
    path.rsplit(['\\', '/']).next().unwrap_or("").to_owned()
}

impl Debugger {
    fn emit(&self, event: Event) {
        let _ = self.events.send(event);
    }

    fn log(&self, text: String) {
        self.emit(Event::Log(text));
    }

    fn spawn(&mut self) -> Result<(), String> {
        let path = self.launch.path.clone();
        let directory = path.parent().unwrap_or(Path::new("."));
        let mut line = format!("\"{}\"", path.display());
        if !self.launch.args.is_empty() {
            line.push(' ');
            line.push_str(&self.launch.args);
        }
        let mut line = wide(OsStr::new(&line));
        let application = wide(path.as_os_str());
        let directory = wide(directory.as_os_str());

        let console = if self.launch.hide_console {
            CREATE_NO_WINDOW
        } else {
            CREATE_NEW_CONSOLE
        };
        let startup = STARTUPINFOW {
            cb: mem::size_of::<STARTUPINFOW>() as u32,
            ..unsafe { mem::zeroed() }
        };
        let mut info: PROCESS_INFORMATION = unsafe { mem::zeroed() };
        let created = unsafe {
            CreateProcessW(
                application.as_ptr(),
                line.as_mut_ptr(),
                ptr::null(),
                ptr::null(),
                0,
                DEBUG_ONLY_THIS_PROCESS | console,
                ptr::null(),
                directory.as_ptr(),
                &startup,
                &mut info,
            )
        };
        if created == 0 {
            return Err(system_error("Starting the program"));
        }
        unsafe {
            CloseHandle(info.hThread);
            CloseHandle(info.hProcess);
        }
        Ok(())
    }

    fn main_loop(&mut self) {
        loop {
            if self.pending.is_some() && !self.stopping {
                // Paused: nothing happens until the user asks for something.
                match self.commands.recv() {
                    Ok(command) => self.handle_stopped(command),
                    Err(_) => self.terminate(),
                }
                continue;
            }

            loop {
                match self.commands.try_recv() {
                    Ok(command) => self.handle_running(command),
                    Err(TryRecvError::Empty) => break,
                    Err(TryRecvError::Disconnected) => {
                        self.terminate();
                        break;
                    }
                }
            }

            let mut event: DEBUG_EVENT = unsafe { mem::zeroed() };
            if unsafe { WaitForDebugEvent(&mut event, WAIT_MILLISECONDS) } == 0 {
                continue;
            }
            if self.handle_event(&event) {
                return;
            }
        }
    }

    fn handle_stopped(&mut self, command: Command) {
        match command {
            Command::Continue => self.resume(Goal::Run),
            Command::StepInto => self.resume(Goal::StepOne),
            Command::StepOver => self.step_over(),
            Command::StepOut => self.resume(Goal::StepOut),
            Command::RunTo(image) => {
                let address = self.rebase(image);
                self.set_temporary(address);
                self.resume(Goal::Run);
            }
            Command::Pause => {}
            Command::Stop => self.terminate(),
            Command::WriteMemory { address, bytes } => self.write_memory(address, &bytes),
            Command::WriteRegister { name, value } => self.write_register(name, value),
            Command::SelectThread(thread) => {
                if self.threads.contains_key(&thread) {
                    self.view_thread = thread;
                    let reason = self.exception_reason.clone().unwrap_or(StopReason::Paused);
                    self.report(reason);
                }
            }
            other => self.handle_any(other),
        }
    }

    fn handle_running(&mut self, command: Command) {
        match command {
            Command::Pause => {
                self.pause_pending = true;
                if unsafe { DebugBreakProcess(self.process) } == 0 {
                    self.pause_pending = false;
                    self.log(system_error("Pausing"));
                }
            }
            Command::Stop => self.terminate(),
            Command::AddBreakpoint(_)
            | Command::RemoveBreakpoint(_)
            | Command::ReadMemory { .. } => self.handle_any(command),
            Command::WriteMemory { .. } | Command::WriteRegister { .. } => {
                self.log("Pause the program before editing memory or registers.".to_owned());
            }
            _ => {}
        }
    }

    fn handle_any(&mut self, command: Command) {
        match command {
            Command::AddBreakpoint(image) => {
                let address = self.rebase(image);
                self.add_breakpoint(address, true);
            }
            Command::RemoveBreakpoint(image) => {
                let address = self.rebase(image);
                self.remove_user_breakpoint(address);
            }
            Command::ReadMemory { address, len } => {
                let bytes = self.read(address, len.min(MAX_MEMORY_READ));
                self.emit(Event::Memory { address, bytes });
            }
            _ => {}
        }
    }

    fn rebase(&self, image: u64) -> u64 {
        image.wrapping_add_signed(self.delta)
    }

    fn terminate(&mut self) {
        self.stopping = true;
        if !self.process.is_null() {
            unsafe { TerminateProcess(self.process, 1) };
        }
        self.continue_pending();
    }

    fn continue_pending(&mut self) {
        if let Some((pid, thread)) = self.pending.take() {
            let status = if self.pass_exception {
                DBG_EXCEPTION_NOT_HANDLED
            } else {
                DBG_CONTINUE
            };
            self.pass_exception = false;
            unsafe { ContinueDebugEvent(pid, thread, status) };
        }
    }

    // Returns true once the process is gone.
    fn handle_event(&mut self, event: &DEBUG_EVENT) -> bool {
        self.pending = Some((event.dwProcessId, event.dwThreadId));
        self.event_thread = event.dwThreadId;
        let mut stopped = false;

        match event.dwDebugEventCode {
            CREATE_PROCESS_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateProcessInfo };
                self.process = info.hProcess;
                self.threads.insert(event.dwThreadId, info.hThread);
                let base = info.lpBaseOfImage as u64;
                self.delta = base.wrapping_sub(self.launch.image_base) as i64;
                self.add_module(base, info.hFile);
                self.emit(Event::Started {
                    pid: event.dwProcessId,
                    base,
                });

                let entry = self.rebase(self.launch.entry);
                for image in std::mem::take(&mut self.launch.breakpoints) {
                    let address = self.rebase(image);
                    self.add_breakpoint(address, true);
                }
                self.set_temporary(entry);
                self.at_entry = true;
            }
            CREATE_THREAD_DEBUG_EVENT => {
                let info = unsafe { event.u.CreateThread };
                self.threads.insert(event.dwThreadId, info.hThread);
            }
            EXIT_THREAD_DEBUG_EVENT => {
                self.threads.remove(&event.dwThreadId);
            }
            LOAD_DLL_DEBUG_EVENT => {
                let info = unsafe { event.u.LoadDll };
                let base = info.lpBaseOfDll as u64;
                self.add_module(base, info.hFile);
                if let Some(module) = self.modules.get(&base) {
                    self.log(format!("Loaded {} at {base:#x}", module.name));
                }
            }
            UNLOAD_DLL_DEBUG_EVENT => {
                let base = unsafe { event.u.UnloadDll }.lpBaseOfDll as u64;
                self.modules.remove(&base);
            }
            OUTPUT_DEBUG_STRING_EVENT => {
                let info = unsafe { event.u.DebugString };
                let length = usize::from(info.nDebugStringLength).min(MAX_DEBUG_STRING);
                let wide_text = info.fUnicode != 0;
                let bytes = self.read(
                    info.lpDebugStringData as u64,
                    if wide_text { length * 2 } else { length },
                );
                let text = if wide_text {
                    let units: Vec<u16> = bytes
                        .as_chunks::<2>()
                        .0
                        .iter()
                        .map(|pair| u16::from_le_bytes(*pair))
                        .collect();
                    String::from_utf16_lossy(&units)
                } else {
                    String::from_utf8_lossy(&bytes).into_owned()
                };
                self.log(format!(
                    "Debug output: {}",
                    text.trim_end_matches(['\0', '\n', '\r'])
                ));
            }
            EXCEPTION_DEBUG_EVENT => stopped = self.handle_exception(event),
            EXIT_PROCESS_DEBUG_EVENT => {
                let code = unsafe { event.u.ExitProcess }.dwExitCode;
                self.continue_pending();
                self.emit(Event::Exited(code));
                return true;
            }
            RIP_EVENT => {
                self.log("The program died in a way Windows could not report.".to_owned());
            }
            _ => {}
        }

        if !stopped {
            self.continue_pending();
        }
        false
    }

    fn add_module(&mut self, base: u64, file: HANDLE) {
        let name = if file.is_null() {
            format!("module_{base:x}")
        } else {
            let name = file_name_of(file);
            unsafe { CloseHandle(file) };
            name
        };
        let size = self.image_size(base);
        self.modules.insert(base, Module { base, size, name });
    }

    fn image_size(&self, base: u64) -> u64 {
        let header = self.read(base + 0x3C, 4);
        let Ok(offset) = <[u8; 4]>::try_from(header.as_slice()) else {
            return 0;
        };
        let nt = u64::from(u32::from_le_bytes(offset));
        let size = self.read(base + nt + 0x50, 4);
        <[u8; 4]>::try_from(size.as_slice()).map_or(0, |raw| u64::from(u32::from_le_bytes(raw)))
    }

    // Returns true when the program should stay stopped for the user.
    fn handle_exception(&mut self, event: &DEBUG_EVENT) -> bool {
        let info = unsafe { event.u.Exception };
        let code = info.ExceptionRecord.ExceptionCode;
        let address = info.ExceptionRecord.ExceptionAddress as u64;
        let first_chance = info.dwFirstChance != 0;

        if self.stopping {
            self.pass_exception = code != EXCEPTION_BREAKPOINT && code != EXCEPTION_SINGLE_STEP;
            return false;
        }

        match code {
            EXCEPTION_BREAKPOINT | STATUS_WX86_BREAKPOINT => {
                self.handle_break(code, address, first_chance)
            }
            EXCEPTION_SINGLE_STEP | STATUS_WX86_SINGLE_STEP => self.handle_single_step(),
            _ => {
                let raw = code as u32;
                if matches!(
                    raw,
                    PRINT_EXCEPTION | PRINT_EXCEPTION_WIDE | THREAD_NAME_EXCEPTION
                ) {
                    self.pass_exception = true;
                    return false;
                }
                self.pass_exception = true;
                self.stop(StopReason::Exception {
                    code: raw,
                    first_chance,
                });
                true
            }
        }
    }

    fn handle_break(&mut self, code: i32, address: u64, first_chance: bool) -> bool {
        if self.breakpoints.contains_key(&address) {
            self.set_ip(address);
            let was_temporary = self.temporary == Some(address);
            let user = self.breakpoints[&address].user;
            if was_temporary {
                self.temporary = None;
                if !user {
                    self.remove_breakpoint(address);
                }
            }

            if self.at_entry && was_temporary {
                self.at_entry = false;
                self.stop(StopReason::Entry);
                return true;
            }
            if user {
                self.stop(StopReason::Breakpoint);
                return true;
            }
            if was_temporary && self.goal == Goal::StepOut {
                return self.step_out_tick();
            }
            self.stop(StopReason::Step);
            return true;
        }

        // Windows raises one breakpoint of its own while starting a process, and a second for the
        // 32-bit layer in a 32-bit program. Neither means anything to the user.
        if code == EXCEPTION_BREAKPOINT && !self.seen_native_break {
            self.seen_native_break = true;
            return false;
        }
        if code == STATUS_WX86_BREAKPOINT && !self.seen_wow_break {
            self.seen_wow_break = true;
            return false;
        }
        if self.pause_pending {
            self.pause_pending = false;
            self.stop(StopReason::Paused);
            return true;
        }

        self.pass_exception = true;
        self.stop(StopReason::Exception {
            code: code as u32,
            first_chance,
        });
        true
    }

    fn handle_single_step(&mut self) -> bool {
        if let Some(address) = self.rearm.take() {
            self.write_byte(address, INT3);
        }
        match self.goal {
            Goal::Run => false,
            Goal::StepOne => {
                self.stop(StopReason::Step);
                true
            }
            Goal::StepOut => {
                if self.temporary.is_some() {
                    return false;
                }
                self.step_out_tick()
            }
        }
    }

    // Walks forward one instruction at a time, running called routines at full speed, until the
    // current routine returns.
    fn step_out_tick(&mut self) -> bool {
        let insn = self.decode_at_ip();
        match insn.flow_control() {
            FlowControl::Return => {
                self.goal = Goal::StepOne;
                self.arm_step();
            }
            FlowControl::Call | FlowControl::IndirectCall => {
                self.set_temporary(insn.next_ip());
                self.step_past_breakpoint();
            }
            _ => self.arm_step(),
        }
        false
    }

    fn arm_step(&mut self) {
        self.step_past_breakpoint();
        self.set_trap();
    }

    fn step_past_breakpoint(&mut self) {
        let ip = self.registers_of(self.event_thread).0;
        if let Some(breakpoint) = self.breakpoints.get(&ip) {
            let original = breakpoint.original;
            self.write_byte(ip, original);
            self.rearm = Some(ip);
            self.set_trap();
        }
    }

    fn decode_at_ip(&self) -> Instruction {
        let ip = self.registers_of(self.event_thread).0;
        let bytes = self.read(ip, MAX_INSTRUCTION);
        let mut decoder = Decoder::with_ip(self.launch.bits, &bytes, ip, DecoderOptions::NONE);
        decoder.decode()
    }

    fn resume(&mut self, goal: Goal) {
        self.goal = goal;
        self.exception_reason = None;
        match goal {
            Goal::Run => self.step_past_breakpoint(),
            Goal::StepOne => self.arm_step(),
            Goal::StepOut => {
                self.step_out_tick();
            }
        }
        self.emit(Event::Running);
        self.continue_pending();
    }

    fn step_over(&mut self) {
        let insn = self.decode_at_ip();
        let steps_past = matches!(
            insn.flow_control(),
            FlowControl::Call | FlowControl::IndirectCall
        ) || insn.has_rep_prefix()
            || insn.has_repe_prefix()
            || insn.has_repne_prefix();
        if steps_past {
            self.set_temporary(insn.next_ip());
            self.resume(Goal::Run);
        } else {
            self.resume(Goal::StepOne);
        }
    }

    fn set_temporary(&mut self, address: u64) {
        if let Some(previous) = self.temporary.take()
            && self.breakpoints.get(&previous).is_some_and(|bp| !bp.user)
        {
            self.remove_breakpoint(previous);
        }
        self.add_breakpoint(address, false);
        self.temporary = Some(address);
    }

    fn add_breakpoint(&mut self, address: u64, user: bool) {
        if let Some(existing) = self.breakpoints.get_mut(&address) {
            existing.user |= user;
            return;
        }
        let byte = self.read(address, 1);
        let Some(&original) = byte.first() else {
            self.log(format!("Could not place a breakpoint at {address:#x}"));
            return;
        };
        if !self.write_byte(address, INT3) {
            self.log(format!("Could not write a breakpoint at {address:#x}"));
            return;
        }
        self.breakpoints
            .insert(address, Breakpoint { original, user });
    }

    fn remove_user_breakpoint(&mut self, address: u64) {
        let Some(existing) = self.breakpoints.get_mut(&address) else {
            return;
        };
        existing.user = false;
        if self.temporary != Some(address) {
            self.remove_breakpoint(address);
        }
    }

    fn remove_breakpoint(&mut self, address: u64) {
        if let Some(breakpoint) = self.breakpoints.remove(&address)
            && self.rearm != Some(address)
        {
            self.write_byte(address, breakpoint.original);
        }
        if self.rearm == Some(address) {
            self.rearm = None;
        }
    }

    fn write_byte(&self, address: u64, byte: u8) -> bool {
        let mut written = 0;
        let done = unsafe {
            WriteProcessMemory(
                self.process,
                address as *const c_void,
                (&raw const byte).cast(),
                1,
                &mut written,
            )
        };
        unsafe { FlushInstructionCache(self.process, address as *const c_void, 1) };
        done != 0 && written == 1
    }

    // Reads as much as is mapped, and shows the original bytes where a breakpoint sits.
    fn read(&self, address: u64, len: usize) -> Vec<u8> {
        let mut bytes = vec![0u8; len];
        let mut total = 0;
        while total < len {
            let page_left = 0x1000 - ((address as usize + total) & 0xFFF);
            let chunk = page_left.min(len - total);
            let mut read = 0;
            let ok = unsafe {
                ReadProcessMemory(
                    self.process,
                    (address + total as u64) as *const c_void,
                    bytes[total..].as_mut_ptr().cast(),
                    chunk,
                    &mut read,
                )
            };
            if ok == 0 || read == 0 {
                break;
            }
            total += read;
        }
        bytes.truncate(total);

        for (&at, breakpoint) in self.breakpoints.range(address..address + total as u64) {
            if self.rearm != Some(at) {
                bytes[(at - address) as usize] = breakpoint.original;
            }
        }
        bytes
    }

    // Breakpoints stay armed: the edited byte becomes the new original and the trap stays in place.
    fn write_memory(&mut self, address: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let mut content = bytes.to_vec();
        let end = address.saturating_add(bytes.len() as u64);
        for (&at, breakpoint) in self.breakpoints.range_mut(address..end) {
            let offset = (at - address) as usize;
            breakpoint.original = content[offset];
            if self.rearm != Some(at) {
                content[offset] = INT3;
            }
        }

        let mut total = 0;
        let mut failed = None;
        while total < content.len() {
            let page_left = 0x1000 - ((address as usize + total) & 0xFFF);
            let chunk = page_left.min(content.len() - total);
            let mut written = 0;
            let done = unsafe {
                WriteProcessMemory(
                    self.process,
                    (address + total as u64) as *const c_void,
                    content[total..].as_ptr().cast(),
                    chunk,
                    &mut written,
                )
            };
            if done == 0 || written != chunk {
                failed = Some(address + total as u64);
                break;
            }
            total += written;
        }
        unsafe { FlushInstructionCache(self.process, address as *const c_void, total) };

        match failed {
            Some(at) => self.log(format!("Could not write memory at {at:#x}")),
            None => {
                self.log(format!("Wrote {} byte(s) at {address:#x}", content.len()));
                self.refresh();
            }
        }
    }

    fn write_register(&mut self, name: &str, value: u64) {
        let Some(&handle) = self.threads.get(&self.view_thread) else {
            self.log("No thread is selected.".to_owned());
            return;
        };
        let outcome = if self.launch.bits == 32 {
            self.with_context32(handle, |context| set_register32(context, name, value))
        } else {
            self.with_context64(handle, |context| set_register64(context, name, value))
        };
        match outcome {
            Some((true, true)) => {
                self.log(format!("{name} = {value:#x}"));
                self.refresh();
            }
            Some((true, false)) => self.log(format!("Could not change {name}")),
            _ => self.log(format!("{name} cannot be changed")),
        }
    }

    fn with_context64<T>(
        &self,
        handle: HANDLE,
        f: impl FnOnce(&mut CONTEXT) -> T,
    ) -> Option<(T, bool)> {
        let mut context: Aligned = unsafe { mem::zeroed() };
        context.0.ContextFlags = CONTEXT_FLAGS_64;
        if unsafe { GetThreadContext(handle, &mut context.0) } == 0 {
            return None;
        }
        let value = f(&mut context.0);
        let saved = unsafe { SetThreadContext(handle, &context.0) } != 0;
        Some((value, saved))
    }

    fn with_context32<T>(
        &self,
        handle: HANDLE,
        f: impl FnOnce(&mut WOW64_CONTEXT) -> T,
    ) -> Option<(T, bool)> {
        let mut context: WOW64_CONTEXT = unsafe { mem::zeroed() };
        context.ContextFlags = CONTEXT_FLAGS_32;
        if unsafe { Wow64GetThreadContext(handle, &mut context) } == 0 {
            return None;
        }
        let value = f(&mut context);
        let saved = unsafe { Wow64SetThreadContext(handle, &context) } != 0;
        Some((value, saved))
    }

    fn set_ip(&self, address: u64) {
        let Some(&handle) = self.threads.get(&self.event_thread) else {
            return;
        };
        if self.launch.bits == 32 {
            self.with_context32(handle, |context| context.Eip = address as u32);
        } else {
            self.with_context64(handle, |context| context.Rip = address);
        }
    }

    fn set_trap(&self) {
        let Some(&handle) = self.threads.get(&self.event_thread) else {
            return;
        };
        if self.launch.bits == 32 {
            self.with_context32(handle, |context| context.EFlags |= TRAP_FLAG);
        } else {
            self.with_context64(handle, |context| context.EFlags |= TRAP_FLAG);
        }
    }

    fn registers_of(&self, thread: u32) -> (u64, u64, Vec<(&'static str, u64)>) {
        let Some(&handle) = self.threads.get(&thread) else {
            return (0, 0, Vec::new());
        };
        if self.launch.bits == 32 {
            let mut c: WOW64_CONTEXT = unsafe { mem::zeroed() };
            c.ContextFlags = CONTEXT_FLAGS_32;
            if unsafe { Wow64GetThreadContext(handle, &mut c) } == 0 {
                return (0, 0, Vec::new());
            }
            let list = vec![
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
            ];
            (u64::from(c.Eip), u64::from(c.Esp), list)
        } else {
            let mut context: Aligned = unsafe { mem::zeroed() };
            context.0.ContextFlags = CONTEXT_FLAGS_64;
            if unsafe { GetThreadContext(handle, &mut context.0) } == 0 {
                return (0, 0, Vec::new());
            }
            let c = &context.0;
            let list = vec![
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
            ];
            (c.Rip, c.Rsp, list)
        }
    }

    fn stop(&mut self, reason: StopReason) {
        self.view_thread = self.event_thread;
        self.goal = Goal::Run;
        self.exception_reason = Some(reason.clone());
        self.report(reason);
    }

    fn report(&self, reason: StopReason) {
        self.emit(Event::Stopped(Box::new(self.snapshot(reason))));
    }

    // Redraws the current stop after an edit without logging another stop.
    fn refresh(&self) {
        if let Some(reason) = &self.exception_reason {
            self.emit(Event::Refreshed(Box::new(self.snapshot(reason.clone()))));
        }
    }

    fn snapshot(&self, reason: StopReason) -> Snapshot {
        let (ip, sp, registers) = self.registers_of(self.view_thread);
        let width = (self.launch.bits / 8) as usize;
        let raw_stack = self.read(sp, STACK_SLOTS * width);
        let stack = raw_stack
            .chunks_exact(width)
            .enumerate()
            .map(|(index, slot)| {
                let mut value = [0u8; 8];
                value[..width].copy_from_slice(slot);
                (sp + (index * width) as u64, u64::from_le_bytes(value))
            })
            .collect();
        let bytes = self.read(ip, CODE_LINES * MAX_INSTRUCTION);
        Snapshot {
            reason,
            thread: self.view_thread,
            threads: self.threads.keys().copied().collect(),
            registers,
            ip,
            sp,
            stack,
            code: disassemble(&bytes, ip, self.launch.bits, CODE_LINES),
            modules: self.modules.values().cloned().collect(),
            delta: self.delta,
        }
    }
}

fn set_register32(context: &mut WOW64_CONTEXT, name: &str, value: u64) -> bool {
    let value = value as u32;
    match name {
        "eax" => context.Eax = value,
        "ebx" => context.Ebx = value,
        "ecx" => context.Ecx = value,
        "edx" => context.Edx = value,
        "esi" => context.Esi = value,
        "edi" => context.Edi = value,
        "ebp" => context.Ebp = value,
        "esp" => context.Esp = value,
        "eip" => context.Eip = value,
        "eflags" => context.EFlags = value,
        _ => return false,
    }
    true
}

fn set_register64(context: &mut CONTEXT, name: &str, value: u64) -> bool {
    match name {
        "rax" => context.Rax = value,
        "rbx" => context.Rbx = value,
        "rcx" => context.Rcx = value,
        "rdx" => context.Rdx = value,
        "rsi" => context.Rsi = value,
        "rdi" => context.Rdi = value,
        "rbp" => context.Rbp = value,
        "rsp" => context.Rsp = value,
        "r8" => context.R8 = value,
        "r9" => context.R9 = value,
        "r10" => context.R10 = value,
        "r11" => context.R11 = value,
        "r12" => context.R12 = value,
        "r13" => context.R13 = value,
        "r14" => context.R14 = value,
        "r15" => context.R15 = value,
        "rip" => context.Rip = value,
        "eflags" => context.EFlags = value as u32,
        _ => return false,
    }
    true
}

#[cfg(test)]
mod tests {
    use super::{CONTEXT, WOW64_CONTEXT, set_register32, set_register64};

    fn context32() -> WOW64_CONTEXT {
        // SAFETY: the Windows context structures are plain data and accept an all-zero state.
        unsafe { std::mem::zeroed() }
    }

    fn context64() -> CONTEXT {
        // SAFETY: the Windows context structures are plain data and accept an all-zero state.
        unsafe { std::mem::zeroed() }
    }

    #[test]
    fn writes_32_bit_registers_by_name() {
        let mut context = context32();
        assert!(set_register32(&mut context, "eip", 0x1234_5678));
        assert!(set_register32(&mut context, "eax", 0xFFFF_FFFF_DEAD_BEEF));
        assert_eq!(context.Eip, 0x1234_5678);
        assert_eq!(context.Eax, 0xDEAD_BEEF);
        assert!(!set_register32(&mut context, "rax", 1));
    }

    #[test]
    fn writes_64_bit_registers_by_name() {
        let mut context = context64();
        assert!(set_register64(&mut context, "rip", 0x1_4000_1000));
        assert!(set_register64(&mut context, "r15", 0xDEAD_BEEF_CAFE_BABE));
        assert_eq!(context.Rip, 0x1_4000_1000);
        assert_eq!(context.R15, 0xDEAD_BEEF_CAFE_BABE);
        assert!(!set_register64(&mut context, "eax", 1));
    }

    #[test]
    fn keeps_the_flag_register_32_bit() {
        let mut context = context64();
        assert!(set_register64(
            &mut context,
            "eflags",
            0xFFFF_FFFF_0000_0202
        ));
        assert_eq!(context.EFlags, 0x202);
    }
}
