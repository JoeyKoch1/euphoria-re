#[cfg(all(windows, target_arch = "x86_64"))]
mod windows;

pub mod live;

use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, Sender};
use std::thread;
use std::time::Duration;

use iced_x86::{Decoder, DecoderOptions, Formatter, IntelFormatter};

pub const STACK_SLOTS: usize = 64;
pub const CODE_LINES: usize = 32;

pub struct Launch {
    pub path: PathBuf,
    pub args: String,
    pub bits: u32,
    pub image_base: u64,
    pub entry: u64,
    // Addresses as the analysis sees them. The session moves them to where the program loaded.
    pub breakpoints: Vec<u64>,
    pub hide_console: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Command {
    Continue,
    StepInto,
    StepOver,
    StepOut,
    RunTo(u64),
    Pause,
    Stop,
    AddBreakpoint(u64),
    RemoveBreakpoint(u64),
    ReadMemory { address: u64, len: usize },
    WriteMemory { address: u64, bytes: Vec<u8> },
    WriteRegister { name: &'static str, value: u64 },
    SelectThread(u32),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StopReason {
    Entry,
    Breakpoint,
    Step,
    Paused,
    Exception { code: u32, first_chance: bool },
}

#[derive(Clone, Debug)]
pub struct Module {
    pub base: u64,
    pub size: u64,
    pub name: String,
}

#[derive(Clone, Debug)]
pub struct CodeLine {
    pub address: u64,
    pub text: String,
}

#[derive(Clone, Debug)]
pub struct Snapshot {
    pub reason: StopReason,
    pub thread: u32,
    pub threads: Vec<u32>,
    pub registers: Vec<(&'static str, u64)>,
    pub ip: u64,
    pub sp: u64,
    pub stack: Vec<(u64, u64)>,
    pub code: Vec<CodeLine>,
    pub modules: Vec<Module>,
    pub delta: i64,
}

impl Snapshot {
    pub fn describe(&self, address: u64) -> Option<String> {
        let module = self
            .modules
            .iter()
            .find(|module| address >= module.base && address - module.base < module.size)?;
        Some(format!("{}+{:#x}", module.name, address - module.base))
    }

    // Where a live address sits in the file on disk, if it belongs to the main program.
    pub fn to_image(&self, address: u64) -> u64 {
        address.wrapping_add_signed(-self.delta)
    }
}

#[derive(Clone, Debug)]
pub enum Event {
    Started { pid: u32, base: u64 },
    Running,
    Stopped(Box<Snapshot>),
    Refreshed(Box<Snapshot>),
    Memory { address: u64, bytes: Vec<u8> },
    Log(String),
    Exited(u32),
    Failed(String),
}

// Windows ties a debugged process to the thread that started it, so everything happens on one
// worker and the caller talks to it through these channels.
pub struct Session {
    commands: Sender<Command>,
    events: Receiver<Event>,
}

impl Session {
    pub fn start(launch: Launch) -> Self {
        let (commands, command_receiver) = mpsc::channel();
        let (event_sender, events) = mpsc::channel();
        thread::spawn(move || run(launch, command_receiver, event_sender));
        Self { commands, events }
    }

    pub fn send(&self, command: Command) {
        let _ = self.commands.send(command);
    }

    pub fn poll(&self) -> Option<Event> {
        self.events.try_recv().ok()
    }

    pub fn wait(&self, timeout: Duration) -> Option<Event> {
        self.events.recv_timeout(timeout).ok()
    }
}

impl Drop for Session {
    fn drop(&mut self) {
        let _ = self.commands.send(Command::Stop);
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
fn run(launch: Launch, commands: Receiver<Command>, events: Sender<Event>) {
    windows::run(launch, commands, events);
}

#[cfg(not(all(windows, target_arch = "x86_64")))]
fn run(_: Launch, _: Receiver<Command>, events: Sender<Event>) {
    let _ = events.send(Event::Failed(
        "The debugger runs on 64-bit Windows for now.".to_owned(),
    ));
}

pub fn exception_name(code: u32) -> &'static str {
    match code {
        0x8000_0003 | 0x4000_001F => "breakpoint",
        0x8000_0004 | 0x4000_001E => "single step",
        0xC000_0005 => "access violation",
        0xC000_001D => "illegal instruction",
        0xC000_0094 => "integer division by zero",
        0xC000_0095 => "integer overflow",
        0xC000_00FD => "stack overflow",
        0xC000_0096 => "privileged instruction",
        0xC000_0025 => "exception that cannot continue",
        0xE06D_7363 => "C++ exception",
        0xC000_0409 => "stack buffer overrun",
        _ => "exception",
    }
}

pub(crate) fn disassemble(bytes: &[u8], address: u64, bits: u32, limit: usize) -> Vec<CodeLine> {
    let mut decoder = Decoder::with_ip(bits, bytes, address, DecoderOptions::NONE);
    let mut formatter = IntelFormatter::new();
    formatter.options_mut().set_hex_prefix("0x");
    formatter.options_mut().set_hex_suffix("");
    formatter.options_mut().set_uppercase_hex(false);
    formatter
        .options_mut()
        .set_space_after_operand_separator(true);
    let mut lines = Vec::new();
    while decoder.can_decode() && lines.len() < limit {
        let insn = decoder.decode();
        let mut text = String::new();
        formatter.format(&insn, &mut text);
        lines.push(CodeLine {
            address: insn.ip(),
            text,
        });
    }
    lines
}
