#![cfg(all(windows, target_arch = "x86_64"))]

// These debug `where.exe`, a harmless tool that ships with Windows, for real.

use std::path::{Path, PathBuf};
use std::time::Duration;

use euphoria_debugger::{Command, Event, Launch, Session, Snapshot, StopReason};
use object::{Object, ObjectSection};

const WAIT: Duration = Duration::from_secs(20);

fn tool(folder: &str) -> Option<(PathBuf, u32, u64, u64)> {
    let path = Path::new(r"C:\Windows").join(folder).join("where.exe");
    let data = std::fs::read(&path).ok()?;
    let file = object::File::parse(&*data).ok()?;
    let bits = if file.is_64() { 64 } else { 32 };
    let text = file.section_by_name(".text")?;
    assert!(text.size() > 0);
    Some((path, bits, file.relative_address_base(), file.entry()))
}

fn start(folder: &str, breakpoints: Vec<u64>) -> Option<(Session, u64, u32)> {
    let (path, bits, image_base, entry) = tool(folder)?;
    let session = Session::start(Launch {
        path,
        args: "/?".to_owned(),
        bits,
        image_base,
        entry,
        breakpoints,
        hide_console: true,
    });
    Some((session, entry, bits))
}

fn next_stop(session: &Session) -> Snapshot {
    loop {
        match session.wait(WAIT).expect("timed out") {
            Event::Stopped(snapshot) => return *snapshot,
            Event::Exited(code) => panic!("exited early with {code}"),
            Event::Failed(message) => panic!("{message}"),
            _ => {}
        }
    }
}

fn wait_exit(session: &Session) -> u32 {
    loop {
        match session.wait(WAIT).expect("timed out") {
            Event::Exited(code) => return code,
            Event::Failed(message) => panic!("{message}"),
            _ => {}
        }
    }
}

fn next_refresh(session: &Session) -> Snapshot {
    loop {
        match session.wait(WAIT).expect("timed out") {
            Event::Refreshed(snapshot) => return *snapshot,
            Event::Exited(code) => panic!("exited early with {code}"),
            Event::Failed(message) => panic!("{message}"),
            _ => {}
        }
    }
}

fn read_byte(session: &Session, address: u64) -> u8 {
    session.send(Command::ReadMemory { address, len: 1 });
    loop {
        match session.wait(WAIT).expect("timed out") {
            Event::Memory { bytes, .. } => return bytes[0],
            Event::Failed(message) => panic!("{message}"),
            _ => {}
        }
    }
}

fn walk_through(folder: &str) {
    let Some((session, entry, bits)) = start(folder, Vec::new()) else {
        return;
    };

    let first = next_stop(&session);
    assert_eq!(first.reason, StopReason::Entry);
    assert_eq!(first.to_image(first.ip), entry);
    assert!(first.sp != 0);
    assert!(!first.code.is_empty());
    assert!(first.stack.len() >= 8);
    let register = if bits == 64 { "rip" } else { "eip" };
    assert!(
        first
            .registers
            .iter()
            .any(|(name, value)| *name == register && *value == first.ip)
    );
    assert!(
        first
            .describe(first.ip)
            .is_some_and(|text| text.contains("where.exe"))
    );

    session.send(Command::StepInto);
    let second = next_stop(&session);
    assert_eq!(second.reason, StopReason::Step);
    assert_ne!(second.ip, first.ip);

    // A breakpoint a few instructions ahead, with one at the current spot too.
    let ahead = second.code[3].address;
    let before = read_byte(&session, ahead);
    session.send(Command::AddBreakpoint(second.to_image(ahead)));
    session.send(Command::AddBreakpoint(second.to_image(second.ip)));
    assert_eq!(
        read_byte(&session, ahead),
        before,
        "breakpoints should stay hidden"
    );

    session.send(Command::RunTo(second.to_image(second.code[1].address)));
    let third = next_stop(&session);
    assert_ne!(third.ip, second.ip);

    session.send(Command::StepOver);
    let fourth = next_stop(&session);
    assert_ne!(fourth.ip, third.ip);

    session.send(Command::RemoveBreakpoint(second.to_image(ahead)));
    session.send(Command::RemoveBreakpoint(second.to_image(second.ip)));
    session.send(Command::Continue);
    let code = wait_exit(&session);
    assert!(code < 256, "exit code {code:#x}");
}

#[test]
fn walks_through_a_64_bit_program() {
    walk_through("System32");
}

#[test]
fn walks_through_a_32_bit_program() {
    walk_through("SysWOW64");
}

#[test]
fn edits_registers_and_memory_while_paused() {
    let Some((session, _, _)) = start("System32", Vec::new()) else {
        return;
    };
    let stop = next_stop(&session);

    session.send(Command::WriteRegister {
        name: "rbx",
        value: 0x1122_3344_5566_7788,
    });
    let edited = next_refresh(&session);
    assert!(
        edited
            .registers
            .iter()
            .any(|(name, value)| *name == "rbx" && *value == 0x1122_3344_5566_7788),
        "the edited register should be visible in the refresh"
    );

    let address = stop.sp - 0x20;
    session.send(Command::WriteMemory {
        address,
        bytes: vec![0xDE, 0xAD, 0xBE, 0xEF],
    });
    next_refresh(&session);
    session.send(Command::ReadMemory { address, len: 4 });
    loop {
        match session.wait(WAIT).expect("timed out") {
            Event::Memory { bytes, .. } => {
                assert_eq!(bytes, vec![0xDE, 0xAD, 0xBE, 0xEF]);
                break;
            }
            Event::Failed(message) => panic!("{message}"),
            _ => {}
        }
    }

    session.send(Command::Stop);
    wait_exit(&session);
}

#[test]
fn stop_ends_the_program() {
    let Some((session, _, _)) = start("System32", Vec::new()) else {
        return;
    };
    next_stop(&session);
    session.send(Command::Stop);
    wait_exit(&session);
}

#[test]
fn breakpoints_set_before_launch_get_hit() {
    let Some((probe, _, _)) = start("System32", Vec::new()) else {
        return;
    };
    let first = next_stop(&probe);
    let target = first.to_image(first.code[2].address);
    probe.send(Command::Stop);
    wait_exit(&probe);

    let Some((session, _, _)) = start("System32", vec![target]) else {
        return;
    };
    let entry = next_stop(&session);
    assert_eq!(entry.reason, StopReason::Entry);
    session.send(Command::Continue);
    let hit = next_stop(&session);
    assert_eq!(hit.reason, StopReason::Breakpoint);
    assert_eq!(hit.to_image(hit.ip), target);
    session.send(Command::Stop);
    wait_exit(&session);
}

#[test]
fn reports_a_program_that_cannot_start() {
    let session = Session::start(Launch {
        path: PathBuf::from(r"C:\does\not\exist.exe"),
        args: String::new(),
        bits: 64,
        image_base: 0,
        entry: 0,
        breakpoints: Vec::new(),
        hide_console: true,
    });
    assert!(matches!(session.wait(WAIT), Some(Event::Failed(_))));
}
