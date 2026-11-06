#![cfg(all(windows, target_arch = "x86_64"))]

// Exercises the live-process API against a real child program (ping), which is safe and disposable.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use euphoria_debugger::live::{self, LiveProcess};

const WAIT: Duration = Duration::from_secs(10);

fn ping() -> Option<&'static Path> {
    let path = Path::new(r"C:\Windows\System32\ping.exe");
    path.is_file().then_some(path)
}

fn spawn(path: &Path) -> Child {
    Command::new(path)
        .args(["-n", "30", "127.0.0.1"])
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("start ping")
}

fn wait_for<T>(mut attempt: impl FnMut() -> Option<T>) -> Option<T> {
    let deadline = Instant::now() + WAIT;
    while Instant::now() < deadline {
        if let Some(value) = attempt() {
            return Some(value);
        }
        thread::sleep(Duration::from_millis(50));
    }
    None
}

#[test]
fn suspends_resumes_and_stops_a_running_process() {
    let Some(path) = ping() else {
        return;
    };
    let mut child = spawn(path);
    let pid = child.id();

    let mut process = wait_for(|| LiveProcess::open(pid).ok()).expect("could not open the child");
    assert!(process.is_alive());
    let has_image = wait_for(|| {
        process.refresh_modules();
        process
            .modules()
            .iter()
            .any(|module| module.name.to_ascii_lowercase().contains("ping"))
            .then_some(())
    });
    assert!(has_image.is_some(), "modules: {:?}", process.modules());
    let image = process
        .modules()
        .iter()
        .find(|module| module.name.to_ascii_lowercase().contains("ping"))
        .cloned()
        .expect("the ping image");
    assert_eq!(process.read(image.base, 2), b"MZ");

    let contexts = wait_for(|| {
        let contexts = process.contexts();
        contexts
            .iter()
            .any(|context| context.error.is_none() && context.ip != 0)
            .then_some(contexts)
    })
    .expect("no thread context was readable");
    let thread = contexts
        .iter()
        .find(|context| context.error.is_none() && context.ip != 0)
        .expect("a readable thread");
    assert!(!thread.registers.is_empty());
    assert!(thread.sp != 0);

    assert!(process.regions().iter().any(|region| region.executable()));
    assert!(process.handle_count().is_some_and(|count| count > 0));

    assert!(process.suspend().expect("suspend") >= 1);
    thread::sleep(Duration::from_millis(200));
    assert!(process.is_alive());
    assert!(process.resume().expect("resume") >= 1);

    assert!(
        live::processes()
            .iter()
            .any(|candidate| candidate.pid == pid)
    );

    process.kill().expect("kill");
    assert!(wait_for(|| (!process.is_alive()).then_some(())).is_some());
    let _ = child.wait();
}
