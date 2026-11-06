use std::ffi::OsStr;
use std::fs::File;
use std::io::Read;
use std::path::Path;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::thread;
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};

const LOG_TAIL_BYTES: u64 = 64 * 1024;

pub(crate) struct Output {
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

impl Output {
    pub fn combined(&self) -> String {
        let mut text = self.stdout.trim().to_owned();
        let stderr = self.stderr.trim();
        if !stderr.is_empty() {
            if !text.is_empty() {
                text.push('\n');
            }
            text.push_str(stderr);
        }
        text
    }
}

// Runs a short command and always returns its output, even when it fails. The pipes are drained
// on separate threads so a chatty child cannot fill a pipe and deadlock the wait loop.
pub(crate) fn run_capture<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    timeout: Duration,
) -> Result<Output> {
    let mut child = Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("cannot start {}", program.display()))?;

    let stdout = child.stdout.take().context("missing stdout pipe")?;
    let stderr = child.stderr.take().context("missing stderr pipe")?;
    let out_reader = thread::spawn(move || read_all(stdout));
    let err_reader = thread::spawn(move || read_all(stderr));

    let deadline = Instant::now() + timeout;
    let status = loop {
        match child.try_wait()? {
            Some(status) => break status,
            None if Instant::now() >= deadline => {
                let _ = child.kill();
                let _ = child.wait();
                let _ = out_reader.join();
                let _ = err_reader.join();
                bail!(
                    "{} did not finish within {} s",
                    program.display(),
                    timeout.as_secs()
                );
            }
            None => thread::sleep(Duration::from_millis(25)),
        }
    };

    let stdout = out_reader.join().unwrap_or_default();
    let stderr = err_reader.join().unwrap_or_default();
    Ok(Output {
        success: status.success(),
        stdout: String::from_utf8_lossy(&stdout).into_owned(),
        stderr: String::from_utf8_lossy(&stderr).into_owned(),
    })
}

fn read_all(mut reader: impl Read) -> Vec<u8> {
    let mut bytes = Vec::new();
    let _ = reader.read_to_end(&mut bytes);
    bytes
}

// Long-lived processes write to a log file. Where a running emulator failed is much easier to
// explain with its last lines than with an exit code alone.
pub(crate) fn spawn_logged<S: AsRef<OsStr>>(
    program: &Path,
    args: &[S],
    log_path: &Path,
) -> Result<Child> {
    let log =
        File::create(log_path).with_context(|| format!("cannot create {}", log_path.display()))?;
    let errors = log
        .try_clone()
        .with_context(|| format!("cannot share {}", log_path.display()))?;
    Command::new(program)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::from(log))
        .stderr(Stdio::from(errors))
        .spawn()
        .with_context(|| format!("cannot start {}", program.display()))
}

pub(crate) fn tail(path: &Path, max_lines: usize) -> String {
    let Ok(mut file) = File::open(path) else {
        return String::new();
    };
    let length = file.metadata().map(|meta| meta.len()).unwrap_or(0);
    if length > LOG_TAIL_BYTES {
        use std::io::{Seek, SeekFrom};
        let _ = file.seek(SeekFrom::Start(length - LOG_TAIL_BYTES));
    }
    let mut bytes = Vec::new();
    let _ = file.read_to_end(&mut bytes);
    let text = String::from_utf8_lossy(&bytes);
    let lines: Vec<&str> = text.lines().collect();
    lines[lines.len().saturating_sub(max_lines)..].join("\n")
}

pub(crate) fn wait_for_exit(child: &mut Child, timeout: Duration) -> Option<ExitStatus> {
    let deadline = Instant::now() + timeout;
    loop {
        match child.try_wait() {
            Ok(Some(status)) => return Some(status),
            Ok(None) if Instant::now() >= deadline => return None,
            Ok(None) => thread::sleep(Duration::from_millis(50)),
            Err(_) => return None,
        }
    }
}

// Closing a Windows job handle with KILL_ON_JOB_CLOSE takes any emulator or scrcpy process down
// with Euphoria, even when the UI thread panics. On other platforms the explicit stop path is
// the guarantee; a parent-death signal is not portable.
pub(crate) struct ProcessGuard {
    #[cfg(windows)]
    job: Option<windows_sys::Win32::Foundation::HANDLE>,
}

impl ProcessGuard {
    pub fn new() -> Self {
        #[cfg(windows)]
        {
            Self::create_job()
        }
        #[cfg(not(windows))]
        {
            Self {}
        }
    }

    #[cfg(windows)]
    fn create_job() -> Self {
        use std::mem::{size_of, zeroed};
        use std::ptr::null;
        use windows_sys::Win32::System::JobObjects::{
            CreateJobObjectW, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
            JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JobObjectExtendedLimitInformation,
            SetInformationJobObject,
        };

        // SAFETY: a null security descriptor and name ask for an unnamed, default job.
        let job = unsafe { CreateJobObjectW(null(), null()) };
        if job.is_null() {
            return Self { job: None };
        }

        // SAFETY: the struct is zeroed and its limit flags are the only field we set.
        let mut info: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = unsafe { zeroed() };
        info.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
        let configured = unsafe {
            SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                &info as *const _ as *const core::ffi::c_void,
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            )
        };
        if configured == 0 {
            // SAFETY: the handle came from CreateJobObjectW and is closed exactly once here.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
            return Self { job: None };
        }
        Self { job: Some(job) }
    }

    #[allow(dead_code)]
    pub fn assign(&self, child: &Child) {
        #[cfg(windows)]
        {
            use std::os::windows::io::AsRawHandle;
            use windows_sys::Win32::System::JobObjects::AssignProcessToJobObject;
            if let Some(job) = self.job {
                // SAFETY: both handles are live for the duration of the call.
                unsafe {
                    AssignProcessToJobObject(job, child.as_raw_handle() as _);
                }
            }
        }
        #[cfg(not(windows))]
        {
            let _ = child;
        }
    }
}

impl Drop for ProcessGuard {
    fn drop(&mut self) {
        #[cfg(windows)]
        if let Some(job) = self.job.take() {
            // SAFETY: the handle came from CreateJobObjectW and is closed exactly once.
            unsafe { windows_sys::Win32::Foundation::CloseHandle(job) };
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_end_of_a_log() {
        let path =
            std::env::temp_dir().join(format!("euphoria-android-tail-{}.log", std::process::id()));
        std::fs::write(&path, "one\ntwo\nthree\n").unwrap();
        assert_eq!(tail(&path, 2), "two\nthree");
        assert_eq!(tail(&path, 10).lines().count(), 3);
        let _ = std::fs::remove_file(&path);
    }
}
