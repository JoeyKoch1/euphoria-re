use std::net::TcpListener;

use anyhow::{Result, bail, ensure};

use crate::adb::Adb;
use crate::config::AndroidConfig;

// The emulator accepts even console ports in this range and uses console+1 for adb.
pub const PORT_START: u16 = 5554;
pub const PORT_END: u16 = 5682;

pub fn allocate_port(adb: &Adb) -> Result<u16> {
    let used = adb.devices().unwrap_or_default();
    for port in (PORT_START..=PORT_END).step_by(2) {
        let serial = format!("emulator-{port}");
        if used.iter().any(|existing| existing == &serial) {
            continue;
        }
        if !bindable(port) || !bindable(port + 1) {
            continue;
        }
        return Ok(port);
    }
    bail!(
        "No free Android emulator port is available between {PORT_START} and {PORT_END}. Close \
         another emulator and try again."
    )
}

fn bindable(port: u16) -> bool {
    TcpListener::bind(("127.0.0.1", port)).is_ok()
}

pub fn validate_avd_name(name: &str) -> Result<()> {
    ensure!(!name.trim().is_empty(), "No AVD was selected.");
    ensure!(
        name.chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')),
        "The AVD name '{name}' contains characters the emulator does not accept."
    );
    Ok(())
}

pub fn build_args(
    config: &AndroidConfig,
    avd: &str,
    port: u16,
    show_window: bool,
    wipe: bool,
    accel_available: bool,
) -> Vec<String> {
    let mut args = vec![
        "-avd".to_owned(),
        avd.to_owned(),
        "-port".to_owned(),
        port.to_string(),
        // Always boot from a clean machine state; Reset additionally wipes user data.
        "-no-snapshot".to_owned(),
        "-no-boot-anim".to_owned(),
        "-no-audio".to_owned(),
        "-no-metrics".to_owned(),
        "-camera-back".to_owned(),
        "none".to_owned(),
        "-camera-front".to_owned(),
        "none".to_owned(),
        "-gpu".to_owned(),
        config.gpu_mode().to_owned(),
        "-accel".to_owned(),
        if accel_available { "auto" } else { "off" }.to_owned(),
    ];
    if wipe {
        args.push("-wipe-data".to_owned());
    }
    if let Some((width, height)) = config.resolution() {
        args.push("-skin".to_owned());
        args.push(format!("{width}x{height}"));
    }
    if !show_window {
        args.push("-no-window".to_owned());
    }
    args.extend(config.extra_emulator_args().map(str::to_owned));
    args
}

pub fn build_scrcpy_args(config: &AndroidConfig, serial: &str, package: &str) -> Vec<String> {
    let mut args = vec![
        "--serial".to_owned(),
        serial.to_owned(),
        "--video-codec=h264".to_owned(),
        // The emulator runs with -no-audio, and the audio stream can break the control
        // channel on some emulator/scrcpy combinations.
        "--no-audio".to_owned(),
        "--stay-awake".to_owned(),
        format!("--window-title=Euphoria - {package}"),
    ];
    if config.max_fps >= 1 {
        args.push(format!("--max-fps={}", config.max_fps));
    }
    if let Some((width, height)) = config.resolution() {
        args.push(format!("--max-size={}", width.max(height)));
    }
    args.extend(config.extra_scrcpy_args().map(str::to_owned));
    args
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_launch_is_headless_and_hardware_accelerated() {
        let args = build_args(
            &AndroidConfig::default(),
            "euphoria",
            5554,
            false,
            false,
            true,
        );
        assert!(args.windows(2).any(|pair| pair == ["-avd", "euphoria"]));
        assert!(args.windows(2).any(|pair| pair == ["-port", "5554"]));
        assert!(args.windows(2).any(|pair| pair == ["-skin", "1280x720"]));
        assert!(args.windows(2).any(|pair| pair == ["-accel", "auto"]));
        assert!(args.contains(&"-no-window".to_owned()));
        assert!(args.contains(&"-no-snapshot".to_owned()));
        assert!(!args.contains(&"-wipe-data".to_owned()));
        assert!(
            !args
                .windows(2)
                .any(|pair| pair == ["-gpu", "definitely-not-a-gpu"])
        );
    }

    #[test]
    fn window_and_wipe_flags_are_opt_in() {
        let args = build_args(
            &AndroidConfig::default(),
            "euphoria",
            5556,
            true,
            true,
            true,
        );
        assert!(!args.contains(&"-no-window".to_owned()));
        assert!(args.contains(&"-wipe-data".to_owned()));
    }

    #[test]
    fn missing_acceleration_falls_back_to_software() {
        let args = build_args(
            &AndroidConfig::default(),
            "euphoria",
            5554,
            false,
            false,
            false,
        );
        assert!(args.windows(2).any(|pair| pair == ["-accel", "off"]));
    }

    #[test]
    fn avd_default_resolution_skips_the_skin() {
        let config = AndroidConfig {
            width: 0,
            height: 0,
            ..AndroidConfig::default()
        };
        let args = build_args(&config, "euphoria", 5554, false, false, true);
        assert!(!args.contains(&"-skin".to_owned()));
    }

    #[test]
    fn scrcpy_uses_the_requested_resolution_fps_and_serial() {
        let args = build_scrcpy_args(&AndroidConfig::default(), "emulator-5554", "com.a.b");
        assert!(
            args.windows(2)
                .any(|pair| pair == ["--serial", "emulator-5554"])
        );
        assert!(args.contains(&"--max-fps=60".to_owned()));
        assert!(args.contains(&"--max-size=1280".to_owned()));
        assert!(args.contains(&"--video-codec=h264".to_owned()));
        assert!(args.contains(&"--no-audio".to_owned()));
    }

    #[test]
    fn avd_names_cannot_inject_flags() {
        assert!(validate_avd_name("euphoria").is_ok());
        assert!(validate_avd_name("pixel_5 -gpu host").is_err());
        assert!(validate_avd_name("").is_err());
    }
}
