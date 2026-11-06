use std::fs;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

const FILE_NAME: &str = "android.json";
pub const DEFAULT_BOOT_TIMEOUT_SECS: u64 = 300;
pub const DEFAULT_WIDTH: u32 = 1280;
pub const DEFAULT_HEIGHT: u32 = 720;
pub const DEFAULT_MAX_FPS: u32 = 60;

// Written to <settings>/Euphoria/android.json. Everything is optional; empty paths mean
// "find it yourself", so a working Android Studio install needs no configuration at all.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct AndroidConfig {
    pub sdk_root: String,
    pub emulator_path: String,
    pub adb_path: String,
    pub scrcpy_path: String,
    pub avd: String,
    pub width: u32,
    pub height: u32,
    pub max_fps: u32,
    pub show_emulator_window: bool,
    pub grant_permissions: bool,
    pub reduce_animations: bool,
    pub apply_wallpaper: bool,
    pub capture_network: bool,
    pub allow_software_accel: bool,
    pub gpu: String,
    pub boot_timeout_secs: u64,
    pub extra_emulator_args: Vec<String>,
    pub extra_scrcpy_args: Vec<String>,
}

impl Default for AndroidConfig {
    fn default() -> Self {
        Self {
            sdk_root: String::new(),
            emulator_path: String::new(),
            adb_path: String::new(),
            scrcpy_path: String::new(),
            avd: String::new(),
            width: DEFAULT_WIDTH,
            height: DEFAULT_HEIGHT,
            max_fps: DEFAULT_MAX_FPS,
            show_emulator_window: false,
            grant_permissions: true,
            reduce_animations: true,
            apply_wallpaper: true,
            capture_network: true,
            allow_software_accel: false,
            gpu: "auto".to_owned(),
            boot_timeout_secs: DEFAULT_BOOT_TIMEOUT_SECS,
            extra_emulator_args: Vec::new(),
            extra_scrcpy_args: Vec::new(),
        }
    }
}

impl AndroidConfig {
    // A missing or broken file gives the defaults; configuration should never stop Euphoria.
    pub fn load() -> Self {
        Self::load_from(&config_path())
    }

    fn load_from(path: &Path) -> Self {
        fs::read(path)
            .ok()
            .and_then(|bytes| serde_json::from_slice(&bytes).ok())
            .unwrap_or_default()
    }

    pub fn save(&self) -> Result<()> {
        self.save_to(&config_path())
    }

    fn save_to(&self, path: &Path) -> Result<()> {
        if let Some(dir) = path.parent() {
            fs::create_dir_all(dir)?;
        }
        let text = serde_json::to_vec_pretty(self)?;
        fs::write(path, text).with_context(|| format!("cannot write {}", path.display()))
    }

    pub fn resolution(&self) -> Option<(u32, u32)> {
        (self.width > 0 && self.height > 0).then_some((self.width, self.height))
    }

    // Unknown values fall back to auto instead of being passed through to the emulator.
    pub fn gpu_mode(&self) -> &'static str {
        match self.gpu.as_str() {
            "host" => "host",
            "angle" => "angle",
            "swiftshader_indirect" => "swiftshader_indirect",
            "guest" => "guest",
            _ => "auto",
        }
    }

    pub fn extra_emulator_args(&self) -> impl Iterator<Item = &str> {
        self.extra_emulator_args
            .iter()
            .map(String::as_str)
            .filter(|arg| !arg.trim().is_empty())
    }

    pub fn extra_scrcpy_args(&self) -> impl Iterator<Item = &str> {
        self.extra_scrcpy_args
            .iter()
            .map(String::as_str)
            .filter(|arg| !arg.trim().is_empty())
    }
}

// Matches the folder the plugin host and community config already use.
pub fn settings_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("Euphoria")
}

pub fn config_path() -> PathBuf {
    settings_dir().join(FILE_NAME)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn temporary(name: &str) -> PathBuf {
        std::env::temp_dir().join(format!(
            "euphoria-android-config-{}-{name}.json",
            std::process::id()
        ))
    }

    #[test]
    fn bad_files_fall_back_to_defaults() {
        let path = temporary("missing");
        let _ = fs::remove_file(&path);
        assert_eq!(AndroidConfig::load_from(&path), AndroidConfig::default());

        fs::write(&path, b"not json").unwrap();
        assert_eq!(AndroidConfig::load_from(&path), AndroidConfig::default());
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn settings_round_trip() {
        let path = temporary("roundtrip");
        let mut config = AndroidConfig {
            sdk_root: "/opt/android".to_owned(),
            avd: "euphoria".to_owned(),
            width: 1920,
            height: 1080,
            max_fps: 30,
            ..AndroidConfig::default()
        };
        config
            .extra_scrcpy_args
            .push("--turn-screen-off".to_owned());
        config.save_to(&path).unwrap();
        assert_eq!(AndroidConfig::load_from(&path), config);
        let _ = fs::remove_file(&path);
    }

    #[test]
    fn invalid_gpu_and_resolution_are_ignored() {
        let config = AndroidConfig {
            gpu: "definitely-not-a-gpu".to_owned(),
            width: 0,
            height: 720,
            ..AndroidConfig::default()
        };
        assert_eq!(config.gpu_mode(), "auto");
        assert_eq!(config.resolution(), None);
    }
}
