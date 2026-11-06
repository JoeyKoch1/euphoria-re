use std::fs;
use std::path::Path;

use anyhow::{Context, Result, ensure};

use crate::adb::Adb;

// Built from android/assets/SetWallpaper.java with javac + d8 (min API 34). It asks the
// wallpaper service for a write descriptor and copies the JPEG into it. `shell` (uid 2000)
// already holds android.permission.SET_WALLPAPER on the emulator images, so no root is needed.
const HELPER: &[u8] = include_bytes!("../assets/SetWallpaper.dex");
const IMAGE: &[u8] = include_bytes!("../../logo.jpg");

const REMOTE_DEX: &str = "/data/local/tmp/euphoria-wallpaper.dex";
const REMOTE_IMAGE: &str = "/data/local/tmp/euphoria-wallpaper.jpg";
const REMOTE_COMMAND: &str = "app_process";

pub fn apply(adb: &Adb, serial: &str, dir: &Path) -> Result<()> {
    let dex = dir.join("euphoria-wallpaper.dex");
    let image = dir.join("euphoria-wallpaper.jpg");
    fs::write(&dex, HELPER).with_context(|| format!("cannot write {}", dex.display()))?;
    fs::write(&image, IMAGE).with_context(|| format!("cannot write {}", image.display()))?;

    let outcome = (|| {
        adb.push(serial, &dex, REMOTE_DEX)
            .context("cannot copy the wallpaper helper to the device")?;
        adb.push(serial, &image, REMOTE_IMAGE)
            .context("cannot copy the wallpaper image to the device")?;
        let output = adb
            .run_app_process(serial, REMOTE_DEX, REMOTE_IMAGE)
            .context("cannot run the wallpaper helper")?;
        let text = output.combined();
        ensure!(
            output.success && text.contains("wrote image"),
            "Android refused to set the wallpaper: {}",
            if text.trim().is_empty() {
                "the helper returned no output"
            } else {
                text.trim()
            }
        );
        Ok(())
    })();

    // The helper is only useful once; do not leave files in the disposable device's /tmp.
    let _ = adb.remove_files(serial, &[REMOTE_DEX, REMOTE_IMAGE]);
    outcome
}

// Kept next to the command builder so a future change to the helper and its invocation stays in
// one place.
pub fn command(dex: &str, image: &str) -> [String; 5] {
    [
        REMOTE_COMMAND.to_owned(),
        format!("-Djava.class.path={dex}"),
        "/system/bin".to_owned(),
        "SetWallpaper".to_owned(),
        image.to_owned(),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embedded_assets_are_usable() {
        assert!(
            HELPER.starts_with(b"dex\n"),
            "the wallpaper helper must be a DEX file"
        );
        assert!(
            IMAGE.starts_with(&[0xff, 0xd8, 0xff]),
            "the default wallpaper must be a JPEG"
        );
        assert!(HELPER.len() > 512);
        assert!(IMAGE.len() > 1024);
    }

    #[test]
    fn the_helper_receives_only_its_classpath_and_image() {
        let command = command("/data/local/tmp/wp.dex", "/data/local/tmp/wp.jpg");
        assert_eq!(command[0], "app_process");
        assert_eq!(command[1], "-Djava.class.path=/data/local/tmp/wp.dex");
        assert_eq!(command[2], "/system/bin");
        assert_eq!(command[3], "SetWallpaper");
        assert_eq!(command[4], "/data/local/tmp/wp.jpg");
        assert!(!command.iter().any(|arg| arg.contains(' ')));
    }
}
