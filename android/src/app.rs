use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};

use crate::discovery::Avd;

#[derive(Clone, Debug)]
pub struct AppInfo {
    pub package: String,
    /// Fully qualified launcher class name, without a package/component slash.
    pub launcher: Option<String>,
    pub min_sdk: Option<u32>,
    pub target_sdk: Option<u32>,
    pub native_abis: Vec<String>,
    pub file_name: String,
    pub sha256: String,
    pub data: Arc<Vec<u8>>,
    pub warnings: Vec<String>,
}

impl AppInfo {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        package: String,
        launcher: Option<String>,
        min_sdk: &str,
        target_sdk: &str,
        native_abis: Vec<String>,
        file_name: String,
        sha256: String,
        data: Arc<Vec<u8>>,
    ) -> Result<Self> {
        let package = package.trim().to_owned();
        validate_package(&package)?;
        ensure!(data.len() >= 22, "The loaded APK is empty or truncated.");
        ensure!(
            data.starts_with(b"PK"),
            "The loaded file is not an APK (it is not a zip archive)."
        );

        let mut warnings = Vec::new();
        let launcher =
            launcher.and_then(
                |launcher| match normalize_launcher(&package, launcher.trim()) {
                    Some(launcher) => Some(launcher),
                    None => {
                        warnings.push(
                        "The manifest's launcher activity has an unusable name; Euphoria will ask \
                         Android for the launcher instead."
                            .to_owned(),
                    );
                        None
                    }
                },
            );
        if launcher.is_none() {
            warnings.push(
                "No MAIN/LAUNCHER activity was found in the manifest; Android will be asked to \
                 resolve one."
                    .to_owned(),
            );
        }

        let mut native_abis: Vec<String> = native_abis
            .into_iter()
            .map(|abi| abi.trim().to_owned())
            .filter(|abi| !abi.is_empty())
            .collect();
        native_abis.sort();
        native_abis.dedup();

        Ok(Self {
            package,
            launcher,
            min_sdk: parse_api_level(min_sdk),
            target_sdk: parse_api_level(target_sdk),
            native_abis,
            file_name,
            sha256,
            data,
            warnings,
        })
    }

    pub fn component(&self) -> Option<String> {
        self.launcher
            .as_ref()
            .map(|class| format!("{}/{}", self.package, class))
    }

    pub fn sdk_text(&self) -> String {
        match (self.min_sdk, self.target_sdk) {
            (Some(min), Some(target)) => format!("API {min}-{target}"),
            (Some(min), None) => format!("API {min}+"),
            (None, Some(target)) => format!("target API {target}"),
            (None, None) => "unknown API".to_owned(),
        }
    }
}

pub fn parse_api_level(value: &str) -> Option<u32> {
    value
        .trim()
        .parse::<u32>()
        .ok()
        .filter(|level| (1..=100).contains(level))
}

// Package names reach the device shell as separate adb arguments, but adb's shell protocol joins
// them before the device shell parses them. Reject anything that could be read as shell syntax
// instead of relying on quoting.
pub fn validate_package(package: &str) -> Result<()> {
    ensure!(
        !package.is_empty(),
        "This APK has no package name, so Android cannot install it."
    );
    ensure!(
        package.len() <= 255,
        "This APK's package name is too long for Android."
    );
    let segments: Vec<&str> = package.split('.').collect();
    ensure!(
        segments.len() >= 2,
        "This APK's package name '{package}' is not a valid Android package name."
    );
    for segment in &segments {
        ensure!(
            !segment.is_empty() && segment.len() <= 63,
            "This APK's package name '{package}' is not a valid Android package name."
        );
        let mut chars = segment.chars();
        let first = chars.next().unwrap_or(' ');
        ensure!(
            first.is_ascii_alphabetic() && chars.all(|ch| ch.is_ascii_alphanumeric() || ch == '_'),
            "This APK's package name '{package}' is not a valid Android package name."
        );
    }
    Ok(())
}

// Accepts ".Main", "Main", "com.example.Main", or "com.example/.Main" and returns the fully
// qualified class name. Anything with characters Android does not allow is rejected.
pub fn normalize_launcher(package: &str, launcher: &str) -> Option<String> {
    let class = launcher
        .split_once('/')
        .map_or(launcher, |(_, class)| class)
        .trim();
    if class.is_empty() {
        return None;
    }
    let class = if class.starts_with('.') {
        format!("{package}{class}")
    } else if class.contains('.') {
        class.to_owned()
    } else {
        format!("{package}.{class}")
    };
    let valid = class.len() <= 255
        && class
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '$'))
        && !class.starts_with('.')
        && !class.ends_with('.');
    valid.then_some(class)
}

pub struct Staging {
    dir: PathBuf,
}

impl Staging {
    pub fn new() -> Result<Self> {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |elapsed| elapsed.as_nanos());
        let dir =
            std::env::temp_dir().join(format!("euphoria-android-{}-{nanos}", std::process::id()));
        fs::create_dir(&dir).with_context(|| format!("cannot create {}", dir.display()))?;
        Ok(Self { dir })
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    // Installs the bytes that are currently loaded, not whatever happens to be on disk at the
    // original path. The digest check makes that explicit.
    pub fn stage_apk(&self, app: &AppInfo) -> Result<PathBuf> {
        let path = self.dir.join(safe_file_name(&app.file_name));
        fs::write(&path, app.data.as_slice())
            .with_context(|| format!("cannot stage the APK at {}", path.display()))?;
        let written = fs::metadata(&path)
            .with_context(|| format!("cannot check {}", path.display()))?
            .len();
        ensure!(
            written == app.data.len() as u64,
            "Staging the APK wrote {written} bytes instead of {}.",
            app.data.len()
        );
        if !app.sha256.trim().is_empty() {
            let digest = Sha256::digest(app.data.as_slice());
            let hex: String = digest.iter().map(|byte| format!("{byte:02x}")).collect();
            ensure!(
                hex.eq_ignore_ascii_case(app.sha256.trim()),
                "The staged APK does not match the SHA-256 of the loaded APK."
            );
        }
        Ok(path)
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

fn safe_file_name(name: &str) -> String {
    let stem = name.rsplit(['/', '\\']).next().unwrap_or(name).trim();
    let mut cleaned: String = stem
        .chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-' | ' ') {
                ch
            } else {
                '_'
            }
        })
        .collect();
    cleaned = cleaned.trim_matches(['.', ' ']).to_owned();
    if cleaned.is_empty() {
        cleaned.push_str("app");
    }
    if !cleaned.to_ascii_lowercase().ends_with(".apk") {
        cleaned.push_str(".apk");
    }
    cleaned
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Compatibility {
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

pub fn compatibility(avd: &Avd, app: &AppInfo) -> Compatibility {
    let mut result = Compatibility::default();
    if let Some(error) = &avd.error {
        result.errors.push(error.clone());
        return result;
    }

    if let (Some(min), Some(api)) = (app.min_sdk, avd.api)
        && min > api
    {
        result.errors.push(format!(
            "{} requires Android API {min}, but the AVD {} is API {api}. Create or select a newer \
             AVD.",
            app.file_name, avd.name
        ));
    }
    if avd.api.is_none() {
        result.warnings.push(format!(
            "Euphoria could not read the API level of AVD {}. It may be too old for this APK.",
            avd.name
        ));
    }
    if let (Some(target), Some(api)) = (app.target_sdk, avd.api)
        && target > api
    {
        result.warnings.push(format!(
            "{} targets API {target}, but AVD {} is API {api}. The app may use features this \
             emulator does not provide.",
            app.file_name, avd.name
        ));
    }
    if !app.native_abis.is_empty()
        && let Some(abi) = &avd.abi
    {
        let device: Vec<String> = avd.abi_family();
        if !app
            .native_abis
            .iter()
            .any(|apk_abi| device.iter().any(|supported| supported == apk_abi))
        {
            result
                .warnings
                .push(abi_warning(&app.native_abis, &device, abi));
        }
    }
    if avd.play_store {
        result.warnings.push(format!(
            "AVD {} is a Play Store image. adb root and writable system partitions are usually \
             unavailable there; a Google APIs or AOSP image is easier to debug.",
            avd.name
        ));
    }
    result
}

pub fn device_abi_warning(app: &AppInfo, device_abis: &[String]) -> Option<String> {
    if app.native_abis.is_empty() || device_abis.is_empty() {
        return None;
    }
    let device = expand_abilist(device_abis);
    if app
        .native_abis
        .iter()
        .any(|apk_abi| device.iter().any(|supported| supported == apk_abi))
    {
        return None;
    }
    Some(abi_warning(
        &app.native_abis,
        &device,
        &device_abis.join(", "),
    ))
}

fn abi_warning(apk_abis: &[String], device_abis: &[String], device_label: &str) -> String {
    format!(
        "Architecture mismatch: the APK contains native libraries for {} but the emulator \
         supports {}. x86_64 images do not generally run ARM libraries. Use an APK with a \
         matching ABI, or select an AVD for the APK's architecture (ARM emulation on x86 hosts \
         is often very slow).",
        apk_abis.join(", "),
        if device_abis.is_empty() {
            device_label.to_owned()
        } else {
            device_abis.join(", ")
        }
    )
}

fn expand_abilist(abis: &[String]) -> Vec<String> {
    let mut expanded: BTreeSet<String> = abis.iter().cloned().collect();
    if abis.iter().any(|abi| abi == "x86_64") {
        expanded.insert("x86".to_owned());
    }
    if abis.iter().any(|abi| abi == "arm64-v8a") {
        expanded.insert("armeabi-v7a".to_owned());
        expanded.insert("armeabi".to_owned());
    }
    expanded.into_iter().collect()
}

// Picks the best installed AVD: matching architecture first, then an API level at or above the
// target, then a non-Play-Store image, then the closest API level.
pub fn choose_avd<'a>(avds: &'a [Avd], app: &AppInfo) -> Option<&'a Avd> {
    avds.iter()
        .filter(|avd| avd.error.is_none())
        .filter(|avd| match (app.min_sdk, avd.api) {
            (Some(min), Some(api)) => api >= min,
            _ => true,
        })
        .max_by(|left, right| {
            score(left, app)
                .cmp(&score(right, app))
                .then_with(|| right.name.cmp(&left.name))
        })
}

fn score(avd: &Avd, app: &AppInfo) -> i64 {
    let mut score = 0;
    if !app.native_abis.is_empty()
        && let Some(abi) = &avd.abi
    {
        let family = avd.abi_family();
        if family.iter().any(|supported| supported == abi)
            && app
                .native_abis
                .iter()
                .any(|apk_abi| family.iter().any(|supported| supported == apk_abi))
        {
            score += 1000;
        }
    }
    if let (Some(target), Some(api)) = (app.target_sdk, avd.api) {
        if api >= target {
            score += 100;
        }
        score -= i64::from(api.abs_diff(target).min(1000));
    }
    if !avd.play_store {
        score += 20;
    }
    if avd.tag.contains("google_apis") {
        score += 10;
    }
    score
}

pub fn select_avd<'a>(avds: &'a [Avd], configured: &str, app: &AppInfo) -> Result<&'a Avd> {
    let configured = configured.trim();
    if !configured.is_empty() {
        let avd = avds
            .iter()
            .find(|avd| avd.name == configured)
            .with_context(|| {
                let available: Vec<&str> = avds.iter().map(|avd| avd.name.as_str()).collect();
                if available.is_empty() {
                    format!("AVD '{configured}' was not found, and no AVDs are installed.")
                } else {
                    format!(
                        "AVD '{configured}' was not found. Installed AVDs: {}.",
                        available.join(", ")
                    )
                }
            })?;
        let issues = compatibility(avd, app);
        if !issues.errors.is_empty() {
            bail!("{}", issues.errors.join("\n"));
        }
        return Ok(avd);
    }

    if let Some(avd) = choose_avd(avds, app) {
        return Ok(avd);
    }
    if avds.is_empty() {
        bail!(
            "No Android Virtual Device is installed. Create one with avdmanager or Android \
             Studio's Device Manager."
        );
    }
    let available = avds
        .iter()
        .map(|avd| {
            let api = avd
                .api
                .map_or_else(|| "unknown API".to_owned(), |api| format!("API {api}"));
            format!("{} ({api})", avd.name)
        })
        .collect::<Vec<_>>()
        .join(", ");
    bail!(
        "No installed AVD meets this APK's requirements. Installed: {available}. Create an AVD \
         with API {} or newer.",
        app.min_sdk.unwrap_or(21)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn app(abis: &[&str], min_sdk: &str, target_sdk: &str) -> AppInfo {
        AppInfo::new(
            "com.example.app".to_owned(),
            Some(".MainActivity".to_owned()),
            min_sdk,
            target_sdk,
            abis.iter().map(|abi| (*abi).to_owned()).collect(),
            "app.apk".to_owned(),
            String::new(),
            Arc::new(b"PK\x05\x06\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0".to_vec()),
        )
        .unwrap()
    }

    fn avd(name: &str, api: u32, abi: &str) -> Avd {
        Avd {
            name: name.to_owned(),
            display_name: name.to_owned(),
            path: PathBuf::from(name),
            api: Some(api),
            abi: Some(abi.to_owned()),
            tag: "google_apis".to_owned(),
            width: None,
            height: None,
            density: None,
            play_store: false,
            error: None,
        }
    }

    #[test]
    fn launcher_names_are_normalized() {
        assert_eq!(
            normalize_launcher("com.a", ".Main").as_deref(),
            Some("com.a.Main")
        );
        assert_eq!(
            normalize_launcher("com.a", "com.a/.Main").as_deref(),
            Some("com.a.Main")
        );
        assert_eq!(
            normalize_launcher("com.a", "Main").as_deref(),
            Some("com.a.Main")
        );
        assert!(normalize_launcher("com.a", "Main; rm -rf /").is_none());
        assert!(normalize_launcher("com.a", "").is_none());
    }

    #[test]
    fn package_names_that_could_reach_the_shell_are_rejected() {
        assert!(validate_package("com.example.app").is_ok());
        assert!(validate_package("single").is_err());
        assert!(validate_package("com..app").is_err());
        assert!(validate_package("1com.app").is_err());
        assert!(validate_package("com.app;id").is_err());
        assert!(validate_package("com.app name").is_err());
        assert!(validate_package("").is_err());
    }

    #[test]
    fn compatibility_finds_old_apis_and_arm_libraries() {
        let arm = app(&["arm64-v8a"], "30", "34");
        let old = compatibility(&avd("old", 29, "x86_64"), &arm);
        assert!(old.errors[0].contains("requires Android API 30"));
        let right_api = compatibility(&avd("new", 34, "x86_64"), &arm);
        assert!(right_api.errors.is_empty());
        assert!(
            right_api
                .warnings
                .iter()
                .any(|w| w.contains("Architecture mismatch"))
        );

        let x86 = app(&["x86_64"], "30", "34");
        assert!(
            compatibility(&avd("new", 34, "x86_64"), &x86)
                .errors
                .is_empty()
        );
        assert!(
            compatibility(&avd("new", 34, "x86_64"), &x86)
                .warnings
                .is_empty()
        );
    }

    #[test]
    fn chooses_a_compatible_avd() {
        let arm = app(&["arm64-v8a"], "30", "34");
        let avds = vec![
            avd("x86-old", 30, "x86_64"),
            avd("arm64", 34, "arm64-v8a"),
            avd("x86-new", 35, "x86_64"),
        ];
        assert_eq!(choose_avd(&avds, &arm).unwrap().name, "arm64");

        let x86 = app(&["x86_64"], "30", "34");
        assert_eq!(choose_avd(&avds, &x86).unwrap().name, "x86-new");

        let no_native = app(&[], "30", "34");
        assert_eq!(choose_avd(&avds, &no_native).unwrap().name, "arm64");
    }

    #[test]
    fn configured_avd_must_satisfy_the_min_sdk() {
        let arm = app(&[], "34", "34");
        let avds = vec![avd("old", 30, "x86_64"), avd("new", 34, "x86_64")];
        assert!(select_avd(&avds, "old", &arm).is_err());
        assert_eq!(select_avd(&avds, "new", &arm).unwrap().name, "new");
        assert!(select_avd(&avds, "missing", &arm).is_err());
    }

    #[test]
    fn staging_installs_the_loaded_bytes_and_cleans_up() {
        let app = app(&[], "30", "34");
        let staging = Staging::new().unwrap();
        let path = staging.stage_apk(&app).unwrap();
        assert_eq!(fs::read(&path).unwrap(), app.data.as_slice());
        let dir = staging.dir().to_owned();
        drop(staging);
        assert!(!dir.exists());
    }

    #[test]
    fn unsafe_file_names_stay_inside_the_staging_directory() {
        assert_eq!(safe_file_name("../../../evil.apk"), "evil.apk");
        assert_eq!(safe_file_name("..\\..\\evil.bin"), "evil.bin.apk");
        assert_eq!(safe_file_name(""), "app.apk");
        assert_eq!(safe_file_name("app.APK"), "app.APK");
    }
}
