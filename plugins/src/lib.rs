mod api;
mod discord;

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::rc::Rc;
use std::sync::Arc;

use euphoria_engine::{Analysis, Arch, Function, Listing, Section, StringEntry, Xref};

use api::Runtime;

pub const API_VERSION: u32 = 1;
pub const PERMISSION_DISCORD: &str = "discord";

const ENABLED_FILE: &str = "enabled.txt";
const MAX_PLUGIN_BYTES: u64 = 4 * 1024 * 1024;
const EXAMPLES: [(&str, &str); 3] = [
    ("hello_tab.lua", include_str!("../examples/hello_tab.lua")),
    (
        "string_search.lua",
        include_str!("../examples/string_search.lua"),
    ),
    (
        "discord_presence.lua",
        include_str!("../examples/discord_presence.lua"),
    ),
];

#[derive(Clone, Debug, PartialEq)]
pub enum Widget {
    Heading(String),
    Label(String),
    Mono(String),
    Separator,
    Button {
        id: usize,
        text: String,
    },
    Input {
        key: String,
        hint: String,
        value: String,
    },
    Checkbox {
        key: String,
        text: String,
        value: bool,
    },
    Row(Vec<Widget>),
    Table {
        headers: Vec<String>,
        rows: Vec<Vec<String>>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum UiEvent {
    Clicked(usize),
    Text { key: String, value: String },
    Toggled { key: String, value: bool },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Jump(u64),
    Status(String),
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Meta {
    pub file: String,
    pub name: String,
    pub version: String,
    pub author: String,
    pub description: String,
    pub permissions: Vec<String>,
}

// Reads the `-- @key value` header without running anything, so a disabled plugin never executes.
pub fn parse_meta(source: &str, file: &str) -> Meta {
    let mut meta = Meta {
        file: file.to_owned(),
        name: Path::new(file)
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned(),
        ..Meta::default()
    };

    for line in source.lines() {
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let Some(comment) = line.strip_prefix("--") else {
            break;
        };
        let Some((key, value)) = comment.trim().split_once(' ') else {
            continue;
        };
        let value = value.trim();
        match key {
            "@name" => meta.name = value.to_owned(),
            "@version" => meta.version = value.to_owned(),
            "@author" => meta.author = value.to_owned(),
            "@description" => meta.description = value.to_owned(),
            "@permissions" => {
                meta.permissions = value
                    .split([',', ' '])
                    .filter(|permission| !permission.is_empty())
                    .map(str::to_owned)
                    .collect();
            }
            _ => {}
        }
    }
    meta
}

pub struct BinaryView {
    pub name: String,
    pub arch: &'static str,
    pub sha256: String,
    pub entry: u64,
    pub data: Arc<Vec<u8>>,
    pub sections: Vec<Section>,
    pub functions: Vec<Function>,
    pub strings: Vec<StringEntry>,
    pub xrefs: Vec<Xref>,
}

impl BinaryView {
    // A file with no x86 analysis behind it, such as an APK.
    pub fn named(name: String, arch: &'static str, sha256: String, data: Arc<Vec<u8>>) -> Self {
        Self {
            name,
            arch,
            sha256,
            entry: 0,
            data,
            sections: Vec::new(),
            functions: Vec::new(),
            strings: Vec::new(),
            xrefs: Vec::new(),
        }
    }

    pub fn new(analysis: &Analysis, listing: &Listing) -> Self {
        Self {
            name: analysis.file_name.clone(),
            arch: match analysis.arch {
                Arch::X86_64 => "x86_64",
                Arch::X86 => "x86",
                Arch::Aarch64 => "aarch64",
            },
            sha256: analysis.sha256.clone(),
            entry: analysis.entry,
            data: Arc::clone(&analysis.data),
            sections: analysis.sections.clone(),
            functions: analysis.functions.clone(),
            strings: listing.strings.clone(),
            xrefs: listing.xrefs.clone(),
        }
    }
}

pub struct Entry {
    pub meta: Meta,
    pub path: PathBuf,
    pub enabled: bool,
    pub error: Option<String>,
    runtime: Option<Runtime>,
}

impl Entry {
    pub fn is_running(&self) -> bool {
        self.runtime.is_some()
    }

    pub fn log(&self) -> Vec<String> {
        self.runtime
            .as_ref()
            .map_or_else(Vec::new, Runtime::log_lines)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TabInfo {
    pub plugin: usize,
    pub tab: usize,
    pub title: String,
}

pub struct PluginHost {
    dir: PathBuf,
    entries: Vec<Entry>,
    view: Option<Rc<BinaryView>>,
    requests: Vec<Request>,
    tab: String,
}

pub fn default_dir() -> PathBuf {
    let base = std::env::var_os("APPDATA")
        .or_else(|| std::env::var_os("XDG_CONFIG_HOME"))
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))
        .unwrap_or_else(std::env::temp_dir);
    base.join("Euphoria").join("plugins")
}

impl PluginHost {
    pub fn open(dir: PathBuf) -> Self {
        let mut host = Self {
            dir,
            entries: Vec::new(),
            view: None,
            requests: Vec::new(),
            tab: String::new(),
        };
        host.refresh();
        host
    }

    pub fn dir(&self) -> &Path {
        &self.dir
    }

    pub fn entries(&self) -> &[Entry] {
        &self.entries
    }

    // Reads the plugin folder again. Running plugins restart, so edits to their files take effect.
    pub fn refresh(&mut self) {
        let enabled = self.read_enabled();
        self.entries.clear();

        let mut paths: Vec<PathBuf> = fs::read_dir(&self.dir)
            .into_iter()
            .flatten()
            .flatten()
            .map(|item| item.path())
            .filter(|path| path.extension().is_some_and(|extension| extension == "lua"))
            .collect();
        paths.sort();

        for path in paths {
            let file = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned();
            let is_enabled = enabled.contains(&file);
            let source = read_source(&path);
            let meta = parse_meta(source.as_deref().unwrap_or(""), &file);
            let mut entry = Entry {
                meta,
                path,
                enabled: is_enabled,
                error: source.as_ref().err().cloned(),
                runtime: None,
            };
            if is_enabled && let Ok(source) = &source {
                start(&mut entry, source, self.view.clone(), &self.tab);
            }
            self.entries.push(entry);
        }
    }

    fn read_enabled(&self) -> BTreeSet<String> {
        fs::read_to_string(self.dir.join(ENABLED_FILE))
            .unwrap_or_default()
            .lines()
            .map(str::to_owned)
            .collect()
    }

    fn write_enabled(&self) -> std::io::Result<()> {
        fs::create_dir_all(&self.dir)?;
        let files: Vec<&str> = self
            .entries
            .iter()
            .filter(|entry| entry.enabled)
            .map(|entry| entry.meta.file.as_str())
            .collect();
        fs::write(self.dir.join(ENABLED_FILE), files.join("\n"))
    }

    pub fn set_enabled(&mut self, plugin: usize, enabled: bool) {
        let view = self.view.clone();
        let tab = self.tab.clone();
        let Some(entry) = self.entries.get_mut(plugin) else {
            return;
        };
        entry.enabled = enabled;
        entry.runtime = None;
        entry.error = None;
        if enabled {
            match read_source(&entry.path) {
                Ok(source) => start(entry, &source, view, &tab),
                Err(error) => entry.error = Some(error),
            }
        }
        if let Err(error) = self.write_enabled() {
            self.requests.push(Request::Status(format!(
                "Could not save the plugin list: {error}"
            )));
        }
    }

    pub fn install_examples(&mut self) -> std::io::Result<usize> {
        fs::create_dir_all(&self.dir)?;
        let mut added = 0;
        for (file, source) in EXAMPLES {
            let path = self.dir.join(file);
            use std::io::Write;
            match fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(path)
            {
                Ok(mut output) => {
                    output.write_all(source.as_bytes())?;
                    added += 1;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
                Err(error) => return Err(error),
            }
        }
        self.refresh();
        Ok(added)
    }

    pub fn tabs(&self) -> Vec<TabInfo> {
        let mut tabs = Vec::new();
        for (plugin, entry) in self.entries.iter().enumerate() {
            if let Some(runtime) = &entry.runtime {
                for (tab, title) in runtime.tab_titles().into_iter().enumerate() {
                    tabs.push(TabInfo { plugin, tab, title });
                }
            }
        }
        tabs
    }

    pub fn draw(&mut self, plugin: usize, tab: usize, events: Vec<UiEvent>) -> Option<Vec<Widget>> {
        let entry = self.entries.get_mut(plugin)?;
        let runtime = entry.runtime.as_ref()?;
        match runtime.draw_tab(tab, events) {
            Ok(widgets) => {
                self.requests.extend(runtime.take_requests());
                Some(widgets)
            }
            Err(error) => {
                fail(entry, error);
                None
            }
        }
    }

    pub fn set_binary(&mut self, view: Option<BinaryView>) {
        self.view = view.map(Rc::new);
        for entry in &mut self.entries {
            if let Some(runtime) = &entry.runtime {
                runtime.set_view(self.view.clone());
                if self.view.is_some() {
                    emit(entry, &mut self.requests, "binary_opened", None);
                }
            }
        }
    }

    pub fn emit_tab_changed(&mut self, title: &str) {
        title.clone_into(&mut self.tab);
        for entry in &mut self.entries {
            if let Some(runtime) = &entry.runtime {
                runtime.set_tab(title);
            }
            emit(entry, &mut self.requests, "tab_changed", Some(title));
        }
    }

    pub fn tick(&mut self) {
        for entry in &mut self.entries {
            emit(entry, &mut self.requests, "tick", None);
        }
    }

    pub fn wants_ticks(&self) -> bool {
        self.entries
            .iter()
            .filter_map(|entry| entry.runtime.as_ref())
            .any(|runtime| runtime.has_handler("tick"))
    }

    pub fn take_requests(&mut self) -> Vec<Request> {
        std::mem::take(&mut self.requests)
    }
}

fn read_source(path: &Path) -> Result<String, String> {
    let size = fs::metadata(path).map_err(|error| error.to_string())?.len();
    if size > MAX_PLUGIN_BYTES {
        return Err("This plugin file is too large".to_owned());
    }
    fs::read_to_string(path).map_err(|error| error.to_string())
}

fn start(entry: &mut Entry, source: &str, view: Option<Rc<BinaryView>>, tab: &str) {
    let has_binary = view.is_some();
    match Runtime::load_on_tab(source, &entry.meta, view, tab) {
        Ok(runtime) => {
            entry.runtime = Some(runtime);
            if has_binary {
                let mut ignored = Vec::new();
                emit(entry, &mut ignored, "binary_opened", None);
            }
        }
        Err(error) => entry.error = Some(error),
    }
}

fn emit(entry: &mut Entry, requests: &mut Vec<Request>, event: &str, argument: Option<&str>) {
    let Some(runtime) = &entry.runtime else {
        return;
    };
    match runtime.emit(event, argument) {
        Ok(()) => requests.extend(runtime.take_requests()),
        Err(error) => fail(entry, error),
    }
}

fn fail(entry: &mut Entry, error: String) {
    entry.runtime = None;
    entry.error = Some(error);
}

// Sends one activity to the Discord app on this machine and returns Discord's reply.
pub fn check_discord(
    client_id: &str,
    details: &str,
    state: &str,
    hold: std::time::Duration,
) -> Result<serde_json::Value, String> {
    if !discord::is_valid_client_id(client_id) {
        return Err("A Discord application ID is a string of digits".to_owned());
    }

    let client = discord::Discord::connect(client_id.to_owned());
    client.set_activity(discord::Activity {
        details: Some(details.to_owned()),
        state: Some(state.to_owned()),
        large_image: Some(
            "https://raw.githubusercontent.com/JoeyKoch1/euphoria-re/main/logo.jpg".to_owned(),
        ),
        large_text: Some("Euphoria".to_owned()),
        started: true,
    });

    let waited = std::time::Instant::now();
    while waited.elapsed() < std::time::Duration::from_secs(10) {
        if let Some(reply) = client.last_reply() {
            std::thread::sleep(hold);
            return Ok(reply);
        }
        let status = client.status();
        if status.starts_with("not connected") || status == "disconnected" {
            return Err(status);
        }
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    Err(format!(
        "No reply from Discord, status: {}",
        client.status()
    ))
}

// Runs one plugin file without the app, for testing plugins and for scripting.
pub fn run_once(path: &Path, view: Option<BinaryView>) -> Result<Vec<String>, String> {
    let source = read_source(path)?;
    let file = path
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .into_owned();
    let meta = parse_meta(&source, &file);
    let has_binary = view.is_some();
    let runtime = Runtime::load(&source, &meta, view.map(Rc::new))?;
    if has_binary {
        runtime.emit("binary_opened", None)?;
    }
    Ok(runtime.log_lines())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("euphoria-plugins-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn reads_the_header_without_running_the_plugin() {
        let source = "-- @name Fancy Tool\n-- @version 1.2\n-- @author Ana\n-- @description Does things\n-- @permissions discord, other\n\nerror('must not run')\n-- @name Not This";
        let meta = parse_meta(source, "fancy.lua");

        assert_eq!(meta.name, "Fancy Tool");
        assert_eq!(meta.version, "1.2");
        assert_eq!(meta.author, "Ana");
        assert_eq!(meta.description, "Does things");
        assert_eq!(meta.permissions, ["discord", "other"]);
    }

    #[test]
    fn falls_back_to_the_file_name() {
        assert_eq!(parse_meta("print(1)", "plain.lua").name, "plain");
    }

    #[test]
    fn plugins_stay_off_until_enabled_and_the_choice_persists() {
        let dir = scratch("enable");
        fs::write(
            dir.join("a.lua"),
            "euphoria.add_tab('A', function(ui) ui:label('hi') end)",
        )
        .unwrap();

        let mut host = PluginHost::open(dir.clone());
        assert_eq!(host.entries().len(), 1);
        assert!(!host.entries()[0].is_running());
        assert!(host.tabs().is_empty());

        host.set_enabled(0, true);
        assert_eq!(host.tabs()[0].title, "A");
        assert_eq!(
            host.draw(0, 0, Vec::new()),
            Some(vec![Widget::Label("hi".to_owned())])
        );

        let reopened = PluginHost::open(dir.clone());
        assert!(reopened.entries()[0].is_running());

        host.set_enabled(0, false);
        assert!(host.tabs().is_empty());
        assert!(!PluginHost::open(dir.clone()).entries()[0].is_running());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn a_failing_plugin_is_stopped_and_reports_why() {
        let dir = scratch("failing");
        fs::write(
            dir.join("bad.lua"),
            "euphoria.add_tab('Bad', function(ui) error('boom') end)",
        )
        .unwrap();
        fs::write(dir.join("syntax.lua"), "this is not lua").unwrap();

        let mut host = PluginHost::open(dir.clone());
        host.set_enabled(0, true);
        host.set_enabled(1, true);

        assert!(host.entries()[1].error.is_some());
        assert_eq!(host.draw(0, 0, Vec::new()), None);
        assert!(host.entries()[0].error.as_ref().unwrap().contains("boom"));
        assert!(host.tabs().is_empty());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn installing_examples_preserves_existing_files() {
        let dir = scratch("upgrade");
        let path = dir.join("hello_tab.lua");
        let mut host = PluginHost::open(dir.clone());

        fs::write(&path, "-- @author Euphoria\n-- @version 0.1\n").unwrap();
        host.install_examples().unwrap();
        assert_eq!(
            fs::read_to_string(&path).unwrap(),
            "-- @author Euphoria\n-- @version 0.1\n"
        );

        fs::write(&path, "-- @author Someone Else\n-- @version 0.1\n").unwrap();
        host.install_examples().unwrap();
        assert!(fs::read_to_string(&path).unwrap().contains("Someone Else"));
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn plugins_can_read_the_current_tab() {
        let dir = scratch("tab");
        fs::write(
            dir.join("t.lua"),
            "euphoria.on('tab_changed', function(title) print(title, euphoria.tab()) end)\nprint(euphoria.tab())",
        )
        .unwrap();

        let mut host = PluginHost::open(dir.clone());
        host.emit_tab_changed("Graph");
        host.set_enabled(0, true);
        host.emit_tab_changed("Strings");
        assert_eq!(host.entries()[0].log(), ["Graph", "Strings Strings"]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn opening_plugins_preserves_older_examples() {
        let dir = scratch("opens-upgraded");
        fs::create_dir_all(&dir).unwrap();
        let old = "-- @name Discord Presence\n-- @version 2.0\n-- @author Euphoria\n";
        fs::write(dir.join("discord_presence.lua"), old).unwrap();
        let mine = "-- @name String Search\n-- @version 9.9\n-- @author Someone\n";
        fs::write(dir.join("string_search.lua"), mine).unwrap();

        let _host = PluginHost::open(dir.clone());

        let upgraded = fs::read_to_string(dir.join("discord_presence.lua")).unwrap();
        assert!(!upgraded.contains("button"));
        assert_eq!(upgraded, old);
        assert_eq!(
            fs::read_to_string(dir.join("string_search.lua")).unwrap(),
            mine
        );
        assert!(!dir.join("hello_tab.lua").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn bundled_examples_install_and_load() {
        let dir = scratch("examples");
        let mut host = PluginHost::open(dir.clone());

        assert_eq!(host.install_examples().unwrap(), EXAMPLES.len());
        assert_eq!(host.install_examples().unwrap(), 0);
        for plugin in 0..host.entries().len() {
            host.set_enabled(plugin, true);
            assert_eq!(host.entries()[plugin].error, None);
        }
        assert!(host.tabs().len() >= EXAMPLES.len());
        for tab in host.tabs() {
            assert!(host.draw(tab.plugin, tab.tab, Vec::new()).is_some());
        }
        let _ = fs::remove_dir_all(dir);
    }
}
