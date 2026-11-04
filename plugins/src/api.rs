use std::cell::{Cell, RefCell};
use std::collections::{HashMap, HashSet};
use std::rc::Rc;
use std::time::{Duration, Instant};

use mlua::{
    ChunkMode, Function, HookTriggers, Lua, LuaOptions, StdLib, Table, UserData, UserDataMethods,
    Value, VmState,
};

use crate::discord::{self, Activity, Discord};
use crate::{API_VERSION, BinaryView, Meta, PERMISSION_DISCORD, Request, UiEvent, Widget};

const MEMORY_LIMIT: usize = 128 * 1024 * 1024;
const LOAD_BUDGET: Duration = Duration::from_secs(2);
const CALL_BUDGET: Duration = Duration::from_millis(250);
const HOOK_INTERVAL: u32 = 10_000;
const MAX_READ_BYTES: usize = 1024 * 1024;
const MAX_LOG_LINES: usize = 500;
const REMOVED_GLOBALS: [&str; 5] = ["dofile", "loadfile", "load", "require", "module"];

#[derive(Default)]
struct TabState {
    texts: HashMap<String, String>,
    checks: HashMap<String, bool>,
    clicked: HashSet<usize>,
    next_id: usize,
    stack: Vec<Vec<Widget>>,
}

impl TabState {
    fn push(&mut self, widget: Widget) {
        if let Some(group) = self.stack.last_mut() {
            group.push(widget);
        }
    }
}

struct TabSlot {
    title: String,
    draw: Function,
    state: Rc<RefCell<TabState>>,
}

struct Shared {
    view: RefCell<Option<Rc<BinaryView>>>,
    tab: RefCell<String>,
    requests: RefCell<Vec<Request>>,
    log: RefCell<Vec<String>>,
    tabs: RefCell<Vec<TabSlot>>,
    handlers: RefCell<Vec<(String, Function)>>,
    deadline: Cell<Instant>,
    permissions: Vec<String>,
    discord: RefCell<Option<Discord>>,
}

impl Shared {
    fn write_log(&self, line: String) {
        let mut log = self.log.borrow_mut();
        if log.len() == MAX_LOG_LINES {
            log.remove(0);
        }
        log.push(line);
    }

    fn require_permission(&self, permission: &str) -> mlua::Result<()> {
        if self.permissions.iter().any(|given| given == permission) {
            return Ok(());
        }
        Err(mlua::Error::runtime(format!(
            "this plugin needs \"-- @permissions {permission}\" in its header"
        )))
    }

    fn view(&self) -> Option<Rc<BinaryView>> {
        self.view.borrow().clone()
    }
}

struct LuaUi(Rc<RefCell<TabState>>);

impl UserData for LuaUi {
    fn add_methods<M: UserDataMethods<Self>>(methods: &mut M) {
        methods.add_method("heading", |_, ui, text: String| {
            ui.0.borrow_mut().push(Widget::Heading(text));
            Ok(())
        });
        methods.add_method("label", |_, ui, text: String| {
            ui.0.borrow_mut().push(Widget::Label(text));
            Ok(())
        });
        methods.add_method("mono", |_, ui, text: String| {
            ui.0.borrow_mut().push(Widget::Mono(text));
            Ok(())
        });
        methods.add_method("separator", |_, ui, ()| {
            ui.0.borrow_mut().push(Widget::Separator);
            Ok(())
        });
        methods.add_method("button", |_, ui, text: String| {
            let mut state = ui.0.borrow_mut();
            let id = state.next_id;
            state.next_id += 1;
            state.push(Widget::Button { id, text });
            Ok(state.clicked.contains(&id))
        });
        methods.add_method("input", |_, ui, (key, hint): (String, Option<String>)| {
            let mut state = ui.0.borrow_mut();
            let value = state.texts.get(&key).cloned().unwrap_or_default();
            state.push(Widget::Input {
                key,
                hint: hint.unwrap_or_default(),
                value: value.clone(),
            });
            Ok(value)
        });
        methods.add_method("checkbox", |_, ui, (key, text): (String, String)| {
            let mut state = ui.0.borrow_mut();
            let value = state.checks.get(&key).copied().unwrap_or(false);
            state.push(Widget::Checkbox { key, text, value });
            Ok(value)
        });
        methods.add_method("row", |lua, ui, draw: Function| {
            ui.0.borrow_mut().stack.push(Vec::new());
            let inner = lua.create_userdata(LuaUi(Rc::clone(&ui.0)))?;
            let result = draw.call::<()>(inner);

            let mut state = ui.0.borrow_mut();
            let group = state.stack.pop().unwrap_or_default();
            state.push(Widget::Row(group));
            result
        });
        methods.add_method(
            "table",
            |_, ui, (headers, rows): (Vec<String>, Vec<Vec<String>>)| {
                ui.0.borrow_mut().push(Widget::Table { headers, rows });
                Ok(())
            },
        );
    }
}

pub(crate) struct Runtime {
    lua: Lua,
    shared: Rc<Shared>,
}

impl Runtime {
    pub(crate) fn load(
        source: &str,
        meta: &Meta,
        view: Option<Rc<BinaryView>>,
    ) -> Result<Self, String> {
        Self::load_on_tab(source, meta, view, "")
    }

    pub(crate) fn load_on_tab(
        source: &str,
        meta: &Meta,
        view: Option<Rc<BinaryView>>,
        tab: &str,
    ) -> Result<Self, String> {
        let libs = StdLib::TABLE | StdLib::STRING | StdLib::MATH | StdLib::UTF8 | StdLib::COROUTINE;
        let lua = Lua::new_with(libs, LuaOptions::default()).map_err(|error| error.to_string())?;
        let shared = Rc::new(Shared {
            view: RefCell::new(view),
            tab: RefCell::new(tab.to_owned()),
            requests: RefCell::new(Vec::new()),
            log: RefCell::new(Vec::new()),
            tabs: RefCell::new(Vec::new()),
            handlers: RefCell::new(Vec::new()),
            deadline: Cell::new(Instant::now() + LOAD_BUDGET),
            permissions: meta.permissions.clone(),
            discord: RefCell::new(None),
        });

        let runtime = Self { lua, shared };
        runtime.sandbox().map_err(|error| error.to_string())?;
        runtime.install_api().map_err(|error| error.to_string())?;
        runtime
            .lua
            .load(source)
            .set_name(meta.file.as_str())
            .set_mode(ChunkMode::Text)
            .exec()
            .map_err(|error| error.to_string())?;
        Ok(runtime)
    }

    fn sandbox(&self) -> mlua::Result<()> {
        self.lua.set_memory_limit(MEMORY_LIMIT)?;

        let globals = self.lua.globals();
        for name in REMOVED_GLOBALS {
            globals.set(name, Value::Nil)?;
        }
        if let Ok(strings) = globals.get::<Table>("string") {
            strings.set("dump", Value::Nil)?;
        }

        let shared = Rc::clone(&self.shared);
        self.lua.set_global_hook(
            HookTriggers::new().every_nth_instruction(HOOK_INTERVAL),
            move |_, _| {
                if Instant::now() > shared.deadline.get() {
                    return Err(mlua::Error::runtime(
                        "this plugin ran too long without returning",
                    ));
                }
                Ok(VmState::Continue)
            },
        )?;
        Ok(())
    }

    fn install_api(&self) -> mlua::Result<()> {
        let lua = &self.lua;
        let shared = &self.shared;
        let api = lua.create_table()?;
        api.set("api_version", API_VERSION)?;

        let state = Rc::clone(shared);
        let log = lua.create_function(move |_, values: mlua::Variadic<Value>| {
            let parts: Vec<String> = values
                .iter()
                .map(|value| {
                    value
                        .to_string()
                        .unwrap_or_else(|_| value.type_name().to_owned())
                })
                .collect();
            state.write_log(parts.join(" "));
            Ok(())
        })?;
        api.set("log", log.clone())?;
        lua.globals().set("print", log)?;

        let state = Rc::clone(shared);
        api.set(
            "status",
            lua.create_function(move |_, text: String| {
                state.requests.borrow_mut().push(Request::Status(text));
                Ok(())
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "jump",
            lua.create_function(move |_, va: i64| {
                state.requests.borrow_mut().push(Request::Jump(va as u64));
                Ok(())
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "tab",
            lua.create_function(move |_, ()| Ok(state.tab.borrow().clone()))?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "add_tab",
            lua.create_function(move |_, (title, draw): (String, Function)| {
                state.tabs.borrow_mut().push(TabSlot {
                    title,
                    draw,
                    state: Rc::default(),
                });
                Ok(())
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "on",
            lua.create_function(move |_, (event, handler): (String, Function)| {
                state.handlers.borrow_mut().push((event, handler));
                Ok(())
            })?,
        )?;

        self.install_binary_api(&api)?;
        self.install_discord_api(&api)?;
        lua.globals().set("euphoria", api)
    }

    fn install_binary_api(&self, api: &Table) -> mlua::Result<()> {
        let lua = &self.lua;
        let shared = &self.shared;

        let state = Rc::clone(shared);
        api.set(
            "binary",
            lua.create_function(move |lua, ()| {
                let Some(view) = state.view() else {
                    return Ok(Value::Nil);
                };
                let info = lua.create_table()?;
                info.set("name", view.name.as_str())?;
                info.set("arch", view.arch)?;
                info.set("sha256", view.sha256.as_str())?;
                info.set("entry", view.entry as i64)?;
                info.set("size", view.data.len() as i64)?;
                Ok(Value::Table(info))
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "functions",
            lua.create_function(move |lua, ()| {
                let list = lua.create_table()?;
                if let Some(view) = state.view() {
                    for function in &view.functions {
                        let item = lua.create_table()?;
                        item.set("va", function.va as i64)?;
                        item.set("size", function.size as i64)?;
                        item.set("name", function.name.as_deref())?;
                        list.push(item)?;
                    }
                }
                Ok(list)
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "strings",
            lua.create_function(move |lua, ()| {
                let list = lua.create_table()?;
                if let Some(view) = state.view() {
                    for entry in &view.strings {
                        let item = lua.create_table()?;
                        item.set("va", entry.va as i64)?;
                        item.set("value", entry.value.as_str())?;
                        item.set("base64", entry.base64.as_deref())?;
                        list.push(item)?;
                    }
                }
                Ok(list)
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "xrefs_to",
            lua.create_function(move |lua, va: i64| {
                let list = lua.create_table()?;
                if let Some(view) = state.view() {
                    for xref in view.xrefs.iter().filter(|xref| xref.to == va as u64) {
                        let item = lua.create_table()?;
                        item.set("from", xref.from as i64)?;
                        item.set("to", xref.to as i64)?;
                        item.set("kind", format!("{:?}", xref.kind).to_lowercase())?;
                        list.push(item)?;
                    }
                }
                Ok(list)
            })?,
        )?;

        let state = Rc::clone(shared);
        api.set(
            "read",
            lua.create_function(move |lua, (va, len): (i64, usize)| {
                let Some(view) = state.view() else {
                    return Ok(Value::Nil);
                };
                let va = va as u64;
                let Some(section) = view
                    .sections
                    .iter()
                    .find(|section| va >= section.va && va - section.va < section.size)
                else {
                    return Ok(Value::Nil);
                };

                let start = (section.offset + (va - section.va)) as usize;
                let left = (section.size - (va - section.va)) as usize;
                let end = start
                    .saturating_add(len.min(left).min(MAX_READ_BYTES))
                    .min(view.data.len());
                match view.data.get(start..end) {
                    Some(bytes) => Ok(Value::String(lua.create_string(bytes)?)),
                    None => Ok(Value::Nil),
                }
            })?,
        )?;
        Ok(())
    }

    fn install_discord_api(&self, api: &Table) -> mlua::Result<()> {
        let lua = &self.lua;
        let shared = &self.shared;
        let table = lua.create_table()?;

        let state = Rc::clone(shared);
        table.set(
            "connect",
            lua.create_function(move |_, client_id: String| {
                state.require_permission(PERMISSION_DISCORD)?;
                if !discord::is_valid_client_id(&client_id) {
                    return Err(mlua::Error::runtime(
                        "a Discord application ID is a string of digits",
                    ));
                }
                *state.discord.borrow_mut() = Some(Discord::connect(client_id));
                Ok(())
            })?,
        )?;

        let state = Rc::clone(shared);
        table.set(
            "set_activity",
            lua.create_function(move |_, activity: Table| {
                state.require_permission(PERMISSION_DISCORD)?;
                let update = Activity {
                    details: activity.get("details")?,
                    state: activity.get("state")?,
                    large_image: activity.get("large_image")?,
                    large_text: activity.get("large_text")?,
                    started: activity.get::<Option<bool>>("started")?.unwrap_or(false),
                };
                if let Some(client) = state.discord.borrow().as_ref() {
                    client.set_activity(update);
                }
                Ok(())
            })?,
        )?;

        let state = Rc::clone(shared);
        table.set(
            "clear",
            lua.create_function(move |_, ()| {
                state.require_permission(PERMISSION_DISCORD)?;
                if let Some(client) = state.discord.borrow().as_ref() {
                    client.clear();
                }
                Ok(())
            })?,
        )?;

        let state = Rc::clone(shared);
        table.set(
            "status",
            lua.create_function(move |_, ()| {
                state.require_permission(PERMISSION_DISCORD)?;
                Ok(state
                    .discord
                    .borrow()
                    .as_ref()
                    .map_or("not connected".to_owned(), Discord::status))
            })?,
        )?;

        api.set("discord", table)
    }

    fn start_call(&self) {
        self.shared.deadline.set(Instant::now() + CALL_BUDGET);
    }

    pub(crate) fn tab_titles(&self) -> Vec<String> {
        self.shared
            .tabs
            .borrow()
            .iter()
            .map(|tab| tab.title.clone())
            .collect()
    }

    pub(crate) fn draw_tab(&self, tab: usize, events: Vec<UiEvent>) -> Result<Vec<Widget>, String> {
        let (draw, state) = {
            let tabs = self.shared.tabs.borrow();
            let slot = tabs
                .get(tab)
                .ok_or_else(|| "This plugin tab no longer exists".to_owned())?;
            (slot.draw.clone(), Rc::clone(&slot.state))
        };

        {
            let mut state = state.borrow_mut();
            state.clicked.clear();
            for event in events {
                match event {
                    UiEvent::Clicked(id) => {
                        state.clicked.insert(id);
                    }
                    UiEvent::Text { key, value } => {
                        state.texts.insert(key, value);
                    }
                    UiEvent::Toggled { key, value } => {
                        state.checks.insert(key, value);
                    }
                }
            }
            state.next_id = 0;
            state.stack = vec![Vec::new()];
        }

        self.start_call();
        let ui = self
            .lua
            .create_userdata(LuaUi(Rc::clone(&state)))
            .map_err(|error| error.to_string())?;
        draw.call::<()>(ui).map_err(|error| error.to_string())?;

        let widgets = state.borrow_mut().stack.pop().unwrap_or_default();
        Ok(widgets)
    }

    pub(crate) fn emit(&self, event: &str, argument: Option<&str>) -> Result<(), String> {
        let handlers: Vec<Function> = self
            .shared
            .handlers
            .borrow()
            .iter()
            .filter(|(name, _)| name == event)
            .map(|(_, handler)| handler.clone())
            .collect();
        for handler in handlers {
            self.start_call();
            handler
                .call::<()>(argument)
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }

    pub(crate) fn has_handler(&self, event: &str) -> bool {
        self.shared
            .handlers
            .borrow()
            .iter()
            .any(|(name, _)| name == event)
    }

    pub(crate) fn set_tab(&self, title: &str) {
        title.clone_into(&mut self.shared.tab.borrow_mut());
    }

    pub(crate) fn set_view(&self, view: Option<Rc<BinaryView>>) {
        *self.shared.view.borrow_mut() = view;
    }

    pub(crate) fn take_requests(&self) -> Vec<Request> {
        std::mem::take(&mut *self.shared.requests.borrow_mut())
    }

    pub(crate) fn log_lines(&self) -> Vec<String> {
        self.shared.log.borrow().clone()
    }
}

impl Drop for Runtime {
    fn drop(&mut self) {
        self.shared.tabs.borrow_mut().clear();
        self.shared.handlers.borrow_mut().clear();
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use euphoria_engine::{Function as Routine, Section, StringEntry, Xref, XrefKind};

    use super::*;

    fn meta(permissions: &[&str]) -> Meta {
        Meta {
            file: "test.lua".to_owned(),
            name: "test".to_owned(),
            permissions: permissions.iter().map(|p| (*p).to_owned()).collect(),
            ..Meta::default()
        }
    }

    fn load(source: &str) -> Result<Runtime, String> {
        Runtime::load(source, &meta(&[]), None)
    }

    fn view() -> Rc<BinaryView> {
        Rc::new(BinaryView {
            name: "sample.exe".to_owned(),
            arch: "x86",
            sha256: "abc".to_owned(),
            entry: 0x1000,
            data: Arc::new(b"\x90\x90hello\0".to_vec()),
            sections: vec![Section {
                va: 0x1000,
                offset: 0,
                size: 8,
                executable: true,
            }],
            functions: vec![Routine {
                va: 0x1000,
                size: 2,
                name: Some("start".to_owned()),
            }],
            strings: vec![StringEntry {
                va: 0x1002,
                value: "hello".to_owned(),
                base64: None,
            }],
            xrefs: vec![Xref {
                from: 0x1000,
                to: 0x1002,
                kind: XrefKind::Data,
            }],
        })
    }

    #[test]
    fn removes_everything_that_reaches_outside_the_sandbox() {
        let runtime = load(
            "for _, name in ipairs({'os', 'io', 'package', 'debug', 'dofile', 'loadfile', 'load', 'require'}) do
                 if _G[name] ~= nil then error(name .. ' is still available') end
             end
             if string.dump ~= nil then error('string.dump is still available') end",
        );
        assert!(runtime.is_ok(), "{:?}", runtime.err());
    }

    #[test]
    fn refuses_precompiled_code() {
        assert!(load("\x1bLuaT\0\x19\u{93}\r\n\x1a\n").is_err());
    }

    #[test]
    fn stops_endless_loops() {
        let error = load("while true do end").err().unwrap();
        assert!(error.contains("ran too long"), "{error}");

        let error = load("local c = coroutine.wrap(function() while true do end end) c()")
            .err()
            .unwrap();
        assert!(error.contains("ran too long"), "{error}");

        let runtime = load("euphoria.add_tab('T', function(ui) while true do end end)").unwrap();
        let error = runtime.draw_tab(0, Vec::new()).unwrap_err();
        assert!(error.contains("ran too long"), "{error}");
    }

    #[test]
    fn limits_memory() {
        let error = load(
            "local parts = {}
             for i = 1, 100 do parts[i] = string.rep('x', 32 * 1024 * 1024) end",
        )
        .err()
        .unwrap();
        assert!(error.to_lowercase().contains("memory"), "{error}");
    }

    #[test]
    fn builds_a_tab_from_widgets() {
        let runtime = load(
            "euphoria.add_tab('Tools', function(ui)
                 ui:heading('Title')
                 ui:label(42)
                 ui:separator()
                 ui:row(function(row)
                     row:mono('a')
                     row:label('b')
                 end)
                 ui:table({'x', 'y'}, {{'1', '2'}})
             end)",
        )
        .unwrap();

        assert_eq!(runtime.tab_titles(), ["Tools"]);
        assert_eq!(
            runtime.draw_tab(0, Vec::new()).unwrap(),
            [
                Widget::Heading("Title".to_owned()),
                Widget::Label("42".to_owned()),
                Widget::Separator,
                Widget::Row(vec![
                    Widget::Mono("a".to_owned()),
                    Widget::Label("b".to_owned()),
                ]),
                Widget::Table {
                    headers: vec!["x".to_owned(), "y".to_owned()],
                    rows: vec![vec!["1".to_owned(), "2".to_owned()]],
                },
            ]
        );
    }

    #[test]
    fn delivers_clicks_text_and_checkboxes() {
        let runtime = load(
            "euphoria.add_tab('T', function(ui)
                 local name = ui:input('name', 'hint')
                 local on = ui:checkbox('on', 'Enable')
                 if ui:button('Go') then
                     euphoria.log('clicked', name, tostring(on))
                 end
             end)",
        )
        .unwrap();

        let widgets = runtime.draw_tab(0, Vec::new()).unwrap();
        let Widget::Button { id, .. } = widgets[2] else {
            panic!("expected a button");
        };
        assert!(runtime.log_lines().is_empty());

        runtime
            .draw_tab(
                0,
                vec![
                    UiEvent::Text {
                        key: "name".to_owned(),
                        value: "ada".to_owned(),
                    },
                    UiEvent::Toggled {
                        key: "on".to_owned(),
                        value: true,
                    },
                    UiEvent::Clicked(id),
                ],
            )
            .unwrap();
        assert_eq!(runtime.log_lines(), ["clicked ada true"]);

        let widgets = runtime.draw_tab(0, Vec::new()).unwrap();
        assert_eq!(runtime.log_lines().len(), 1);
        assert!(matches!(&widgets[0], Widget::Input { value, .. } if value == "ada"));
    }

    #[test]
    fn exposes_the_loaded_binary() {
        let runtime = Runtime::load(
            "local b = euphoria.binary()
             local f = euphoria.functions()[1]
             local s = euphoria.strings()[1]
             local x = euphoria.xrefs_to(0x1002)[1]
             print(b.name, b.arch, b.entry, b.size)
             print(f.name, f.va, f.size)
             print(s.value, s.va)
             print(x.from, x.kind)
             print(euphoria.read(0x1002, 5))
             print(euphoria.read(0x9999, 5) == nil)
             euphoria.jump(0x1000)
             euphoria.status('done')",
            &meta(&[]),
            Some(view()),
        )
        .unwrap();

        assert_eq!(
            runtime.log_lines(),
            [
                "sample.exe x86 4096 8",
                "start 4096 2",
                "hello 4098",
                "4096 data",
                "hello",
                "true",
            ]
        );
        assert_eq!(
            runtime.take_requests(),
            [Request::Jump(0x1000), Request::Status("done".to_owned())]
        );
    }

    #[test]
    fn reports_no_binary_when_none_is_open() {
        let runtime = load("print(euphoria.binary() == nil, #euphoria.functions())").unwrap();
        assert_eq!(runtime.log_lines(), ["true 0"]);
    }

    #[test]
    fn delivers_events_to_handlers() {
        let runtime = load(
            "euphoria.on('tab_changed', function(title) print('tab', title) end)
             euphoria.on('tick', function() print('tick') end)",
        )
        .unwrap();

        assert!(runtime.has_handler("tick"));
        assert!(!runtime.has_handler("other"));
        runtime.emit("tab_changed", Some("Graph")).unwrap();
        runtime.emit("tick", None).unwrap();
        runtime.emit("unknown", None).unwrap();
        assert_eq!(runtime.log_lines(), ["tab Graph", "tick"]);
    }

    #[test]
    fn discord_needs_the_declared_permission() {
        let error = load("euphoria.discord.connect('123')").err().unwrap();
        assert!(error.contains("@permissions discord"), "{error}");

        let runtime = Runtime::load(
            "print(euphoria.discord.status())
             local ok = pcall(euphoria.discord.connect, 'not digits')
             print(ok)",
            &meta(&["discord"]),
            None,
        )
        .unwrap();
        assert_eq!(runtime.log_lines(), ["not connected", "false"]);
    }
}
