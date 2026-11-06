# Euphoria plugins

A plugin is one `.lua` file in the plugins folder. On Windows that is `%APPDATA%\Euphoria\plugins`. The Local section of the Plugins tab has a button that opens it.

Plugins stay off until you turn them on, and Euphoria reads only the header comments of a plugin that is off.

## Header

```lua
-- @name String Search
-- @version 1.0
-- @author Your Name
-- @description One line about what it does.
-- @permissions discord
```

`@permissions` is only needed for the extra access listed below.

## Adding a tab

```lua
euphoria.add_tab("Hello", function(ui)
    ui:heading("Hello")
    if ui:button("Jump to the entry point") then
        euphoria.jump(euphoria.binary().entry)
    end
end)
```

The function runs every time the tab redraws, so keep it quick.

## The `ui` object

| Call | Does |
|---|---|
| `ui:heading(text)` | Large text |
| `ui:label(text)` | Normal text |
| `ui:mono(text)` | Fixed-width text |
| `ui:separator()` | A dividing line |
| `ui:button(text)` | Returns true once after a click |
| `ui:input(key, hint)` | Returns the current text |
| `ui:checkbox(key, text)` | Returns true or false |
| `ui:row(function(row) ... end)` | Lays widgets out side by side |
| `ui:table(headers, rows)` | Draws a table of strings |

## The `euphoria` table

| Call | Returns or does |
|---|---|
| `euphoria.binary()` | `name`, `arch`, `sha256`, `entry`, `size`, or nil with no file open |
| `euphoria.functions()` | A list of `va`, `size`, `name` |
| `euphoria.strings()` | A list of `va`, `value`, `base64` |
| `euphoria.xrefs_to(va)` | A list of `from`, `to`, `kind` |
| `euphoria.read(va, length)` | Bytes as a string, up to 1 MB, or nil |
| `euphoria.tab()` | The title of the open tab |
| `euphoria.jump(va)` | Moves the Listing to an address |
| `euphoria.rename(va, name)` | Names the routine containing `va`; an empty or nil name restores the default |
| `euphoria.status(text)` | Shows text in the status bar |
| `euphoria.log(...)` or `print(...)` | Writes to the plugin's log |
| `euphoria.on(event, function)` | Listens for `binary_opened`, `tab_changed`, or `tick` (once a second) |
| `euphoria.api_version` | The API version number |

## Extra access: Discord

Needs `-- @permissions discord`. It talks to the Discord app on the same machine, and you supply the ID of your own Discord application.

| Call | Does |
|---|---|
| `euphoria.discord.connect(application_id)` | Connects in the background |
| `euphoria.discord.set_activity{ details=, state=, large_image=, large_text=, started= }` | Updates your profile. `large_image` is an uploaded asset name or a public image URL. |
| `euphoria.discord.clear()` | Removes the activity |
| `euphoria.discord.status()` | Returns the connection state as text |

## Limits

Plugins have no `os`, `io`, `package`, `debug`, `load`, or `require`, so they cannot reach your files or the network directly. A call that runs longer than 250 ms or a plugin that uses more than 128 MB gets stopped, and the reason appears in the Local section.

This protects against mistakes more than against a determined attacker, so only turn on plugins you trust. A slow Lua pattern match inside a single library call cannot be interrupted.

## Testing a plugin

```bash
cargo run -p euphoria-cli -- plugin run my_plugin.lua path/to/binary
```
