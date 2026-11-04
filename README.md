# euphoria-re

A fast, scriptable disassembly workbench, currently a pre-alpha. Expect bugs and breaking changes. It parses PE, ELF, and Mach-O files, finds functions from the entry point, symbols, exports, and a prologue scan, and shows 32-bit and 64-bit x86 disassembly, control flow graphs, references, and strings in a desktop app. It also reports entropy, identifies common packers, decodes Base64 strings, finds single-byte XOR text, explains SQL files without running them, reads Android APKs down to Dalvik bytecode, dumps everything it knows about a file into one zip, turns x86 and x64 routines into C-like pseudocode, and debugs Windows programs with breakpoints and stepping. Function detection is still rough, and the decompiler is young: it won't match a mature commercial one on large optimized programs. See [PLAN.md](PLAN.md) for the roadmap.

Everything runs locally unless you tell Aero, the networking library, to contact a domain. Euphoria asks first, for each domain.

Only analyze binaries you own or have permission to inspect, and only scan or send requests to systems you own or have permission to test.

## Build

You need Rust, CMake, Ninja, NASM, and a GCC or Clang toolchain. On Windows that means the `x86_64-pc-windows-gnu` Rust toolchain with MinGW, since the native build has not been tested with MSVC.

```bash
cargo build --release
```

## Use

```bash
cargo run -p euphoria-cli -- analyze path/to/binary --save out.euph
```

`.euph` datasets hold the program and your saved work, compressed, and reopen like any other file.

```bash
cargo run -p euphoria-cli -- functions path/to/binary --json
```

```bash
cargo run -p euphoria-cli -- graph path/to/binary main
```

```bash
cargo run -p euphoria-cli -- inspect path/to/binary
```

```bash
cargo run -p euphoria-cli -- xor path/to/binary --json
```

```bash
cargo run -p euphoria-cli -- sql path/to/dump.sql
```

```bash
cargo run -p euphoria-cli -- apk path/to/app.apk
```

```bash
cargo run -p euphoria-cli -- dump path/to/binary_or_apk -o dump.zip
```

```bash
cargo run -p euphoria-cli -- links path/to/binary
```

```bash
cargo run -p euphoria-cli -- redirect path/to/binary https://host/path -o patched.bin
```

`redirect` rewrites a URL in the binary to point at `127.0.0.1` and writes a patched copy, for pointing a sample at the local emulator. The input file is only read. In the Networking tab, right-click a link and choose "Patch to local emulator" to do the same, then save the patched copy.

```bash
cargo run -p euphoria-cli -- aero scan example.com --i-have-permission
```

```bash
cargo run -p euphoria-cli -- aero send https://example.com/ --i-have-permission
```

```bash
cargo run -p euphoria-ui -- path/to/binary
```

## Plugin marketplace and public database

The Marketplace section of the Plugins tab lists what's in [euphoria-plugins](https://github.com/JoeyKoch1/euphoria-plugins). A plugin installs switched off, only after its contents match the hash in the list, and you turn it on yourself under Local.

You can also use `eu plugin market` to list them and `eu plugin install <id>` to install one.

To publish one, add your `.lua` file to `plugins/` in that repo with a lowercase name, then run this in your checkout to refresh the list:

```bash
eu plugin index path/to/euphoria-plugins
```

The File tab can check [euphoria-db](https://github.com/JoeyKoch1/euphoria-db) for routine names other people shared about the same file. Lookups are off until you ask for one, and each one tells GitHub the file's SHA-256. The file itself never leaves your computer. Sharing saves a small JSON file with routine addresses, sizes and names, which you upload yourself. Dumps live at `dumps/<first two hash characters>/<sha256>.json`.

## Configuration

Everything has a working default. To point Euphoria at a fork or a mirror, create `config.json` in the Euphoria settings folder, which is `%APPDATA%\Euphoria` on Windows and `~/.config/Euphoria` elsewhere. Any field can be left out.

```json
{
  "plugin_repo": "JoeyKoch1/euphoria-plugins",
  "database_repo": "JoeyKoch1/euphoria-db",
  "branch": "main",
  "raw_base": "https://raw.githubusercontent.com",
  "web_base": "https://github.com",
  "automatic_lookups": false
}
```

## Decompiler

Open the Decompiler tab, or press F5, to see the routine under the cursor. It lifts machine code to an intermediate form, rebuilds variables with SSA, recovers stack slots, arguments and return values, and structures the result into if, while, for, do and switch. It also undoes the multiply-and-shift tricks compilers use for most constant division.

`decompiler/check/check.py` compiles sample C with gcc, decompiles the machine code, compiles that pseudocode, and compares what both versions return.

What it doesn't do yet: recover structs, classes or real type names, lift vectorized code (it shows up as an `__asm__` line), or decompile ARM64.

## Debugger

The buttons under the Listing header set breakpoints and drive a real run of the program. Euphoria asks before the first run of each file, because the program really executes. Only run what you own or are allowed to inspect, and use a virtual machine for anything you don't trust.

| Key | Action |
|---|---|
| F2, or double-click a line | Set or remove a breakpoint |
| F9 | Run or continue |
| F7 | Step into |
| F8 | Step over |
| Shift+F8 | Step out |
| F4 | Run to the cursor |

The Debugger tab shows registers, the stack, live code, memory, loaded modules, threads and a log. It handles 32-bit and 64-bit programs on 64-bit Windows. It has software breakpoints only, can't attach to a running process, and doesn't edit registers or memory.

## Layout

| Folder | Language | Owns |
|---|---|---|
| `capi` | Rust | The ABI, defined once in `src/abi.rs`. `euphoria.h` is generated from it, and the build compiles the native code. |
| `core` | C++20 | Analysis |
| `db` | C | Storage |
| `simd` | NASM and C | Byte and pattern scanners |
| `formats` | Rust | File parsers |
| `engine` | Rust | The one API that the CLI and UI share, including the instruction listing and `.euph` datasets |
| `sql` | Rust | SQL script and SQLite inspection |
| `aero` | Rust | HTTP client, subdomain discovery, response capture, and the local emulator |
| `apk` | Rust | APK reader: manifest, DEX classes, and Dalvik bytecode |
| `decompiler` | Rust | Machine code to C-like pseudocode |
| `debugger` | Rust | Runs and controls Windows programs |
| `community` | Rust | Settings file, plugin marketplace, and public database client |
| `dump` | Rust | Parallel dump of everything about a file into one zip |
| `plugins` | Rust and Lua | The Lua plugin host, its API, and example plugins. See [plugins/README.md](plugins/README.md). |
| `hypervisor` | None yet | Reserved for the Euphoria Hypervisor |
| `cli` | Rust | The `eu` command |
| `ui` | Rust | The `euphoria` desktop app |

## Test

```bash
cargo test --workspace
```

The scanner test compares the assembly and C versions:

```bash
cmake -S . -B build -G Ninja
```

```bash
cmake --build build --target scan_test
```

```bash
ctest --test-dir build --output-on-failure
```
**Disclaimer**
While building this project, I'm using AI because why not take advantage of a tool that makes development easier and helps me make progress faster? It's free, it's useful, and it helps me get things done. So there's really no reason to complain.

## License

Euphoria is source-available under the [PolyForm Noncommercial License 1.0.0](LICENSE). It isn't open source in the strict sense.

You can read, build, change and share it for free for personal use, study, hobby projects, and at schools, charities and public research groups. Commercial use needs a paid license, so open an issue on this repo if your company wants one.

By sending a pull request, you agree that your contribution can be used under this license and under paid commercial licenses for Euphoria.

Third-party packages keep their own licenses, listed in [THIRD_PARTY.md](THIRD_PARTY.md).
