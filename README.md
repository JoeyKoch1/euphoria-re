# euphoria-re

A fast, scriptable disassembly workbench. Early skeleton: it parses PE, ELF, and Mach-O files, finds functions from the entry point, symbols, exports, and a prologue scan, and shows 32-bit and 64-bit x86 disassembly, control flow graphs, references, and strings in a desktop app. It also reports entropy, identifies common packers, decodes Base64 strings, finds single-byte XOR text, explains SQL files without running them, reads Android APKs down to Dalvik bytecode, and dumps everything it knows about a file into one zip. There is no decompiler yet, and function detection is still rough. See [PLAN.md](PLAN.md) for the roadmap.

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
