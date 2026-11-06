# Euphoria project plan

Euphoria is a disassembly and decompilation workbench for x86-64 and ARM64 binaries. It has a fast native core, a desktop UI, a scriptable CLI, and a stable plugin API. This plan covers what to build, in what order, how to prove it is good, and how to sell it for 20 USD lifetime.

Planning assumptions: one developer, about 15 hours a week, starting 4 November 2026. That is roughly 900 hours to v1.0, including about 140 hours for the public database in section 14. Everything below is sized to fit that budget, and the cut list in section 4 says what goes first if time runs short.

### Current status (6 November 2026)

A public beta is being prepared for the week of 9 November 2026, well ahead of the phase targets below. It covers PE, ELF, and Mach-O parsing; x86 and x64 listing, graph, and decompiler; APK analysis; the SQL inspector; dump; plugins; Aero networking; the Android runtime; the debugger; and live process attach with `.euphp` patches. It also ships a first-run tour and three sample files. This is not the v0.5 milestone in section 4: the plugin ABI, 72-hour fuzzing, usability exit criteria, and ARM64 work still belong to that milestone. The dates below remain the plan for v1.0, not a gate on the beta.

## 1. Positioning and honest claims

IDA Pro has more than two decades of processor modules, type libraries, a mature decompiler, a debugger, and a plugin ecosystem. Euphoria will not match that in ten months, and the README should say so on day one. Claiming to beat IDA across the board is the fastest way to lose credibility with the exact audience that would buy this.

Euphoria competes in narrow areas where a new, focused tool can measurably win:

- Startup time and time to reopen a saved analysis.
- Headless batch throughput (analyzing many binaries from a script or CI job).
- Memory use on large binaries.
- Search and indexing latency.
- Plugin API size, stability, and time to a first working plugin.
- Scripting and automation ergonomics, including JSON output from every CLI command.
- Price and licensing clarity.

Where IDA stays ahead for the foreseeable future, and where the README will say so:

- Processor and file format coverage.
- Decompiler output quality.
- Type libraries and signature databases.
- Debugger integration.
- Third-party plugin ecosystem.
- Years of real-world testing.

The one-line pitch: a fast, scriptable, 20 USD disassembler for people who want to automate analysis and write plugins without a heavy workflow.

Name check: "Euphoria" is already an existing programming language (OpenEuphoria) and a TV show, so search results will be crowded. Use the repository name `euphoria-re`, a short tagline in every title, and check trademark conflicts before you buy a domain. Never use "IDA" or "Hex-Rays" in the product name, logo, or marketing headline. A factual comparison page that names them is fine.

## 2. Measurable targets

Every number below is a target, not a result. None of them goes into marketing until the benchmark harness (section 6) has measured it on published hardware. If a target is missed, the README reports the real figure.

Reference machine for all targets: a laptop-class x86-64 CPU with 8 cores, 32 GB RAM, NVMe SSD, Windows 11. Record the exact model when you pick it, and publish it.

| Area | Metric | MVP target | v1.0 target | How it is measured |
|---|---|---|---|---|
| Startup | Process launch to interactive UI, no file | 800 ms | 400 ms | Scripted launch, 20 runs, median and p95 |
| Reopen | Open a saved analysis of a 50 MB PE to first listing view | 3 s | 1 s | Same corpus, cold and warm cache |
| Initial analysis | Wall time for full auto-analysis of a 50 MB x86-64 PE, 8 cores | Within 3x of the fastest comparator | Within 1.25x of the fastest comparator, ahead in at least one size class | Normalized work: see section 6 |
| Memory | Peak working set during analysis | 8x input size | 5x input size | OS peak working set counter |
| Search | Substring search over names and strings in a 100 MB database | 300 ms p95 | 100 ms p95 | Built-in timer, 1000 queries |
| Function recovery | F1 score for function boundaries against DWARF/PDB ground truth | 0.90 | 0.95 on gcc, clang, and MSVC -O2 builds | Own-built corpus with debug info |
| Decompiler latency | Pseudo-C for one function under 500 instructions | n/a | 200 ms p95 | Corpus functions, 10 runs each |
| Plugin API | Lines of code for a "rename functions by pattern" plugin | 40 | 25 | Counted in the docs example |
| Plugin API | Time for a new user to build and load a hello-world plugin | 30 min | 10 min | Timed with 5 volunteers |
| Plugin API | Documented public symbols | 90 percent | 100 percent | Doc coverage check in CI |
| Scripting | CLI commands with `--json` output | 80 percent | 100 percent | CI check |
| UX clarity | Task completion in a 6-task usability test | 4 of 6 for 5 testers | 6 of 6 for 5 of 8 testers | Moderated sessions, notes published |
| Stability | Crashes found by parser fuzzing in the last 72 hours before release | 0 | 0 | CI fuzz job logs |

The "within 3x" and "within 1.25x" analysis targets are deliberately modest. Auto-analysis in a mature tool does a lot of work, and the honest first goal is to be competitive while doing equivalent work, not to win on a rigged comparison.

## 3. Architecture and language ownership

The rule that keeps four languages manageable: there is exactly one boundary type, a stable C ABI, and every cross-language call goes through it. No language reaches into another one's internals.

### Layers

```
        +-------------------+    +------------------+
        |  euphoria-ui      |    |  euphoria-cli    |
        |  Rust (egui)      |    |  Rust (clap)     |
        +---------+---------+    +--------+---------+
                  |                       |
                  +-----------+-----------+
                              |
                  +-----------v-----------+      +-------------------+
                  |  euphoria-capi        |<---->|  plugins          |
                  |  C header + C++ impl  |      |  C ABI, Python    |
                  +-----------+-----------+      +-------------------+
                              |
        +---------------------+---------------------+
        |                     |                     |
+-------v------+     +--------v--------+    +-------v-------+
| euphoria-    |     | euphoria-core   |    | euphoria-db   |
| formats      |     | C++20           |    | C             |
| Rust         |     | analysis, IR,   |    | mmap store    |
| parsers      |     | decompiler      |    +---------------+
+--------------+     +--------+--------+
                              |
                     +--------v--------+
                     | euphoria-simd   |
                     | ASM + C fallback|
                     +-----------------+
```

### Who owns what

| Module | Language | Why this language |
|---|---|---|
| `euphoria-formats` | Rust | Parses untrusted input. Malicious binaries are the main attack surface of a reverse engineering tool, so memory safety matters most here. Uses the `object`, `gimli`, and `pdb` crates where they fit. |
| `euphoria-db` | C | Small, auditable, with a stable on-disk format. A memory-mapped, page-based store with columnar tables for names, xrefs, strings, and comments. Fast reopen comes from mapping the file instead of parsing it. |
| `euphoria-core` | C++20 | The analysis engine: function discovery, control flow graphs, cross references, type propagation, lifter to IR, SSA, structuring, pseudo-C emission. Needs templates, value types, and a work-stealing job scheduler. |
| `euphoria-simd` | NASM assembly with C intrinsic fallback | Byte-pattern and signature scanning, prologue scanning, string scanning. Runtime CPUID dispatch picks AVX2 or the portable C path. |
| `euphoria-capi` | Rust definitions, generated C header, C++ implementation | The only ABI that crosses language lines. Defined once in `capi/src/abi.rs`, with `euphoria.h` generated by `cbindgen`. Versioned structs, opaque handles, explicit ownership rules, no exceptions across the boundary. |
| `euphoria-engine` | Rust | The single API the CLI and UI share, so neither repeats the open, parse, and analyze flow. |
| `euphoria-ui` | Rust with egui and OpenGL (glow) | Small binary and a custom virtualized listing widget that can scroll millions of lines. In rough first timings on a laptop with an NVIDIA and an Intel GPU, wgpu took 2.5 to 14 seconds to show a window and glow took about 1.4 seconds once warm. Neither meets the startup target yet. |
| `euphoria-cli` (`eu`) | Rust | Subcommands, JSON and JSONL output, shell completion, scripting-friendly exit codes. |
| Python bindings | C ABI via cffi, thin wrapper | Scripting for most users. Generated from the C header so it cannot drift. |

### Rules for assembly

Assembly is the smallest part of the project and has to earn its place. A routine stays in assembly only if it beats the C intrinsic version by at least 15 percent on a published microbenchmark. Otherwise it is deleted and the C version ships. Every assembly routine has a portable C reference implementation and a test that compares their outputs on random and adversarial input. Realistic assembly volume is a few hundred lines. Plugin trampolines and calling-convention shims (Windows x64 and System V differ) are the other legitimate use.

### Build and tooling

- CMake builds the C, C++, and assembly parts. Cargo builds Rust and calls CMake from `capi/build.rs`, so `cargo build` produces everything.
- `cbindgen` generates the C header, and a CI check that the committed header is current keeps the C ABI honest.
- Sanitizers (ASan, UBSan) on Linux CI. `cargo-fuzz` and libFuzzer on every parser, with a corpus checked in.
- `clang-tidy` and `clippy` run in CI and fail the build.
- Windows is the primary platform. Linux second. macOS at beta.

### Third-party code

Do not write every part from scratch, because the schedule will not allow it. Use iced-x86 (MIT) for x86-64 decoding in the Rust listing, and Zydis (MIT) when the C++ core needs its own decoder for analysis. Use Capstone (BSD) for ARM64 at first. The original work is the lifter, the IR, the analysis passes, the database, and the UI. A hand-written decoder can replace a library later if profiling says it matters. Keep a `THIRD_PARTY.md` with every dependency, version, and license.

## 4. Roadmap

### Phase 0: foundations (4 November to 30 November 2026)

- Pick the reference machine and record its specs.
- Build the benchmark harness skeleton first, before any analysis code. Measuring from day one prevents fake numbers later.
- Spike the C ABI: a Rust CLI calling a C++ function that reads a Rust-parsed PE and writes to the C database. This proves the toolchain before real code depends on it.
- Build the corpus recipe: pinned open source projects compiled with pinned compilers, with debug info kept alongside stripped copies.
- Write `ETHICS.md` and `THIRD_PARTY.md`.

Exit criterion: one command builds all four languages on Windows and Linux in CI, and the harness reports startup time for a hello-world CLI.

### MVP, v0.1 (target: end of February 2027)

Scope:
- PE and ELF parsing in Rust (x86-64 only).
- x86-64 disassembly through Zydis.
- Function discovery by entry points, exports, symbols, and recursive descent. Prologue heuristics through the SIMD scanner.
- Control flow graph and cross-reference tables stored in the database.
- Strings, names, and comments. Rename and comment edits persist.
- UI: listing view, function list, xrefs panel, strings panel, hex view, simple graph view, global search.
- CLI: `eu analyze`, `eu functions`, `eu xrefs`, `eu strings`, `eu disasm`, all with `--json`.
- Saved analysis files that reopen quickly.
- Graph tab: control flow graph per function with a layered layout, pan and zoom, and Space to switch with the listing.
- Local file checks, with no network: Shannon entropy per file and section, a packer identifier built on our own signature list, Base64 string detection with a hover tooltip, and an XOR decoder with a single-byte auto scan and manual multi-byte keys.
- 32-bit and 64-bit x86 decoding, with absolute data references resolved for 32-bit code.
- Datasets saved as `.euph`: the whole program plus saved work, compressed with zstd at level 19 and checked with SHA-256 on open. These stay on the machine and are separate from the shareable `.eupack` in section 14, which never holds program bytes.
- SQL inspector: reads SQL scripts in any common dialect and SQLite files without running them, lists what each statement does, flags risky ones, and draws a map of tables and how data moves between them.
- Aero, our own networking library: an HTTP/1.1 client over rustls, subdomain discovery from certificate logs and DNS, JSON capture, and a loopback server that replays saved responses. Nothing leaves the machine until the user allows it for that domain.
- Redirecting a URL in a binary to the local emulator: right-click a link, or run `eu redirect`, to rewrite its host to 127.0.0.1 and save a patched copy. The original file is never changed, and the edit is shown before it is saved. This is the standard sandbox move of pointing a sample at a server you control instead of the real one.
- APK analysis: decoded manifest, permissions, DEX classes, Dalvik bytecode, strings, native library list, signing schemes, and known protectors. The code stays in its own reader, and static analysis is the only thing it does.
- Dump: everything Euphoria knows about a binary or APK, written to one zip by parallel workers. It can hold code and the original file, so it stays separate from the shareable `.eupack` in section 14.
- Advanced tab with a placeholder for the Euphoria Hypervisor. The `hypervisor/` folder is empty, and the UI says plainly that nothing starts yet.
- Start screen with New project, Open local file, and a disabled Browse public database entry. SHA-256 identity for every loaded file (section 14).
- No decompiler, no plugins, no ARM64, no network code.

Exit criteria: all MVP targets in section 2 are measured and published, including the ones that miss. The function-recovery F1 is computed against the corpus. Five people outside your circle have run the tool and reported what broke.

### Beta, v0.5 (target: end of June 2027)

Scope:
- Public C ABI plugin API with versioned headers, and Python bindings.
- Plugin examples: rename-by-pattern, export-to-JSON, a custom xref analyzer.
- Mach-O parsing in Rust, and ARM64 disassembly through Capstone.
- Lifter from x86-64 to an internal IR, SSA construction, dead code removal, expression propagation. First pseudo-C output with stack variable recovery, for straightforward functions only.
- Parallel analysis scheduler tuned using profiler data from the benchmark corpus.
- Signature matching with Euphoria's own format. Do not copy or convert proprietary signature databases.
- `.eupack` export and import, annotation layers, local cache, and read-only snapshots, all working offline (section 14).
- Paid beta opens with the 20 USD founding license. Telemetry stays off.

Exit criteria: usability test passes the beta target. Fuzzers run clean for 72 hours. The public API has full docs. At least three people besides you have written a plugin.

### Public database, v0.6 (target: end of August 2027)

Scope: public catalog, hash lookup, the open-or-fresh prompt, browser, opt-in contribution, and manual moderation. Section 14.11 has the acceptance criteria. This release adds about 140 hours by rough estimate, and it moves v1.0 from October to December 2027.

### v1.0 (target: end of December 2027)

Scope:
- Control flow structuring (if, else, loops, switch) from published structuring algorithms. Basic type propagation and calling convention detection. Output is pseudo-C for x86-64.
- ARM64 stays disassembly and graph only, plus lifting if time remains.
- Frozen 1.x plugin ABI with a written compatibility promise.
- Signed Windows and Linux builds, SHA-256 checksums, and an SBOM.
- Full benchmark report with raw data, scripts, and a replication guide.
- Documentation site complete.

Exit criteria: every row in section 2 is measured. Results are published whether they hit the target or not. No open crash bugs with reproducers.

### What gets cut first if time runs short

1. macOS support moves to 1.1.
2. ARM64 lifting moves to 1.1.
3. Structuring of switch statements moves to 1.1.
4. Graph view polish and themes move to 1.1.
5. The hosted public database moves to 1.1. `.eupack` export and import stay, so people can still share dumps by hand.

The things that must not be cut: the benchmark harness, the C ABI, the database, parser fuzzing, and the documentation. They are what make the project credible.

### After v1.0

Out-of-process plugins over JSON-RPC, WASM plugin sandboxing, a debugger bridge to existing debuggers, and RISC-V and MIPS decoders. These are candidates, not promises.

## 5. Differentiators

Each one is tied to something that can be checked:

1. Analysis lives in a memory-mapped columnar file, so reopening does not parse or rebuild anything. Checked by the reopen benchmark.
2. Every UI action has a CLI equivalent with JSON output, and the same calls are available through the C API and Python. Checked by the CI rule that every command has `--json`.
3. The plugin API is a deliberately narrow, versioned C ABI, with a compatibility promise for all of 1.x. Checked by the plugin line-count and time-to-first-plugin tests.
4. The benchmark harness ships in the repo, and users can run it against their own copy of other tools. Few tools in this space publish raw data.
5. Parsers are written in Rust and fuzzed continuously. Checked by the fuzz logs and the zero-crash release criterion.
6. Pricing is 20 USD once, covering all of 1.x, with no subscription and no telemetry.
7. A public database of analysis dumps, checked by SHA-256, with a visible choice before anything opens and no code or binary bytes in any dump. Checked by the acceptance tests in section 14.11.

## 6. Benchmark plan

### Principles

- Measure equivalent work. A tool that finishes quickly because it does less is not faster. Every run records the number of functions found, xrefs, and strings, and results are shown next to those counts.
- Publish losses. If Euphoria is slower somewhere, the table says so.
- Report medians and p95 over at least 10 runs, with min, max, and standard deviation. Report cold cache and warm cache separately.
- Pin everything: tool versions, compiler versions, OS build, CPU model, RAM, power plan.
- Raw results (JSON) are committed to the repo with each release.

### Corpus

Only redistributable binaries that you build yourself or that are clearly licensed for this use:

| Size class | Examples | Notes |
|---|---|---|
| Small (under 1 MB) | zlib, a small CLI utility | Startup-dominated |
| Medium (1 to 10 MB) | SQLite, curl, Lua | Typical analysis |
| Large (10 to 100 MB) | LLVM tools, a large game engine demo or browser component built from source | Memory and scheduling |
| Very large (100 MB and up) | A full Chromium component or LLVM build | Stress test |

Each is built with gcc, clang, and MSVC at -O0 and -O2, with debug info saved separately. The debug info is the ground truth for function boundary scoring. No malware, no commercial software, and no cracked or leaked binaries are ever part of the corpus.

### Comparators

- Ghidra (current stable release), which anyone can run.
- radare2 or rizin, for a fast native baseline.
- Binary Ninja, if you hold a license.
- IDA Pro or IDA Free. Read the current license terms before publishing any numbers, since some vendors restrict publishing benchmarks. If publishing is restricted, ship a script that lets users run the same tasks against their own IDA install and does not publish IDA numbers itself.

### Tasks

1. Cold start to idle UI (or to ready CLI).
2. Full auto-analysis, headless, wall time and peak memory.
3. Reopen a saved analysis.
4. Substring search for names and strings.
5. Function boundary precision, recall, and F1 against ground truth.
6. Decompile 200 sampled functions, report latency and the share that compile after minimal fix-up (v1.0 only).
7. Plugin task: the same "rename functions matching a pattern" task written for each tool's API, with line count and time for a new user.
8. Public dump load against fresh local analysis of the same binary, in Euphoria only. Report load time, memory, and how much the two results differ.

### Harness

A `bench/` directory with one script per task, a `results/` folder of JSON, and a `REPLICATE.md` with the exact steps. A GitHub issue template titled "Benchmark discrepancy" lets other people report that they could not reproduce a number. Benchmarks run on release candidates, on the reference machine, not on shared CI runners, because shared runners are too noisy to trust.

### Reporting

The README shows one summary chart and links to the full report. The report includes methodology, hardware, every run, the wins, and the losses. Charts always start at zero.

## 7. GitHub plan

### Repository layout

```
euphoria-re/
  README.md
  LICENSE
  ETHICS.md
  SECURITY.md
  CONTRIBUTING.md
  CODE_OF_CONDUCT.md
  CHANGELOG.md
  THIRD_PARTY.md
  CMakeLists.txt
  Cargo.toml
  core/          C++ analysis engine
  db/            C database
  simd/          assembly and C fallbacks
  capi/          ABI definitions and generated header
  formats/       Rust parsers
  engine/        Rust API shared by the CLI and UI
  aero/          Rust networking library
  sql/           Rust SQL inspector
  hypervisor/    reserved for the Euphoria Hypervisor, empty for now
  pack/          Rust reader and writer for the .eupack format
  publicdb/      catalog builder, write API, moderation tools
  ui/            Rust UI
  cli/           Rust CLI
  bindings/      Python
  plugins/       Lua plugin host, API docs, and examples
  bench/         harness, corpus recipes, results
  docs/          documentation site source
  fuzz/          fuzz targets and corpora
  .github/       workflows, issue templates
```

### README structure

1. Title, one-line pitch, badges (CI, release, license).
2. A short GIF of the UI opening a saved analysis, with the reopen time shown on screen.
3. What Euphoria is, and an honest "what it is not yet" list.
4. Benchmark summary: one chart, a link to the full report, and a note on where it loses.
5. Install: download a release, or build from source in three commands.
6. 60-second tour: CLI example with JSON output, then a 20-line plugin.
7. Feature status table: what works, what is in beta, what is planned.
8. Comparison with Ghidra, rizin, and IDA that states strengths and gaps plainly.
9. Architecture overview with the diagram from section 3.
10. Pricing and license.
11. Ethics and acceptable use.
12. Contributing, docs links, contact.

### Docs

Quickstart, CLI reference, C API reference (generated), Python API reference, plugin tutorial, architecture guide, database format spec, benchmark methodology, the `.eupack` format spec, a privacy page listing every network request the app can make, the public database policy, and a FAQ that includes the "why not just use Ghidra" question answered fairly.

### Demo assets

- A 15-second GIF of reopen speed.
- A 60-second screen recording with captions, no music.
- An asciinema recording of the CLI.
- The benchmark chart as SVG, regenerated by the harness so it cannot go stale.
- A static screenshot set for the landing page.

### Issue templates

Bug report (with a field for the binary's source and license), crash report with reproducer, feature request, format or architecture request, plugin API feedback, benchmark discrepancy, and security report that points to `SECURITY.md` instead of a public issue.

### Release plan

- SemVer. Tags `v0.1.0`, `v0.5.0`, `v1.0.0`.
- Release builds for Windows and Linux, signed where possible, with SHA-256 checksums and an SBOM.
- A `CHANGELOG.md` entry for every release, and release notes that state known issues.
- A nightly channel for people who want it, clearly labeled unstable.
- Each release attaches the benchmark JSON that was measured on that build.

### Contribution guide

Build instructions, code style per language, how to add a file format or architecture, the rule that every parser needs a fuzz target, the rule that every benchmark claim needs a reproducible script, DCO sign-off instead of a CLA, and a "good first issue" label kept stocked with real tasks. Contributors may not submit code derived from proprietary tools or leaked sources. State this in the guide.

## 8. Pricing and revenue

### Model

- Source: public on GitHub under the PolyForm Noncommercial License 1.0.0. Personal and other noncommercial use is free, and commercial use needs a paid license. Have a lawyer review this before the paid launch.
- Price: 20 USD, one time, one person, all 1.x releases. A 2.0 release may be a separate paid upgrade. Say that on the pricing page.
- Free access: students and open source maintainers can request a free key. Source builds stay free for non-commercial use.
- Sales platform: use a merchant of record such as Lemon Squeezy, Paddle, or Gumroad, so VAT and sales tax are handled for you. Check current fee tables. Fees of 8 to 10 percent on a 20 USD sale are a safe planning figure.

### The 2000 USD goal

2000 USD gross needs 100 sales. After fees, 100 sales nets roughly 1800 to 1850 USD, so reaching 2000 USD net needs about 110 sales. Plan for 110.

Rough funnel math, with every rate an assumption you will replace with real data:

| Step | Assumption | Result |
|---|---|---|
| Qualified visits to the repo or landing page | 8,000 over 90 days | |
| Visitors who download or star | 10 percent | 800 |
| Download-to-purchase conversion | 12 percent | about 96 |

That path is plausible but not guaranteed. A reasonable range for the first six months is 20 to 150 sales, depending on how well the launch lands. Treat 100 as the goal, not the forecast. The project is worth building for the CV even at 30 sales.

### Checkpoints

| Date | Cumulative sales | Action if behind |
|---|---|---|
| 4 weeks into paid beta | 15 | Rewrite the landing page, add a demo video |
| v1.0 release | 40 | Publish the benchmark write-up, post to more communities |
| 90 days after v1.0 | 110 | Offer a team license, run a conference talk or CFP |

### Price changes

The 20 USD price is a founding price. If you raise it at v1.0, say so in advance and honor it. Do not invent a countdown timer or fake scarcity.

## 9. Launch plan

### Pre-launch (from February 2027)

- Start a public devlog after the MVP ships. One post a month with real measurements, including failures.
- Keep a waitlist page with an email form. No dark patterns, one email per milestone.
- Share the benchmark harness early and ask people to try it on their machines.

### Beta launch (June 2027)

1. A technical write-up, such as "How the reopen time dropped to X ms with a memory-mapped analysis database", using real numbers from your harness.
2. Show HN, posted Tuesday to Thursday morning US Eastern, with a plain title and a working download. Be present for the comments.
3. Posts in r/ReverseEngineering, r/rust, r/cpp, and relevant Discord servers, following each community's self-promotion rules. Read the rules first. Do not cross-post identical text.
4. A short video demo.
5. Direct messages to a handful of reverse engineers and CTF players asking for feedback, not for reposts.

### v1.0 launch (December 2027)

1. Full benchmark report with raw data, plus a comparison page that states where Euphoria loses.
2. Release notes, a second Show HN only if there is a real new story, and a Lobsters post.
3. A conference or meetup talk proposal using the architecture as the topic.
4. A thank-you post to beta users and contributors.

### Support

Fast replies on issues in the first month matter more than any ad. Aim for a first response within 48 hours.

## 10. CV bullets

Rule: every bracketed number gets replaced by a number from your own benchmark results. Delete any bullet you cannot back up with a measured figure.

- Designed and built Euphoria, a source-available x86-64 and ARM64 disassembler and decompiler workbench with a C++20 analysis core, a C database layer, Rust parsers and UI, and a stable C plugin ABI.
- Reduced saved-analysis reopen time for a 50 MB PE to [X] ms by moving to a memory-mapped columnar database, compared with [Y] ms for [comparator] in a published, reproducible benchmark.
- Built a parallel analysis scheduler that analyzes a [N] MB binary in [X] seconds on 8 cores and peaks at [Y]x the input size in memory, measured against DWARF and PDB ground truth with an F1 score of [Z] for function boundaries.
- Wrote Rust parsers for PE, ELF, and Mach-O and fuzzed them with cargo-fuzz and libFuzzer; ran [N] billion executions and fixed [M] memory-safety and logic bugs before release.
- Implemented AVX2 pattern-scanning routines in NASM with runtime CPUID dispatch and a verified C fallback, speeding signature scans by [X] percent over the intrinsic version.
- Designed a versioned, documented C ABI that connects C++, Rust, and Python, and wrote the plugin SDK; [N] outside contributors wrote working plugins during the beta.
- Built a lifter, SSA pipeline, and control-flow structuring pass that emits pseudo-C for x86-64, and measured readability and compile success on [N] sampled functions.
- Shipped v1.0 with signed builds, SBOM, CI on Windows and Linux, and [N] paying users, with a public benchmark harness other people have independently reproduced.

One-line summary for a profile or portfolio: "Built a native disassembler and decompiler workbench in C++, C, Rust, and assembly, with a reproducible benchmark suite and a stable plugin ABI."

## 11. Legal and ethical notes

I am not a lawyer. Have one check the license text, the terms of sale, and anything touching benchmark publication or reverse engineering law in your country.

### Acceptable use

- Euphoria is for analyzing binaries you own or have explicit permission to inspect: your own software, open source projects, CTF challenges, malware samples in an isolated lab you are authorized to run, and security research under a legitimate agreement or recognized disclosure process.
- Put this in `ETHICS.md`, the README, the installer, and the license. State plainly that it does not support piracy, license bypassing, or attacks on systems you do not own.
- Laws on reverse engineering, interoperability, and security research differ by country and by contract. Users are responsible for knowing their own.

### Product decisions that follow from this

- Aero only touches a domain after the user confirms they own it or have permission to test it, and the prompt warns that the server's operator may see the traffic. Subdomain discovery uses certificate logs and a short list of common names, and it does not brute force or crawl.
- No features whose purpose is to remove license checks, generate keys, or bypass copy protection. Patching and editing remain general tools for legitimate work like fixing your own binaries or testing.
- No cracked, leaked, or pirated binaries in the repo, the docs, the demos, or the benchmark corpus. Demos use open source software and your own builds.
- No malware samples in the repo. Documentation recommends analyzing untrusted code only in a disposable virtual machine.
- Telemetry off. If you add opt-in crash reporting later, say exactly what it sends.
- Report-abuse and security contact addresses in `SECURITY.md`.

### Clean-room rules

- Do not use leaked or decompiled code from any commercial tool. Do not reverse engineer another vendor's file formats, signature databases, or type libraries to copy them.
- Contributors must confirm they wrote their code or have the right to submit it.
- Keep `THIRD_PARTY.md` current and respect every dependency license. Check that the license of Zydis, Capstone, and any Rust crate is compatible with how you sell the binaries.
- Do not use another company's name or logo as your own branding. Comparisons name competitors factually and neutrally, and link to their own pages.

## 12. Risks

| Risk | Likelihood | Mitigation |
|---|---|---|
| Scope grows past the time budget | High | Hard cut list in section 4, MVP exit criteria before beta work starts |
| Benchmark targets are missed | Medium | Publish real numbers, narrow the claim, and still report the engineering story |
| Four-language build becomes painful | Medium | One build command in CI from week one, one C ABI, no cross-language shortcuts |
| Decompiler quality disappoints users | High | Market it as pseudo-C for simple functions in 1.0, never as a Hex-Rays equivalent |
| 100 sales not reached | Medium | Checkpoints with specific fixes, and value the project as a portfolio piece either way |
| Name collision hurts discoverability | Medium | Use `euphoria-re`, strong tagline, own domain |
| Legal challenge on comparisons or licensing | Low | Neutral wording, license review, no use of competitor names in branding |
| Source builds replace paid sales | Medium | Sell signed builds, updates, and support, and accept that some users will compile |

## 13. First 30 days checklist

1. Pick and document the reference machine.
2. Create the repo with the layout from section 7, plus empty `ETHICS.md`, `THIRD_PARTY.md`, and `LICENSE`.
3. Get Cargo and CMake building one call across Rust, C++, C, and assembly, on Windows and Linux CI.
4. Write the benchmark harness and run it on hello-world startup.
5. Script the corpus builds with pinned compilers and save the debug info.
6. Write the first draft of the C ABI header and a one-page spec of the database format.
7. Fuzz the first PE parser for an hour and commit the corpus.
8. Reserve the domain, the sales account, and the repo name after the trademark and name check.

## 14. Project start flow and public analysis database

When someone loads a binary, Euphoria hashes it, checks whether an analysis already exists, and asks what to do. Analysts can skip work that someone has already done on an open source library or a CTF binary, and they stay in control of what they trust and what leaves their machine.

IDA's Lumina shares function metadata between users, so the idea has precedent. Euphoria's version works on whole-binary dumps, keeps the data open, and lets you run your own server later. This section makes no claim that it is better or faster than Lumina or anything else. The only performance figures it allows are the ones from benchmark task 8.

### Four decisions that shape everything else

Dumps contain no code. A dump holds function boundaries, names, types, comments, and tags, addressed by offset. It has no raw bytes, disassembly text, pseudo-C, or string contents. Publishing decompiled proprietary code is a real copyright problem, and leaving it out removes most of that risk. It also means a dump is only useful to someone who already has the binary, so the database cannot be used to get software.

Binary upload does not exist. The stronger rule is simpler to explain and to audit than a consent checkbox: no code path in the client can send binary bytes. If binary sharing is ever added, it would be a separate, separately consented feature with its own legal review.

Network use is off by default. Sending a SHA-256 tells the server what you are looking at, and that matters for unreleased software or an active incident. Euphoria starts offline. The user turns on lookups themselves, on a settings screen and through a first-run question that defaults to No.

Reads are static files. A 20 USD lifetime product cannot fund an always-on search backend indefinitely. The read path is a signed catalog and hash-prefix buckets on object storage behind a CDN. The only running service is a small write API for contributions. Running costs stay low and predictable, and anyone can mirror the data. Check current hosting prices before committing, and set a monthly spending cap.

### 14.1 UI flow and state machine

The start screen has three main actions and a recent files list:

- New project creates a named folder holding one or more binaries, analysis options (architecture override, base address, load options), the analysis database, and annotation layers.
- Open local file takes a binary, a project, or an `.eupack`. It also handles drag and drop.
- Browse public database opens the catalog browser. Offline, it shows the last downloaded catalog and its age, or an explanation of how to turn on lookups.

The pre-analysis prompt:

```
A public analysis exists for this file

  File name     libfoo.so.1 (as named by the contributor)
  Architecture  x86-64, ELF
  SHA-256       3f2a...91c4  [copy]
  Analyzed      2027-08-14
  Contributor   example-handle (reputation 18)
  Tool version  Euphoria 0.6.2
  Confidence    Medium (62)  [how this is calculated]
  Tags          open-source, compression
  Notes         Built from upstream 1.3.1, names checked against source.

  This dump was made with an older Euphoria version. Some results may differ.

  [ Open public dump ]    [ Start fresh local analysis ]

  Public dumps open read-only. You can fork one to add your own notes.
```

The two buttons have equal visual weight, and neither is preselected. There is no "always do this" option in the MVP, because automatically trusting third-party data is the wrong default for this audience. The contributor's fields are shown as plain text, and links in them are not clickable.

States and transitions, owned by the `engine` crate so the UI and CLI share one implementation:

| State | Event | Next state |
|---|---|---|
| Start | New project | ProjectSetup |
| Start | Open local file | Hashing |
| Start | Browse | Browser |
| ProjectSetup | File chosen | Hashing |
| Hashing | Done | LocalLookup |
| Hashing | Read error | Error |
| LocalLookup | Own project exists for this hash | OwnProjectPrompt |
| LocalLookup | Cached public dump found | HitPrompt |
| LocalLookup | No match, online | RemoteLookup |
| LocalLookup | No match, offline | Analyzing |
| RemoteLookup | Dump found | HitPrompt |
| RemoteLookup | Not found, timeout, or error | Analyzing, with a quiet status note |
| OwnProjectPrompt | Reopen | LocalProject |
| OwnProjectPrompt | New analysis | LocalLookup, skipping own projects |
| HitPrompt | Open public dump | Verifying |
| HitPrompt | Start fresh | Analyzing |
| Verifying | Pack hash, signature, and binary hash match | Snapshot |
| Verifying | Any check fails | Error, offering fresh analysis |
| Snapshot | Fork | LocalProject, with the public dump as a read-only layer |
| Snapshot | Compare | Compare |
| Analyzing | Done, hash was not in the database | LocalProject, with a contribution offer |
| Analyzing | Done, hash was in the database | LocalProject, with a Compare option |
| Browser | Open dump with matching local file | Hashing, then HitPrompt |
| Browser | Open dump with no local file | NeedBinary |
| NeedBinary | User selects the matching file | Verifying |
| NeedBinary | Selected file has a different hash | NeedBinary, with an error |

A slow network never blocks the app. Remote lookup has a 1.5 second timeout, which is a starting value. If a result arrives after analysis has started, it shows as a banner, and analysis keeps going.

The CLI never prompts or uses the network unless told to:

```bash
eu open app.bin --fresh
```

```bash
eu open app.bin --public-dump <dump-id>
```

`eu lookup app.bin --online` checks for dumps and prints JSON, with exit codes that scripts can test.

Identity is SHA-256 over the exact file bytes on disk. That is the only lookup key. Import hash (PE) and TLSH or ssdeep are optional later additions for "similar binaries" suggestions in the browser. They never open a dump automatically, because a near match has different offsets.

### 14.2 Local cache and offline mode

Everything except fetching new data works with no network. Offline is the default mode, and it has a CI test that runs the full flow with networking blocked.

| Mode | What it does | Default |
|---|---|---|
| Offline | No network requests at all | Yes |
| Lookup | Downloads the catalog and hash-prefix buckets, and fetches dumps the user chooses | No |
| Contribute | Lookup, plus sign-in and uploads the user approves one at a time | No |

The cache lives in the platform's standard folder (`%LOCALAPPDATA%\Euphoria` on Windows, `~/.cache/euphoria` on Linux):

- `index.sqlite` holds cached dump metadata, lookup results, the catalog, and last-used times.
- `dumps/3f/2a/<dump-id>.eupack` holds the packs, stored by content hash and verified on every load.
- Lookup results expire: 24 hours for "not found", 7 days for a hit's metadata. Both are starting values.
- A default 2 GB limit with least-recently-used eviction. Pinned dumps and anything a local project depends on are never evicted.

Hash lookups use a k-anonymity pattern. The client requests a bucket by the first 20 bits of the SHA-256 and matches the full hash locally, so the server and CDN never receive the full hash during a lookup. The bucket request still narrows things down and shows an IP address, and the privacy page says that plainly. Fetching a dump does reveal which one you picked.

### 14.3 Database schema

Server side in Postgres. The MVP needs the first five tables, and the rest arrive with later versions.

| Table | Main columns | Purpose |
|---|---|---|
| `binaries` | `sha256` (primary key), `size`, `format`, `arch`, `first_seen`, `status` | One row per binary identity, with no file contents |
| `dumps` | `id`, `sha256`, `parent_dump_id`, `contributor_id`, `display_name`, `category`, `status`, `created_at` | One analysis line by one contributor |
| `dump_versions` | `id`, `dump_id`, `version_no`, `pack_sha256`, `pack_size`, `format_version`, `tool_version`, `config_hash`, `auto_layer_hash`, `notes`, `created_at` | Immutable, append-only releases of a dump |
| `contributors` | `id`, `handle`, `github_id`, `reputation`, `status`, `created_at` | Public identity and standing |
| `reports` | `id`, `dump_version_id`, `reporter_id`, `reason`, `details`, `status`, `resolved_by`, `created_at` | Reports and their outcomes |
| `provenance` | `dump_version_id`, `tool_build_hash`, `plugins`, `has_human_edits`, `category_attestation`, `signature` | How a version was produced |
| `confidence` | `dump_version_id`, `score`, `level`, `formula_version`, `inputs`, `computed_at` | Stored score with its inputs, so it can be explained |
| `confirmations` | `dump_version_id`, `contributor_id`, `matched_auto_layer`, `created_at` | Other users reproducing the automatic results |
| `tags` | `dump_id`, `tag` | From a controlled list |
| `moderation_log` | `id`, `actor_id`, `action`, `target`, `reason`, `created_at` | Public record of moderation actions |

Version rows are never edited. Corrections create a new version, and removals change `status`, so history stays auditable.

### 14.4 Duplicates and versioning

One binary can have many dumps, and each dump can have many versions:

- The same contributor updating their work creates a new version of their dump.
- A different contributor building on a dump creates a new dump with `parent_dump_id` set, which credits the original.
- Independent work creates a new dump with no parent.

Exact duplicates are rejected using `pack_sha256`. For that to work, packs must be deterministic: sorted records, canonical JSON, and timestamps kept only in the manifest, outside the content hash. Re-uploading identical content returns the existing dump.

Purely automatic dumps get a stricter rule. If `auto_layer_hash` and `tool_version` match an existing dump and there are no human annotations, the upload counts as a confirmation of that dump and does not create a new one. This stops the catalog from filling with copies of the same output.

The browser shows the top-ranked dump for each binary and collapses the rest under "N other dumps". The MVP caps active dumps at 20 per binary, which is a starting value.

### 14.5 Trust and reputation

A confidence score has to be explainable, so the formula is public and the UI shows each input. It measures provenance and agreement, and it does not prove a dump is correct. The docs and the tooltip say that directly.

Starting formula, stored with a `formula_version`. The weights are first guesses and should change as real data arrives.

| Input | Points |
|---|---|
| Base | 20 |
| Tool version: current minor release / older minor / older major | 20 / 10 / 0 |
| Confirmations from distinct established accounts | 10 each, up to 30 |
| Contributor reputation | 0 to 30 |
| Open reports from established accounts | minus 5 each, up to minus 30 |
| Upheld reports | minus 15 each |

The score is clamped to 0 to 100. High is 70 and up, Medium is 40 to 69, and Low is under 40.

Reputation starts at 5, gains 2 when another account confirms a dump, and loses 10 for each upheld report. It is capped at 30, and weekly gains are limited so it cannot be farmed quickly. An established account is at least 30 days old with at least one accepted dump.

Confirmations work because automatic analysis is reproducible. Anyone with the binary and the same tool version can re-run it and compare `auto_layer_hash`, without uploading anything but the result. Human annotations cannot be confirmed this way, so they are labeled as such in the UI.

Moderation stays simple. Report reasons are: incorrect analysis, misleading notes, secrets or personal data, piracy-related content, and legal complaint. Reports lower the rank straight away. Two reports from established accounts hide a dump until it is reviewed, and legal or personal data reports hide it after one. You are the only moderator at first, so publish a realistic response target (72 hours) and keep the `moderation_log` public. Hidden dumps already in someone's cache show a warning at their next catalog refresh.

A malicious dump cannot run code, because packs hold only data and the reader is a fuzzed Rust parser with strict limits on size and record counts. It can still mislead someone, for example by naming a backdoor `check_update`. So every public annotation stays visually marked as public, and the snapshot view keeps showing who wrote it. Compare mode is the way to check.

### 14.6 Diff and merge

Annotations live in layers, and the merged view applies them in order:

1. `auto`, produced by the tool.
2. `public`, read-only and pinned to a specific dump version.
3. `local`, the user's own work.

Local beats public, and public beats auto. Each annotation is keyed by binary hash, address, and kind (function boundary, name, type, comment, tag). A fork adds an empty local layer on top of the pinned public version, so it costs almost nothing and no edit ever touches public data.

Compare mode shows a table of differences between any two of these sources, such as a public dump and a fresh local analysis. It groups differences into functions only in A, functions only in B, boundary changes, name changes, and type changes.

When a new public version appears, Euphoria offers a three-way merge between the pinned version, the new version, and the local layer. Non-conflicting changes apply automatically and are listed. Conflicts are shown side by side for a decision. Merges never delete local work, and the previous pin is kept so a merge can be undone.

The MVP ships layers, fork, and a read-only compare table. Three-way merge comes in v1.0, and until then users stay pinned to the version they forked and see a notice when a newer one exists.

### 14.7 Search and filters in the browser

Search runs locally against the downloaded catalog using SQLite full-text search. No query ever reaches a server, which suits both privacy and cost. The catalog should stay manageable into the tens of thousands of dumps. Measure its size as it grows, and move to server-side search only when the numbers demand it.

MVP filters: exact SHA-256 or hash prefix, display name, architecture, file format, tag, category, tool version, confidence level, contributor, date range, and "has human annotations". Sorting options are confidence, newest, and most confirmed.

Later: exported symbol name search, import hash, similar binaries, and saved searches.

Results show metadata only, and notes render as plain text. The browser has no download links, because no binaries exist to download. Selecting a dump without a matching local file leads to the NeedBinary state, which asks for the file and verifies its hash.

### 14.8 Auth, rate limits, and abuse prevention

Reading needs no account. Contributing requires GitHub sign-in through the OAuth device flow, so Euphoria stores no passwords. The resulting token is scoped to contributions, sits in the OS keychain, and can be revoked. Requiring a GitHub account limits throwaway abuse but excludes some people, which is an acceptable trade for a one-person moderation team.

Starting limits, which should be tuned using real traffic:

| Action | Limit |
|---|---|
| Catalog and bucket reads | CDN cached, with a coarse per-IP limit at the edge |
| Uploads, accounts under 30 days old | 2 per day |
| Uploads, established accounts | 20 per day |
| Reports | 20 per day |
| Pack size | 50 MB compressed |
| Storage per contributor | 500 MB, raised on request |
| Name / comment / note length | 512 bytes / 4 KB / 8 KB |

The field limits also stop people from smuggling binaries or source code inside annotations. Server validation parses every pack with the same Rust reader as the client, checks the schema and limits, and flags high-entropy or base64-like text for review. It rejects addresses outside the declared binary size. In the MVP, a contributor's first three dumps are reviewed by hand before they appear.

The catalog and buckets are signed with an Ed25519 key pinned in the client, so a compromised CDN cannot alter what users see. The signing key stays offline, and the docs describe how it would be rotated. A global switch can pause all uploads if something goes wrong.

### 14.9 Export and import format

`.eupack` is the one format used for sharing by hand, caching, and publishing. It is a zstd-compressed tar archive with a public spec:

```
manifest.json       format version, binary SHA-256 and size, architecture, tool version,
                    config hash, layer hashes, contributor, category, created date
functions.jsonl     address, size, source
names.jsonl         address, name, source
types.jsonl         address, type definition
comments.jsonl      address, text, author layer
tags.json           tags
```

The commands, all with `--json`:

```bash
eu dump export project.euproj --layer local -o my-notes.eupack
```

```bash
eu dump import my-notes.eupack
```

```bash
eu dump verify my-notes.eupack --binary app.bin
```

```bash
eu dump diff a.eupack b.eupack
```

Readers support every earlier format version, and unknown fields are ignored within a major version. The binary hash and size in the manifest must match the local file before anything loads. A `.eupack` can be exchanged privately with no account and no server involved, and that is also the fallback if the public service ever closes.

### 14.10 Contribution, consent, and legal rules

After a local analysis of a binary with no dump, a small dismissible banner offers to share it. It never appears as a modal, and it is disabled unless the user is in Contribute mode. Choosing to share opens a review screen:

| Goes up | Control |
|---|---|
| SHA-256, file size, format, architecture | Always, required for lookup |
| Tool version, config hash, plugin list, auto layer hash | Always |
| Function boundaries and types | Always |
| Names and comments from your local layer | Off until ticked, with a line-by-line preview |
| Display name, tags, notes | Optional, and the file name is blank by default |

| Never goes up |
|---|
| Binary bytes, disassembly, pseudo-C, or string contents |
| File paths, machine name, or OS username |
| Other project files or plugin private data |

The screen shows the exact manifest and data that will be sent, along with these required confirmations:

- A category choice: my own software, open source (with a source URL), or CTF or teaching material.
- A statement that "I own this binary or have permission to inspect and share this analysis."
- A statement that "This will be public, tied to my handle, and copies may remain after deletion."

Consent is per upload, with no "always upload" setting. The CLI needs the full hash repeated, which prevents an accidental upload from a script:

```bash
eu dump publish project.euproj --confirm-sha256 <full-hash>
```

A local log records every upload. Contributors can withdraw a dump at any time, which removes it from the catalog at the next build.

Rules for the public database, published as a policy page and enforced through moderation:

- Only analyze binaries you own or have permission to inspect.
- The MVP accepts open source, your own software, and CTF or teaching material. Dumps of third-party commercial software are not accepted, even without code, since EULAs and local law vary too much to review alone. Malware analysis dumps are also out for the MVP, and they can be reconsidered with a separate policy.
- No piracy support: no crack, keygen, or license-bypass notes, no such tags, and no links to such material. Violations are removed, and accounts can be banned.
- No secrets or personal data in notes. The review screen warns about strings that look like keys or email addresses.
- A published takedown process with a contact address, covering copyright and personal data complaints, with hide-first handling.
- Keep IP logs for abuse handling only, with a short retention period (30 days as a starting value), and offer account deletion. Contributors' handles and dumps are personal data under laws such as GDPR, so write the privacy notice before launch.
- License contributions under CC0 or CC BY so that the data stays open and mirrors stay legal.

Have a lawyer review this policy before v0.6 goes live. Treat that as a launch gate. If the review says it needs more than you can reasonably run, ship `.eupack` sharing alone and hold back the hosted service.

### 14.11 MVP acceptance criteria

All of these need to pass before v0.6 ships:

1. The start screen offers New project, Open local file, and Browse public database, and each path reaches a working state in the app with the network disabled.
2. A fresh install makes zero network requests until the user turns on Lookup or opens the plugin Marketplace (section 16). Verified by a packet capture test and a CI run with networking blocked.
3. SHA-256 for a given file matches `sha256sum` on the corpus.
4. Lookup checks the local cache before the network, and a lookup never sends a full hash. Verified by inspecting requests against a test server.
5. A hit shows the prompt with file name, architecture, hash, analysis date, contributor, tool version, confidence, tags, and notes, and nothing opens until the user chooses.
6. A public dump opens read-only, and edits are impossible until the user forks it. Forking leaves the cached pack byte-identical.
7. A fresh analysis on a binary with a public dump finishes without changing any cached or public data.
8. A dump from an older tool version shows the warning in the prompt.
9. Corrupted, tampered, or mismatched packs and catalogs are rejected with a clear error and an offer of fresh analysis. Covered by automated tests, plus 72 clean hours of fuzzing on the pack reader.
10. A test proves that no binary bytes, disassembly, string contents, file paths, or usernames appear in an uploaded pack. An upload cannot happen without the review screen or the CLI hash confirmation.
11. Reporting a dump works, and a hidden dump disappears from the browser at the next catalog refresh.
12. The privacy page lists every network request the app can make, and it matches a captured trace.
13. The catalog launches with real entries: dumps of the open source benchmark corpus, so the first users are not looking at an empty database.
14. Five people outside your circle complete the open, prompt, fork, and contribute tasks without help.

Feature targets, to be measured and published the same way as section 2. All of these exclude hashing time unless noted:

| Metric | Target |
|---|---|
| Local cache lookup | Under 10 ms p95 |
| Remote lookup timeout | 1.5 s, without blocking the UI |
| Browser search over a 10,000-entry catalog | Under 100 ms p95 |
| Hash speed | Record the measured figure, no target until there is data |

### 14.12 What ships when

| Capability | v0.1 | v0.5 | v0.6 | v1.0 | Later |
|---|---|---|---|---|---|
| Start screen, New and Open, SHA-256 | Yes | | | | |
| `.eupack`, layers, local cache, read-only snapshots, fork | | Yes | | | |
| Catalog, k-anonymity lookup, prompt, older version warning | | | Yes | | |
| Browser with local search and filters | | | Yes | | |
| Opt-in contribution, GitHub sign-in, reports, manual review | | | Yes | | |
| Compare table, "analyze anyway" path | | Compare | Fresh analysis button | | |
| Confidence score and reputation | | | Simple version | Full formula, confirmations | |
| Three-way merge of annotation layers | | | | Yes | |
| Private database for solo users and teams, same API and format | | | | | 1.x |
| Similar binaries by import hash and fuzzy hash | | | | | 1.x |
| Contributor-signed dumps, public moderators | | | | | 1.x |

The rough 140-hour estimate for v0.6: client flow 40, pack format and validation 30, catalog and write API 30, contribution and moderation 30, docs and policy 10. Track real hours against it, and if the first two pieces overrun by more than half, use the cut list in section 4.

Pricing does not change. Lookups, browsing, and contributing work in every build, including free source builds, because a contribution database needs as many contributors as possible. Paying buyers get the same signed builds and updates as before. If you ever shut the service down, publish the final catalog and packs as an open archive, and say so in advance on the policy page.

### 14.13 Risks specific to this feature

| Risk | Likelihood | Mitigation |
|---|---|---|
| Empty database, so the feature looks dead | High | Seed from the benchmark corpus, and keep the browser low-key in the UI until it has real entries |
| A takedown or legal complaint | Medium | No code in dumps, restricted categories, hide-first process, legal review as a launch gate |
| Moderation takes more time than one person has | Medium | Pre-review for new contributors, upload limits, global upload pause switch |
| Misleading annotations fool someone | Medium | Visible public markings, plain-text notes, Compare mode, fresh analysis always one click away |
| Hosting costs outlast the revenue | Medium | Static read path, spending cap, storage quotas, open archive as the exit plan |
| Hash lookups leak what someone is analyzing | Low with mitigations | Off by default, k-anonymity buckets, plain explanation on the privacy page |
| Feature delays the core analysis work | High | v0.6 comes after the beta, and the hosted part is on the cut list |

### 14.14 CV bullets for this feature

Same rule as section 10: replace each bracket with a measured figure, or delete the bullet.

- Designed a privacy-first analysis sharing system: offline by default, SHA-256 identity, and k-anonymity hash-prefix lookups, so servers never receive a full file hash during a check.
- Built a deterministic, versioned `.eupack` format and a fuzzed Rust reader that treats every dump as untrusted input; ran [N] billion fuzz executions and fixed [M] bugs before release.
- Implemented layered annotations (auto, public, local) with read-only snapshots, cheap forks, and three-way merges that preserve local work.
- Served [N] dumps from a signed static catalog on object storage with local full-text search, keeping search under [X] ms p95 with no server-side query logging.
- Designed a published, explainable confidence score using tool version, reputation, reports, and reproducibility confirmations through hashes of automatic analysis results.
- Wrote and enforced the consent model, content policy, and takedown process for a public dataset, with automated tests proving that uploads contain no binary bytes, code, or local paths.

## 15. What goes in the Advanced tab

Advanced is for features that can crash the machine, touch other processes, or need extra rights. Each one stays off until the user starts it, and each one says what it is about to do. Ordinary analysis tools belong in their own tabs.

Suggested build order, easiest and safest first:

| Order | Feature | What it does | What it needs |
|---|---|---|---|
| 1 | Analysis settings | Worker threads, memory limit, base address override, turning the prologue scan on or off | Nothing new |
| 2 | Network mode | The Offline, Lookup, and Contribute switch from section 14, plus a log of every request the app made | Nothing new |
| 3 | Run a function in isolation | Emulates one function with no OS underneath, which is useful for decoding strings without running the program | An emulator library, with its license checked first since Unicorn is GPL |
| 4 | Open in a sandbox | Launches a patched copy in Windows Sandbox with networking off or pointed at the Aero emulator | Windows Pro or a VM |
| 5 | Debugger bridge | Keeps Euphoria in sync with x64dbg or GDB while debugging a process you own | A protocol for each debugger |
| 6 | Euphoria Hypervisor | Observes code from below the OS on AMD CPUs | A signed kernel driver or test signing, administrator rights, and a spare machine or VM to test on |

Before any hypervisor code goes in the repo, three things need settling. Get the license from .zhk_ in writing, because code you can't legally redistribute can't ship in a paid product. Read every line, since a kernel driver bug or backdoor affects the whole machine. Budget for driver signing too, because Windows won't load an unsigned driver on a normal setup, and a signing certificate plus Microsoft's process costs real money against a 2000 USD revenue goal.

Staying out of Advanced: anything built to hide from anti-cheat, DRM, or security software. That rule keeps the hypervisor in the same place as the rest of section 11, and it matters for how the project reads on a CV.

## 16. Plugins

Plugins are Lua 5.4 scripts, each one a single file. The API is documented in `plugins/README.md`.

Shipped now:

- Local section: lists plugins from the plugin folder, and each stays off until the user turns it on and sees what it asks for.
- A sandbox with no file, network, or code-loading libraries, a 250 ms limit per call, and a 128 MB memory limit, with one Lua state per plugin so a crash stops only that plugin.
- Plugins can add tabs, read the open binary, jump the listing, and listen for events.
- Discord presence as an opt-in permission, and three example plugins.

Marketplace section: a placeholder for now, and it contacts nothing.

When the repo exists, opening the Marketplace section fetches a signed `index.json` from GitHub. This is a deliberate exception to the offline default, and the user chose it. The request reveals an IP address to GitHub and nothing about the open file, and a setting turns it off. Each listing should pin a SHA-256 of the plugin file so a changed file fails to install, and installed plugins still start switched off.

Next for the API, in order: writing names and comments back to the analysis, a graph widget, an HTTP permission that goes through Aero and asks per domain, and a stable version promise for `api_version` 1.

## 17. Decompiler and debugger

Both exist now in a first form, ahead of the original order, because they were the most requested pieces.

The decompiler is its own crate. It goes from machine code through an intermediate form and SSA to structured pseudocode, and its check compares the behavior of recompiled output against the original build at several optimization levels. Next up are struct recovery, type propagation across calls, more import signatures, lifting common vector code, and ARM64.

The debugger uses the Windows debug API on one worker thread for programs it launches, and a separate read-only path for attaching to a running process. Attaching loads the main module at its live base with mapped bytes and shows thread registers, stack, memory, modules and live code in the Debugger tab. Next up are hardware breakpoints, applying breakpoints and stepping to an attached process, a real call stack from unwind data, and a Linux backend.
