# Sample files

These files exist so the welcome tour and the documentation have something safe to open.

| File | What it demonstrates |
| --- | --- |
| `hello.exe` | A plain 64-bit program: named routines, strings, imports, and a simple loop. Try the listing, graph, decompiler, and debugger. |
| `encoded.exe` | A single-byte XOR decoder loop. The message and URL are stored encoded in `.rdata`; `Advanced -> XOR` recovers both. Decompile `decode` to see the loop. |
| `demo.apk` | A synthetic APK with an `AndroidManifest.xml`, one `classes.dex`, a flagged `libjiagu.so`, and a v1 signature entry. |

`hello.exe` and `encoded.exe` only print text and exit. `demo.apk` is not installable and is not signed
with a real key; it exists to exercise the analyzer.

## Rebuilding

```bash
scripts/make-samples.sh
```

The script needs `gcc` (or `${CC}`) and the workspace toolchain. It rebuilds the two native programs
and writes `demo.apk` through `eu sample`.

The application looks for samples in `$EUPHORIA_SAMPLES`, then `samples/` next to the executable,
then `samples/` in the current directory. Release archives include a `samples/` folder next to
`euphoria.exe`.
