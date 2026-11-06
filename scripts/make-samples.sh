#!/usr/bin/env bash
# Rebuilds the bundled sample files in samples/.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

cc="${CC:-gcc}"
if ! command -v "$cc" >/dev/null; then
    echo "No C compiler found. Set CC or install gcc." >&2
    exit 1
fi

# -O1 keeps the decoder loop visible while still producing a normal binary.
"$cc" -O1 -fno-inline -o samples/hello.exe samples/src/hello.c
"$cc" -O1 -fno-inline -o samples/encoded.exe samples/src/encoded.c

cargo run -q -p euphoria-cli -- sample --out samples/demo.apk

ls -l samples/*.exe samples/*.apk
