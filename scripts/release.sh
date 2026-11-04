#!/usr/bin/env bash
# Builds release binaries into dist/ with this computer's folder names removed from them.
set -euo pipefail

root="$(cd "$(dirname "$0")/.." && pwd)"
cd "$root"

native() {
    if command -v cygpath >/dev/null; then cygpath -w "$1"; else printf '%s' "$1"; fi
}

cargo_home="$(native "${CARGO_HOME:-$HOME/.cargo}")"
rustup_home="$(native "${RUSTUP_HOME:-$HOME/.rustup}")"
source_root="$(native "$root")"
user_home="$(native "$HOME")"

# The encoded form keeps a folder name with spaces in one piece. Longest prefixes go last because
# the compiler applies the last match.
separator=$'\x1f'
flags="--remap-path-prefix=$user_home=home"
flags+="$separator--remap-path-prefix=$rustup_home=rustup"
flags+="$separator--remap-path-prefix=$cargo_home=cargo"
flags+="$separator--remap-path-prefix=$source_root=euphoria"
export CARGO_ENCODED_RUSTFLAGS="$flags"

cargo build --release -p euphoria-ui -p euphoria-cli

mkdir -p dist
for name in euphoria eu; do
    for file in "target/release/$name" "target/release/$name.exe"; do
        if [ -f "$file" ]; then
            cp "$file" dist/
        fi
    done
done

# Fails the release if the current user's folder still appears in a binary.
for file in dist/*; do
    if grep -a -q -F "$user_home" "$file"; then
        echo "$file still contains $user_home" >&2
        exit 1
    fi
done
ls -l dist
