#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
#
# Builds the library twice, from two copies of the source in different
# directories, and compares the static and dynamic libraries byte for byte.
# A difference means the build depends on where it ran, and nobody could
# check a published binary against the source.
#
#   tools/check_reproducible.sh
#
# Paths are remapped (--remap-path-prefix) so the build directory and the
# Cargo home do not end up in the binaries. The toolchain is whatever
# `cargo` resolves to; both builds use the same one.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo_home=${CARGO_HOME:-$HOME/.cargo}

for copy in one two; do
    mkdir -p "$work/$copy"
    # The copies differ in path only: same files, no build output.
    (cd "$here" && tar --exclude=./target --exclude=./fuzz -cf - .) | (cd "$work/$copy" && tar -xf -)
    (
        cd "$work/$copy"
        RUSTFLAGS="--remap-path-prefix=$work/$copy=/build --remap-path-prefix=$cargo_home=/cargo" \
            CARGO_TARGET_DIR="$work/$copy/target" \
            cargo build --release --locked --lib --quiet
    )
done

status=0
found=0
for lib in libseylock.a libseylock.so libseylock.dylib seylock.dll; do
    a="$work/one/target/release/$lib"
    b="$work/two/target/release/$lib"
    [ -f "$a" ] || continue
    found=$((found + 1))
    if cmp -s "$a" "$b"; then
        echo "same:      $lib  $(shasum -a 256 "$a" | cut -c1-16)"
    else
        echo "DIFFERENT: $lib"
        status=1
    fi
done
[ "$found" -gt 0 ] || { echo "no library was built" >&2; exit 2; }
exit $status
