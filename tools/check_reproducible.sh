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
# Both builds use the settings of the release scripts (tools/release_env.sh):
# the pinned toolchain and remapped paths, so neither the build directory nor
# the Cargo home ends up in the binaries. The check also fails if any local
# path is left in them.
set -eu

here=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

for copy in one two; do
    mkdir -p "$work/$copy"
    # The copies differ in path only: same files, no build output.
    (cd "$here" && tar --exclude=./target --exclude=./fuzz -cf - .) | (cd "$work/$copy" && tar -xf -)
    (
        cd "$work/$copy"
        here="$work/$copy"
        . tools/release_env.sh
        CARGO_TARGET_DIR="$work/$copy/target" cargo build --release --locked --lib --quiet
        for lib in target/release/libseylock.a target/release/libseylock.so \
            target/release/libseylock.dylib; do
            if [ -f "$lib" ]; then check_no_local_paths "$lib"; fi
        done
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
