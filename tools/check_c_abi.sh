#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
#
# Compiles tests/c/smoke.c against include/seylock.h and the static library,
# links it with the native libraries rustc reports, and runs it. Fails if the
# header and the library disagree.
#
#   tools/check_c_abi.sh
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
cargo build --release --lib --quiet
# No colour: with CARGO_TERM_COLOR=always (as in CI) the note carries escape
# codes that would end up in the linker flags.
native=$(cargo rustc --release --lib --quiet --color never -- --print native-static-libs 2>&1 \
    | sed -n 's/.*native-static-libs: //p' | tail -1)
out=$(mktemp -d)
trap 'rm -rf "$out"' EXIT
# shellcheck disable=SC2086 # $native is a list of linker flags.
${CC:-cc} -std=c11 -Wall -Wextra -Werror -I include tests/c/smoke.c \
    target/release/libseylock.a $native -o "$out/smoke"
"$out/smoke"
