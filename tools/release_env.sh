# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
#
# Sourced by the release build scripts (build_xcframework.sh,
# build_android_libs.sh) with $here set to the crate root.
#
# Rust writes source paths into binaries for panic messages. Remapping them
# keeps the paths of the build machine (the user name, the folder layout) out
# of published libraries, and makes builds on different machines comparable.

# The Rust version releases are built with. Another version gives other
# bytes, so a published library can be checked only against this one. It is
# set here, not by a rust-toolchain.toml, so CI still tests stable and the
# minimum supported version.
RUSTUP_TOOLCHAIN=${RUSTUP_TOOLCHAIN:-1.93.1}
export RUSTUP_TOOLCHAIN

cargo_home=${CARGO_HOME:-$HOME/.cargo}
rustup_home=${RUSTUP_HOME:-$HOME/.rustup}
RUSTFLAGS="${RUSTFLAGS:+$RUSTFLAGS }--remap-path-prefix=$here=/seylock --remap-path-prefix=$cargo_home=/cargo --remap-path-prefix=$rustup_home=/rustup"
export RUSTFLAGS
# The same for C and assembly compiled by dependencies (ring), which rustc's
# remapping does not reach.
prefix_maps="-ffile-prefix-map=$here=/seylock -ffile-prefix-map=$cargo_home=/cargo"
CFLAGS="${CFLAGS:+$CFLAGS }$prefix_maps"
ASMFLAGS="${ASMFLAGS:+$ASMFLAGS }$prefix_maps"
export CFLAGS ASMFLAGS

# Fails if any of the given files still contains a path of this machine.
check_no_local_paths() {
    for file in "$@"; do
        for path in "$here" "$cargo_home" "$rustup_home" "$HOME"; do
            if strings -a "$file" | grep -qF "$path"; then
                echo "error: $file contains the local path $path" >&2
                exit 1
            fi
        done
    done
}
