#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
#
# Builds libseylock.so for arm64-v8a, armeabi-v7a and x86_64 with the Android
# NDK and puts them where the Android library module expects them:
# bindings/android/seylock/src/main/jniLibs/<abi>/.
#
#   tools/build_android_libs.sh
#
# The NDK is taken from ANDROID_NDK_HOME, or the newest one under
# $ANDROID_HOME/ndk (default ~/Library/Android/sdk or ~/Android/Sdk).
#
# Google Play requires native libraries aligned to 16 KB pages. Older NDKs
# align to 4 KB by default, so the alignment is set explicitly and checked.
# Paths of the build machine are kept out of the libraries.
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
. tools/release_env.sh

sdk=${ANDROID_HOME:-${ANDROID_SDK_ROOT:-}}
if [ -z "$sdk" ]; then
    for d in "$HOME/Library/Android/sdk" "$HOME/Android/Sdk"; do
        [ -d "$d" ] && sdk=$d && break
    done
fi
ndk=${ANDROID_NDK_HOME:-$(ls -d "$sdk"/ndk/* 2>/dev/null | sort -V | tail -1)}
[ -d "$ndk" ] || { echo "Android NDK not found; set ANDROID_NDK_HOME" >&2; exit 2; }
bin=$(ls -d "$ndk"/toolchains/llvm/prebuilt/*/bin | head -1)
# The NDK's own headers are named in the debug information of C code.
CFLAGS="$CFLAGS -ffile-prefix-map=$ndk=/ndk"
ASMFLAGS="$ASMFLAGS -ffile-prefix-map=$ndk=/ndk"
api=24
jni=bindings/android/seylock/src/main/jniLibs

for pair in aarch64-linux-android:arm64-v8a:aarch64-linux-android \
            armv7-linux-androideabi:armeabi-v7a:armv7a-linux-androideabi \
            x86_64-linux-android:x86_64:x86_64-linux-android; do
    target=${pair%%:*}; rest=${pair#*:}; abi=${rest%%:*}; clang=${rest#*:}
    upper=$(echo "$target" | tr 'a-z-' 'A-Z_')
    lower=$(echo "$target" | tr '-' '_')
    env "CARGO_TARGET_${upper}_LINKER=$bin/${clang}${api}-clang" \
        "CC_${lower}=$bin/${clang}${api}-clang" \
        "AR_${lower}=$bin/llvm-ar" \
        "RUSTFLAGS=$RUSTFLAGS -C link-arg=-Wl,-z,max-page-size=16384" \
        cargo build --release --lib --locked --quiet --target "$target"
    so="target/$target/release/libseylock.so"
    check_no_local_paths "$so"
    # Every loadable segment must be aligned to at least 16 KB (0x4000).
    for align in $("$bin/llvm-readelf" -lW "$so" | awk '$1 == "LOAD" { print $NF }'); do
        if [ $((align)) -lt 16384 ]; then
            echo "error: $so has a LOAD segment aligned to $align, not 16 KB" >&2
            exit 1
        fi
    done
    mkdir -p "$jni/$abi"
    cp "$so" "$jni/$abi/"
    echo "$abi: $(du -h "$jni/$abi/libseylock.so" | cut -f1), 16 KB aligned"
done
