#!/bin/sh
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
#
# Builds SeyLockFFI.xcframework (static libraries for iOS devices, the iOS
# simulator on Apple silicon, and macOS arm64 + x86_64) with the C header and
# a module map, zips it for a Swift Package binary target, and prints the
# checksum SwiftPM needs. Paths of the build machine are kept out of the
# libraries, and the zip is deterministic: the same libraries give the same
# checksum on any machine.
#
#   tools/build_xcframework.sh [output-dir]      # default target/xcframework
set -eu
here=$(cd "$(dirname "$0")/.." && pwd)
cd "$here"
. tools/release_env.sh
out=${1:-target/xcframework}
rm -rf "$out"
# The header and module map sit in a folder named after the module, so they
# never collide with another XCFramework's in an application's build.
mkdir -p "$out/headers/SeyLockFFI" "$out/macos"

build() {
    # Deployment targets are set per platform: a macOS one set while building
    # for iOS breaks host-built proc macros.
    case "$1" in
        *-ios|*-ios-sim) IPHONEOS_DEPLOYMENT_TARGET=13.0 cargo build --release --lib --locked --quiet --target "$1" ;;
        *-darwin) MACOSX_DEPLOYMENT_TARGET=11.0 cargo build --release --lib --locked --quiet --target "$1" ;;
    esac
}
for t in aarch64-apple-ios aarch64-apple-ios-sim aarch64-apple-darwin x86_64-apple-darwin; do
    build "$t"
done

lipo -create \
    target/aarch64-apple-darwin/release/libseylock.a \
    target/x86_64-apple-darwin/release/libseylock.a \
    -output "$out/macos/libseylock.a"

check_no_local_paths target/aarch64-apple-ios/release/libseylock.a \
    target/aarch64-apple-ios-sim/release/libseylock.a "$out/macos/libseylock.a"

cp include/seylock.h "$out/headers/SeyLockFFI/"
cat > "$out/headers/SeyLockFFI/module.modulemap" <<'MAP'
module SeyLockFFI {
    header "seylock.h"
    link "iconv"
    export *
}
MAP

xcodebuild -create-xcframework \
    -library target/aarch64-apple-ios/release/libseylock.a -headers "$out/headers" \
    -library target/aarch64-apple-ios-sim/release/libseylock.a -headers "$out/headers" \
    -library "$out/macos/libseylock.a" -headers "$out/headers" \
    -output "$out/SeyLockFFI.xcframework" >/dev/null

# xcodebuild lists the slices in no fixed order; sort them so Info.plist,
# and with it the zip, is the same on every run.
python3 -I - "$out/SeyLockFFI.xcframework/Info.plist" <<'PY'
import plistlib, sys
path = sys.argv[1]
with open(path, "rb") as f:
    info = plistlib.load(f)
info["AvailableLibraries"].sort(key=lambda lib: lib["LibraryIdentifier"])
with open(path, "wb") as f:
    plistlib.dump(info, f, sort_keys=True)
PY

# Fixed times, permissions and order, and no extra attributes: a rebuilt zip
# of the same libraries has the same checksum.
(
    cd "$out"
    chmod -R u=rwX,go=rX SeyLockFFI.xcframework
    TZ=UTC find SeyLockFFI.xcframework -exec touch -h -t 198001010000 {} +
    find SeyLockFFI.xcframework | LC_ALL=C sort |
        TZ=UTC zip -X -q -@ SeyLockFFI.xcframework.zip
)
echo "built:    $out/SeyLockFFI.xcframework"
echo "zip:      $out/SeyLockFFI.xcframework.zip ($(du -h "$out/SeyLockFFI.xcframework.zip" | cut -f1))"
echo "checksum: $(swift package compute-checksum "$out/SeyLockFFI.xcframework.zip")"
