// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! On Apple platforms the linker records the dynamic library's own path
//! (`LC_ID_DYLIB`) as the absolute path it was built at, which puts the build
//! machine's directories, including the user name, into the binary and makes
//! two builds from different directories differ. An `@rpath` install name is
//! the same everywhere and is what an application embedding the library needs
//! anyway. The same goes for the debug map, see below. Static libraries,
//! which the Secretly app links, are not affected.

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    if os == "macos" || os == "ios" {
        let lib = std::env::var("CARGO_PKG_NAME")
            .unwrap_or_default()
            .replace('-', "_");
        println!("cargo:rustc-cdylib-link-arg=-Wl,-install_name,@rpath/lib{lib}.dylib");
        // Keep debug records (stabs pointing at every object file, by
        // absolute path) out of the dynamic library at link time. Cargo's
        // usual way, stripping after the link, produces a library that
        // Xcode 27's dyld refuses to load, so the release profile turns it
        // off and the linker does the job instead.
        println!("cargo:rustc-cdylib-link-arg=-Wl,-S");
    }
}
