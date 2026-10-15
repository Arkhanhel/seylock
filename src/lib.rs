// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! SeyLock: reach your own servers from networks that block them.
//!
//! The library gets an application's requests to its servers when direct
//! names or addresses are blocked. It never decrypts application traffic: end-to-end
//! encryption happens above it, in the client, and this crate only carries
//! the bytes (over TLS to the real server names, or through a mirror, CDN,
//! proxy or SOCKS path).
//!
//! Modules:
//! - [`endpoints`]: signed lists of entry points. Covers what a list looks
//!   like, how its signature is verified, and why a list is accepted only
//!   if it is newer than the current one;
//! - [`paths`]: which paths to the servers exist and in what order to try
//!   them on a given network, with a memory of what worked last time;
//! - [`proxy`]: a local reverse proxy on loopback. The client talks plain
//!   HTTP to loopback; the proxy does the outbound TLS and picks the path;
//! - [`runtime`]: a process-wide runtime that owns the running proxy;
//! - [`ffi`]: a C ABI for non-Rust clients such as Dart/Flutter.

#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

pub mod endpoints;
pub mod ffi;
pub mod paths;
pub mod proxy;
pub mod runtime;

// Compiles the Rust examples in README.md as doctests, so the README cannot
// drift from the API.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// Newest version of the endpoint list format; versions 1 and 2 are both
/// accepted. Any incompatible change to the format means a new version and a
/// new signing context.
pub const ENDPOINT_LIST_VERSION: u32 = 2;

/// Returns the crate version.
pub fn version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
