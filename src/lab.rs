// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Extra root certificates for the network lab (`examples/netem_lab.rs`).
//!
//! The lab runs real TLS against its own servers, so it needs to trust its
//! own certificate authority. This module exists only with the `lab-roots`
//! feature, which is off by default. An application must never enable it:
//! a root added here lets its holder impersonate any server.
//!
//! Roots are read when a proxy starts; add them before [`crate::proxy::start`].

use std::sync::Mutex;

use rustls::pki_types::CertificateDer;

static ROOTS: Mutex<Vec<CertificateDer<'static>>> = Mutex::new(Vec::new());

/// Trusts one more root certificate (DER) in proxies started after this call.
pub fn add_root(der: Vec<u8>) {
    ROOTS
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .push(CertificateDer::from(der));
}

pub(crate) fn roots() -> Vec<CertificateDer<'static>> {
    ROOTS.lock().unwrap_or_else(|e| e.into_inner()).clone()
}
