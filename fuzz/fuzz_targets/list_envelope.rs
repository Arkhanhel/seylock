// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Arbitrary bytes as a signed envelope: must be rejected cleanly, never
//! panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use seylock::endpoints::verify_and_parse;

const KEY: &str = "iojj3XQJ8ZX9UtstPLpdcspnCb8dlBIb83SIAbQPb1w=";

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let _ = verify_and_parse(text, KEY, 1_800_000_000_000, 0);
        let _ = verify_and_parse(text, text, 1_800_000_000_000, 0);
    }
});
