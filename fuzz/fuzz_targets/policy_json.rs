// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! The policy JSON that applications pass through the C ABI: arbitrary input
//! must parse or fail, never panic.
#![no_main]

use libfuzzer_sys::fuzz_target;
use seylock::runtime::PolicyInput;

fuzz_target!(|data: &[u8]| {
    let _ = serde_json::from_slice::<PolicyInput>(data);
});
