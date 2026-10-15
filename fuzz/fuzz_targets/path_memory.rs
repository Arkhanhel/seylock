// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Saved path memory comes back from the application's storage, which may be
//! damaged: parsing and ordering must never panic, and the order must be a
//! permutation of the allowed paths.
#![no_main]

use libfuzzer_sys::fuzz_target;
use seylock::endpoints::PathSpec;
use seylock::paths::PathMemory;

fuzz_target!(|data: &[u8]| {
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };
    let mut memory = PathMemory::from_json(text);
    let paths = vec![
        PathSpec::Direct,
        PathSpec::Ip {
            ip: "203.0.113.1".into(),
        },
        PathSpec::Tor,
    ];
    let order = memory.order("net", &paths, &|_| true, 1_800_000_000_000);
    let mut sorted = order.clone();
    sorted.sort_unstable();
    assert_eq!(sorted, vec![0, 1, 2], "order is a permutation: {order:?}");
    memory.report("net", 5, true, 1);
    let _ = memory.to_json();
});
