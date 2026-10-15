// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Arbitrary bytes as a list document, validly signed under both contexts, so
//! the fuzzer reaches the document and shape checks instead of stopping at the
//! signature. An accepted list must also survive a JSON round trip.
#![no_main]

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use libfuzzer_sys::fuzz_target;
use seylock::endpoints::{signing_message, signing_message_v2, verify_and_parse};

fuzz_target!(|data: &[u8]| {
    let Ok(doc) = std::str::from_utf8(data) else {
        return;
    };
    let key = SigningKey::from_bytes(&[1; 32]);
    let public = B64.encode(key.verifying_key().to_bytes());
    for message in [
        signing_message(doc.as_bytes()),
        signing_message_v2(doc.as_bytes()),
    ] {
        let signed = serde_json::json!({
            "doc": doc,
            "sig_b64": B64.encode(key.sign(&message).to_bytes()),
        })
        .to_string();
        if let Ok(list) = verify_and_parse(&signed, &public, 1_800_000_000_000, 0) {
            let json = serde_json::to_string(&list).expect("an accepted list serialises");
            let back: seylock::endpoints::EndpointList =
                serde_json::from_str(&json).expect("and parses back");
            assert_eq!(back, list);
        }
    }
});
