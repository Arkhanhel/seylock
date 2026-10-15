// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Stable-toolchain counterpart of the fuzz targets in `fuzz/`: damaged and
//! extreme inputs must be rejected cleanly, never panic. Tests run with
//! overflow checks on, so arithmetic that could overflow fails here.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey};
use seylock::endpoints::{
    EndpointList, PathSpec, signing_message, signing_message_v2, verify_and_parse,
};
use seylock::paths::PathMemory;
use seylock::runtime::PolicyInput;

const VALID_V1: &str = r#"{"v":1,"issued_at_ms":1000,"expires_at_ms":9000000000000,"logical":{"keys":"https://k.example","relay":"https://r.example"},"paths":[{"kind":"direct"},{"kind":"ip","ip":"203.0.113.1"},{"kind":"mirror","keys":"https://mk","relay":"https://mr"},{"kind":"proxy","host":"p.example","port":443}]}"#;
const VALID_V2: &str = r#"{"v":2,"issued_at_ms":1000,"expires_at_ms":9000000000000,"services":{"api":"https://a.example","media":"https://m.example"},"paths":[{"kind":"direct"},{"kind":"cdn","targets":{"api":"https://c.example"}},{"kind":"socks","addr":"127.0.0.1:9050"}]}"#;

/// Small deterministic generator, so a failure reproduces exactly.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
}

fn mutate(rng: &mut Rng, input: &str) -> String {
    let mut bytes = input.as_bytes().to_vec();
    for _ in 0..1 + rng.below(4) {
        if bytes.is_empty() {
            break;
        }
        let i = rng.below(bytes.len());
        match rng.below(4) {
            0 => {
                const ALPHABET: &[u8] = b"{}[]\":,0-9az\\ ";
                bytes[i] = ALPHABET[rng.below(ALPHABET.len())];
            }
            1 => {
                bytes.remove(i);
            }
            2 => bytes.insert(i, bytes[rng.below(bytes.len())]),
            _ => {
                let j = rng.below(bytes.len());
                bytes.swap(i, j);
            }
        }
    }
    String::from_utf8_lossy(&bytes).into_owned()
}

#[test]
fn mutated_documents_signed_with_the_right_key_never_panic() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let public = B64.encode(key.verifying_key().to_bytes());
    let mut rng = Rng(0x5eed_1234_abcd_ef01);
    let mut accepted = 0;
    for round in 0..4_000 {
        let base = if round % 2 == 0 { VALID_V1 } else { VALID_V2 };
        let doc = mutate(&mut rng, base);
        let message = if rng.below(2) == 0 {
            signing_message(doc.as_bytes())
        } else {
            signing_message_v2(doc.as_bytes())
        };
        let signed = serde_json::json!({
            "doc": doc,
            "sig_b64": B64.encode(key.sign(&message).to_bytes()),
        })
        .to_string();
        if let Ok(list) = verify_and_parse(&signed, &public, 5_000, 0) {
            accepted += 1;
            let back: EndpointList =
                serde_json::from_str(&serde_json::to_string(&list).unwrap()).unwrap();
            assert_eq!(back, list, "an accepted list survives a round trip");
        }
    }
    // Some mutations (inside a URL, say) keep the list valid; if none did,
    // the generator would not be reaching the checks after parsing.
    assert!(accepted > 0);
}

#[test]
fn mutated_envelopes_never_panic() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let public = B64.encode(key.verifying_key().to_bytes());
    let signed = serde_json::json!({
        "doc": VALID_V1,
        "sig_b64": B64.encode(key.sign(&signing_message(VALID_V1.as_bytes())).to_bytes()),
    })
    .to_string();
    let mut rng = Rng(0xfeed_beef_0000_0001);
    for _ in 0..4_000 {
        let _ = verify_and_parse(&mutate(&mut rng, &signed), &public, 5_000, 0);
        let _ = verify_and_parse(&signed, &mutate(&mut rng, &public), 5_000, 0);
    }
}

#[test]
fn extreme_clocks_are_handled() {
    let key = SigningKey::from_bytes(&[1; 32]);
    let public = B64.encode(key.verifying_key().to_bytes());
    let signed = serde_json::json!({
        "doc": VALID_V1,
        "sig_b64": B64.encode(key.sign(&signing_message(VALID_V1.as_bytes())).to_bytes()),
    })
    .to_string();
    for now in [i64::MIN, -1, 0, i64::MAX - 1, i64::MAX] {
        for current in [i64::MIN, 0, i64::MAX] {
            let _ = verify_and_parse(&signed, &public, now, current);
        }
    }
    // A clock far in the future: the list has expired.
    assert_eq!(
        verify_and_parse(&signed, &public, i64::MAX, 0)
            .unwrap_err()
            .code(),
        6
    );
}

#[test]
fn damaged_path_memory_never_panics_and_orders_every_path() {
    let paths = vec![
        PathSpec::Direct,
        PathSpec::Ip {
            ip: "203.0.113.1".into(),
        },
        PathSpec::Tor,
    ];
    let damaged = [
        "",
        "null",
        "[]",
        "{\"networks\":5}",
        r#"{"networks":{"n":{"last_ok":99,"last_ok_at_ms":0,"failed_at_ms":{"0":-9223372036854775808}}}}"#,
        r#"{"networks":{"n":{"last_ok":1,"last_ok_at_ms":9223372036854775807,"failed_at_ms":{"2":9223372036854775807}}}}"#,
    ];
    for raw in damaged {
        let mut memory = PathMemory::from_json(raw);
        for now in [i64::MIN, 0, i64::MAX] {
            let mut order = memory.order("n", &paths, &|_| true, now);
            order.sort_unstable();
            assert_eq!(order, vec![0, 1, 2], "{raw} at {now}");
        }
        memory.report("n", 7, false, i64::MIN);
        memory.report("n", 0, true, i64::MAX);
        let _ = memory.to_json();
    }
}

#[test]
fn mutated_policy_json_never_panics() {
    let policy = format!(
        r#"{{"list":{VALID_V2},"memory":{{"networks":{{}}}},"network_id":"wifi:x","allow_tor":false,"allow_socks":true,"race":{{"delay_ms":250,"max_parallel":3}}}}"#
    );
    assert!(serde_json::from_str::<PolicyInput>(&policy).is_ok());
    let mut rng = Rng(0x0123_4567_89ab_cdef);
    for _ in 0..4_000 {
        let _ = serde_json::from_str::<PolicyInput>(&mutate(&mut rng, &policy));
    }
}
