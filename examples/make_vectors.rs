// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Writes the endpoint list test vectors to `test-vectors/endpoints.json`.
//!
//! ```text
//! cargo run --example make_vectors
//! ```
//!
//! Every expected result below is written by hand from PROTOCOL.md; none is
//! computed by the library under test. `tests/vectors.rs` then checks the
//! library against the file, and `tools/verify_vectors.py`, a second
//! implementation written from PROTOCOL.md alone, checks it too.
//!
//! Ed25519 signatures are deterministic, so running this again produces the
//! same file byte for byte.

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use ed25519_dalek::{Signer as _, SigningKey, VerifyingKey};
use serde_json::{Value, json};
use seylock::endpoints::{signing_message, signing_message_v2};

const NOW: i64 = 1_800_000_000_000;
const DAY: i64 = 24 * 60 * 60 * 1000;
const WEEK: i64 = 7 * DAY;
const ISSUED: i64 = NOW - 60_000;
const EXPIRES: i64 = NOW + 30 * DAY;

fn key(seed: u8) -> SigningKey {
    SigningKey::from_bytes(&[seed; 32])
}

fn envelope(doc: &str, sig: &[u8]) -> String {
    json!({ "doc": doc, "sig_b64": B64.encode(sig) }).to_string()
}

fn sign_v1(k: &SigningKey, doc: &str) -> String {
    envelope(doc, &k.sign(&signing_message(doc.as_bytes())).to_bytes())
}

fn sign_v2(k: &SigningKey, doc: &str) -> String {
    envelope(doc, &k.sign(&signing_message_v2(doc.as_bytes())).to_bytes())
}

fn v1(issued: i64, expires: i64) -> Value {
    json!({
        "v": 1,
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "logical": { "keys": "https://keys.example.org", "relay": "https://relay.example.org" },
        "paths": [
            { "kind": "direct" },
            { "kind": "ip", "ip": "203.0.113.10" },
            { "kind": "mirror", "keys": "https://k.mirror.example.net", "relay": "https://r.mirror.example.net" },
            { "kind": "cdn", "keys": "https://keys.cdn.example.com", "relay": "https://relay.cdn.example.com" },
            { "kind": "proxy", "host": "volunteer.example.org" },
            { "kind": "socks", "addr": "127.0.0.1:9050" },
            { "kind": "tor" }
        ]
    })
}

fn v2(issued: i64, expires: i64) -> Value {
    json!({
        "v": 2,
        "issued_at_ms": issued,
        "expires_at_ms": expires,
        "services": { "api": "https://api.example.org", "media": "https://media.example.org" },
        "paths": [
            { "kind": "direct" },
            { "kind": "mirror", "targets": { "api": "https://a.mirror.example.net", "media": "https://m.mirror.example.net" } },
            { "kind": "cdn", "targets": { "api": "https://api.cdn.example.com" } },
            { "kind": "proxy", "host": "volunteer.example.org", "port": 8443 }
        ]
    })
}

fn with(mut doc: Value, path: &[&str], value: Value) -> Value {
    let mut cur = &mut doc;
    for p in &path[..path.len() - 1] {
        cur = match p.parse::<usize>() {
            Ok(i) => &mut cur[i],
            Err(_) => &mut cur[*p],
        };
    }
    let last = path[path.len() - 1];
    match last.parse::<usize>() {
        Ok(i) => cur[i] = value,
        Err(_) => {
            if value.is_null() {
                cur.as_object_mut().unwrap().remove(last);
            } else {
                cur[last] = value;
            }
        }
    }
    doc
}

/// 32 bytes that do not decode to a curve point.
fn not_a_point() -> [u8; 32] {
    (0u8..=255)
        .map(|b| {
            let mut bytes = [0u8; 32];
            bytes[0] = b;
            bytes[1] = 1;
            bytes
        })
        .find(|bytes| VerifyingKey::from_bytes(bytes).is_err())
        .expect("some y has no x")
}

struct Case {
    name: &'static str,
    signed: String,
    now_ms: i64,
    current_issued_at_ms: i64,
    expect: i32,
    public_key_b64: Option<String>,
}

fn case(name: &'static str, signed: String, expect: i32) -> Case {
    Case {
        name,
        signed,
        now_ms: NOW,
        current_issued_at_ms: 0,
        expect,
        public_key_b64: None,
    }
}

fn main() {
    let k = key(1);
    let other = key(2);
    let pk = B64.encode(k.verifying_key().to_bytes());
    let d1 = v1(ISSUED, EXPIRES).to_string();
    let d2 = v2(ISSUED, EXPIRES).to_string();
    let s1 = |doc: Value| sign_v1(&k, &doc.to_string());
    let s2 = |doc: Value| sign_v2(&k, &doc.to_string());
    let names17: serde_json::Map<String, Value> = (0..17)
        .map(|i| (format!("s{i}"), json!("https://s.example.org")))
        .collect();
    let names16: serde_json::Map<String, Value> = (0..16)
        .map(|i| (format!("s{i}"), json!("https://s.example.org")))
        .collect();

    let cases = vec![
        // Accepted.
        case("v1 accepted", sign_v1(&k, &d1), 0),
        case("v2 accepted", sign_v2(&k, &d2), 0),
        case(
            "v2 with 16 services accepted",
            s2(with(
                with(v2(ISSUED, EXPIRES), &["services"], json!(names16)),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            0,
        ),
        case(
            "v2 accepted with a 32-byte service name",
            s2(with(
                with(
                    v2(ISSUED, EXPIRES),
                    &["services"],
                    json!({ "a2345678901234567890123456789012": "https://a" }),
                ),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            0,
        ),
        case(
            "unknown fields are ignored",
            s1(with(v1(ISSUED, EXPIRES), &["comment"], json!("anything"))),
            0,
        ),
        case(
            "issued exactly seven days ahead is accepted",
            s1(v1(NOW + WEEK, NOW + 2 * WEEK)),
            0,
        ),
        // 1: envelope.
        case("envelope is not JSON", "not json".into(), 1),
        case(
            "envelope without sig_b64",
            json!({ "doc": d1 }).to_string(),
            1,
        ),
        case(
            "doc is not a string",
            json!({ "doc": v1(ISSUED, EXPIRES), "sig_b64": "AAAA" }).to_string(),
            1,
        ),
        // 2: key and signature format.
        case(
            "signature is not base64",
            json!({ "doc": d1, "sig_b64": "!!!!" }).to_string(),
            2,
        ),
        case(
            "signature is 63 bytes",
            envelope(
                &d1,
                &k.sign(&signing_message(d1.as_bytes())).to_bytes()[..63],
            ),
            2,
        ),
        Case {
            public_key_b64: Some(B64.encode([7u8; 31])),
            ..case("key is 31 bytes", sign_v1(&k, &d1), 2)
        },
        Case {
            public_key_b64: Some(B64.encode(not_a_point())),
            ..case("key is not a curve point", sign_v1(&k, &d1), 2)
        },
        // 3: signature.
        case(
            "document changed after signing",
            sign_v1(&k, &d1).replace("203.0.113.10", "198.51.100.10"),
            3,
        ),
        case("signed by another key", sign_v1(&other, &d1), 3),
        case(
            "signed without the context",
            envelope(&d1, &k.sign(d1.as_bytes()).to_bytes()),
            3,
        ),
        case("v1 document under the v2 context", sign_v2(&k, &d1), 3),
        case("v2 document under the v1 context", sign_v1(&k, &d2), 3),
        // 4: document.
        case("signed document is not JSON", sign_v1(&k, "not json"), 4),
        case(
            "document without paths",
            s1(with(v1(ISSUED, EXPIRES), &["paths"], Value::Null)),
            4,
        ),
        case(
            "unknown path kind",
            s1(with(
                v1(ISSUED, EXPIRES),
                &["paths", "0"],
                json!({ "kind": "carrier-pigeon" }),
            )),
            4,
        ),
        case(
            "proxy port out of range",
            s1(with(
                v1(ISSUED, EXPIRES),
                &["paths", "4", "port"],
                json!(70000),
            )),
            4,
        ),
        case(
            "v1 mirror without relay",
            s1(with(
                v1(ISSUED, EXPIRES),
                &["paths", "2", "relay"],
                Value::Null,
            )),
            4,
        ),
        case(
            "v1 list with services",
            s1(with(
                v1(ISSUED, EXPIRES),
                &["services"],
                json!({ "api": "https://a" }),
            )),
            4,
        ),
        case(
            "v2 list with logical",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["logical"],
                json!({ "keys": "https://k", "relay": "https://r" }),
            )),
            4,
        ),
        case(
            "v2 mirror with keys and relay",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["paths", "1"],
                json!({ "kind": "mirror", "keys": "https://k", "relay": "https://r" }),
            )),
            4,
        ),
        case(
            "v2 cdn without targets",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["paths", "2"],
                json!({ "kind": "cdn" }),
            )),
            4,
        ),
        // 5: version.
        case(
            "version 3",
            s1(with(v1(ISSUED, EXPIRES), &["v"], json!(3))),
            5,
        ),
        case(
            "version 0",
            s1(with(v1(ISSUED, EXPIRES), &["v"], json!(0))),
            5,
        ),
        // 6: time.
        case("expires exactly now", s1(v1(ISSUED, NOW)), 6),
        case("already expired", s1(v1(NOW - 2 * DAY, NOW - DAY)), 6),
        case(
            "issued more than seven days ahead",
            s1(v1(NOW + WEEK + 1, NOW + 2 * WEEK)),
            6,
        ),
        // 7: freshness.
        Case {
            current_issued_at_ms: ISSUED,
            ..case("same issued_at as the current list", sign_v1(&k, &d1), 7)
        },
        Case {
            current_issued_at_ms: ISSUED + 1,
            ..case("older than the current list", sign_v1(&k, &d1), 7)
        },
        Case {
            current_issued_at_ms: ISSUED - 1,
            ..case("one millisecond newer is accepted", sign_v1(&k, &d1), 0)
        },
        // 8: empty.
        case(
            "no paths",
            s1(with(v1(ISSUED, EXPIRES), &["paths"], json!([]))),
            8,
        ),
        case(
            "v1 empty relay base",
            s1(with(v1(ISSUED, EXPIRES), &["logical", "relay"], json!(""))),
            8,
        ),
        case(
            "v1 without logical",
            s1(with(v1(ISSUED, EXPIRES), &["logical"], Value::Null)),
            8,
        ),
        case(
            "v2 without services",
            s2(with(
                with(v2(ISSUED, EXPIRES), &["services"], Value::Null),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            8,
        ),
        case(
            "v2 empty service base",
            s2(with(v2(ISSUED, EXPIRES), &["services", "media"], json!(""))),
            8,
        ),
        // 9: service names.
        case(
            "uppercase service name",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["services"],
                json!({ "Api": "https://a" }),
            )),
            9,
        ),
        case(
            "service name starting with a dash",
            s2(with(
                with(
                    v2(ISSUED, EXPIRES),
                    &["services"],
                    json!({ "-api": "https://a" }),
                ),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            9,
        ),
        case(
            "service name with an underscore",
            s2(with(
                with(
                    v2(ISSUED, EXPIRES),
                    &["services"],
                    json!({ "api_v2": "https://a" }),
                ),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            9,
        ),
        case(
            "33-byte service name",
            s2(with(
                with(
                    v2(ISSUED, EXPIRES),
                    &["services"],
                    json!({ "a23456789012345678901234567890123": "https://a" }),
                ),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            9,
        ),
        case(
            "17 services",
            s2(with(
                with(v2(ISSUED, EXPIRES), &["services"], json!(names17)),
                &["paths"],
                json!([{ "kind": "direct" }]),
            )),
            9,
        ),
        // 10: unknown service.
        case(
            "mirror target for an unknown service",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["paths", "1", "targets", "video"],
                json!("https://v.mirror.example.net"),
            )),
            10,
        ),
        // 11: Tor bridges.
        case(
            "v2 with Tor bridge lines accepted",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["tor_bridges"],
                json!([
                    "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0",
                    "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/path"
                ]),
            )),
            0,
        ),
        case(
            "33 Tor bridge lines",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["tor_bridges"],
                json!(vec![
                    "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
                    33
                ]),
            )),
            11,
        ),
        case(
            "empty Tor bridge line",
            s2(with(v2(ISSUED, EXPIRES), &["tor_bridges"], json!([""]))),
            11,
        ),
        case(
            "Tor bridge line with a newline",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["tor_bridges"],
                json!(["obfs4 a\nb"]),
            )),
            11,
        ),
        case(
            "Tor bridge line with non-ASCII",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["tor_bridges"],
                json!(["obfs4 caf\u{e9}"]),
            )),
            11,
        ),
        case(
            "Tor bridge line longer than 2048 bytes",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["tor_bridges"],
                json!(["x".repeat(2049)]),
            )),
            11,
        ),
        case(
            "v1 list with Tor bridges",
            s1(with(
                v1(ISSUED, EXPIRES),
                &["tor_bridges"],
                json!(["obfs4 x"]),
            )),
            4,
        ),
        case(
            "Tor bridges not a list of strings",
            s2(with(v2(ISSUED, EXPIRES), &["tor_bridges"], json!([1, 2]))),
            4,
        ),
        case(
            "empty target URL",
            s2(with(
                v2(ISSUED, EXPIRES),
                &["paths", "2", "targets", "api"],
                json!(""),
            )),
            10,
        ),
    ];
    // The service-name cases rely on these lengths; check the arithmetic
    // rather than trust the literals.
    assert_eq!("a2345678901234567890123456789012".len(), 32);
    assert_eq!("a23456789012345678901234567890123".len(), 33);

    let vectors: Vec<Value> = cases
        .iter()
        .map(|c| {
            let mut v = json!({
                "name": c.name,
                "signed": c.signed,
                "now_ms": c.now_ms,
                "current_issued_at_ms": c.current_issued_at_ms,
                "expect": c.expect,
            });
            if let Some(key) = &c.public_key_b64 {
                v["public_key_b64"] = json!(key);
            }
            v
        })
        .collect();
    let file = json!({
        "about": "Test vectors for signed endpoint lists, formats 1 and 2. \
                  `expect` is 0 for an accepted list, otherwise the rejection \
                  code from PROTOCOL.md. A vector's own `public_key_b64`, \
                  when present, replaces the file's.",
        "public_key_b64": pk,
        "vectors": vectors,
    });
    let out = serde_json::to_string_pretty(&file).unwrap() + "\n";
    std::fs::create_dir_all("test-vectors").unwrap();
    std::fs::write("test-vectors/endpoints.json", out).unwrap();
    println!("test-vectors/endpoints.json: {} vectors", cases.len());
}
