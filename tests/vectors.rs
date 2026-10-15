// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Checks the library against `test-vectors/endpoints.json`, whose expected
//! results are written by hand from PROTOCOL.md. `tools/verify_vectors.py`
//! checks the same file with an independent implementation.

use serde_json::Value;
use seylock::endpoints::verify_and_parse;

#[test]
fn every_vector_gives_the_expected_result() {
    let raw = std::fs::read_to_string(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/test-vectors/endpoints.json"
    ))
    .expect("test-vectors/endpoints.json");
    let file: Value = serde_json::from_str(&raw).unwrap();
    let default_key = file["public_key_b64"].as_str().unwrap();
    let vectors = file["vectors"].as_array().unwrap();
    assert!(vectors.len() >= 40, "the file lost vectors");

    let mut failures = Vec::new();
    for v in vectors {
        let name = v["name"].as_str().unwrap();
        let key = v["public_key_b64"].as_str().unwrap_or(default_key);
        let got = match verify_and_parse(
            v["signed"].as_str().unwrap(),
            key,
            v["now_ms"].as_i64().unwrap(),
            v["current_issued_at_ms"].as_i64().unwrap(),
        ) {
            Ok(_) => 0,
            Err(e) => e.code(),
        };
        let expect = v["expect"].as_i64().unwrap() as i32;
        if got != expect {
            failures.push(format!("{name}: expected {expect}, got {got}"));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}
