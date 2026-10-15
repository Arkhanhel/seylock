// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Live checks against a real server: TLS, the root store, SNI, the `ip` path.
//!
//! They need a server you run, given by environment variables, and are
//! ignored by default:
//!
//! ```text
//! LIVE_KEYS_URL=https://keys.example.org \
//! LIVE_RELAY_URL=https://relay.example.org \
//! LIVE_SERVER_IP=203.0.113.10 \
//! cargo test --test live_direct -- --ignored
//! ```
//!
//! Each service must answer `GET /health` with 200. `LIVE_SERVER_IP` is the
//! address of the keys service, used to check that the `ip` path keeps the
//! real name for SNI. A test whose variables are missing says so and passes.

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use seylock::endpoints::{EndpointList, Logical, PathSpec};
use seylock::paths::PathMemory;
use seylock::proxy::{self, HEADER_PATH, HEADER_TOKEN, HEADER_UPSTREAM, Policy, Race};
use tokio::net::TcpStream;

fn env(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|v| !v.is_empty())
}

/// Whether the variables a test needs are set; prints which are missing.
fn configured(names: &[&str]) -> bool {
    let missing: Vec<&str> = names.iter().copied().filter(|n| env(n).is_none()).collect();
    if !missing.is_empty() {
        eprintln!("skipped: set {}", missing.join(", "));
    }
    missing.is_empty()
}

async fn health_via(policy: Policy, upstream: &str) -> (http::StatusCode, String, String) {
    let proxy = proxy::start(policy).await.unwrap();
    let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/health")
        .header(http::header::HOST, "127.0.0.1")
        .header(HEADER_TOKEN, &proxy.token)
        .header(HEADER_UPSTREAM, upstream)
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.unwrap();
    let status = res.status();
    let via = res
        .headers()
        .get(HEADER_PATH)
        .map(|v| v.to_str().unwrap().to_string())
        .unwrap_or_default();
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, via, String::from_utf8_lossy(&body).to_string())
}

fn policy(paths: Vec<PathSpec>) -> Policy {
    Policy {
        list: EndpointList {
            v: 1,
            issued_at_ms: 1,
            expires_at_ms: i64::MAX / 2,
            logical: Some(Logical {
                keys: env("LIVE_KEYS_URL").unwrap_or_default(),
                relay: env("LIVE_RELAY_URL").unwrap_or_default(),
            }),
            services: Default::default(),
            paths,
            tor_bridges: Vec::new(),
        },
        memory: PathMemory::default(),
        network_id: "live".into(),
        allow_tor: false,
        allow_socks: false,
        current: None,
        race: Race::default(),
    }
}

#[tokio::test]
#[ignore]
async fn live_keys_and_relay_health_direct() {
    if !configured(&["LIVE_KEYS_URL", "LIVE_RELAY_URL"]) {
        return;
    }
    let (status, via, body) = health_via(policy(vec![PathSpec::Direct]), "keys").await;
    assert_eq!(status, http::StatusCode::OK, "{body}");
    assert_eq!(via, "direct");
    assert!(body.contains("ok") || body.contains("protocol"), "{body}");
    let (status, via, _) = health_via(policy(vec![PathSpec::Direct]), "relay").await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(via, "direct");
}

#[tokio::test]
#[ignore]
async fn live_ip_path_keeps_sni_on_the_real_name() {
    if !configured(&["LIVE_KEYS_URL", "LIVE_RELAY_URL", "LIVE_SERVER_IP"]) {
        return;
    }
    let (status, via, _) = health_via(
        policy(vec![PathSpec::Ip {
            ip: env("LIVE_SERVER_IP").unwrap_or_default(),
        }]),
        "keys",
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(via, "ip");
}

#[tokio::test]
#[ignore]
async fn live_dead_first_path_falls_over_to_direct() {
    if !configured(&["LIVE_KEYS_URL", "LIVE_RELAY_URL"]) {
        return;
    }
    // 192.0.2.1 is a documentation address (RFC 5737): nothing answers there.
    let (status, via, _) = health_via(
        policy(vec![
            PathSpec::Ip {
                ip: "192.0.2.1".into(),
            },
            PathSpec::Direct,
        ]),
        "relay",
    )
    .await;
    assert_eq!(status, http::StatusCode::OK);
    assert_eq!(via, "direct");
}
