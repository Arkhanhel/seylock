// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Live check against the real Tor network: SeyLock's proxy, a list whose
//! only path is `tor`, and a request to a public HTTPS site. TLS to the site
//! runs inside the Tor stream, so the exit relay sees neither request nor
//! response.
//!
//! Ignored by default, because it needs the network and takes 10 to 60
//! seconds on a cold start:
//!
//! ```text
//! cargo test --test live_tor -- --ignored --nocapture
//! ```
//!
//! Tor's files go to `target/live-tor` (kept between runs, so later runs
//! reuse the directory cache), or to `SEYLOCK_TOR_TEST_DIR`.
//!
//! The bridge test takes its bridge line from `SEYLOCK_TOR_BRIDGE` and is
//! skipped without it. A plain bridge (`address fingerprint`, for example a
//! public guard relay) needs no pluggable transport. The two tests share
//! process-wide state; run them one at a time, by name.

use std::time::Instant;

use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use hyper_util::rt::TokioIo;
use seylock::endpoints::{EndpointList, PathSpec};
use seylock::paths::PathMemory;
use seylock::proxy::{
    self, HEADER_SERVICE, HEADER_TRANSPORT_PATH, HEADER_TRANSPORT_TOKEN, Policy, Race,
};
use seylock_tor::{ArtiConnector, TorSettings};
use tokio::net::TcpStream;

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_request_goes_through_a_bridge_from_the_signed_list() {
    let Ok(bridge) = std::env::var("SEYLOCK_TOR_BRIDGE") else {
        eprintln!("skipped: set SEYLOCK_TOR_BRIDGE");
        return;
    };
    // A fresh state directory: no guards remembered from direct runs.
    let dir = concat!(env!("CARGO_MANIFEST_DIR"), "/target/live-tor-bridge");
    let _ = std::fs::remove_dir_all(format!("{dir}/state"));
    let settings = TorSettings {
        state_dir: format!("{dir}/state"),
        cache_dir: format!("{dir}/cache"),
        bridges: vec![],
        transports: vec![],
    };
    // The bridge comes from the list, as an operator would distribute it;
    // the application's own settings have none.
    let mut list = site_list();
    list.tor_bridges = vec![bridge];
    let proxy = proxy::start(policy(list)).await.expect("proxy");
    let started = Instant::now();
    let connector =
        ArtiConnector::start_on(&settings, &tokio::runtime::Handle::current()).expect("tor setup");
    seylock::tor::install(connector);
    let (status, via, len) = fetch(&proxy).await;
    println!(
        "bridge: status {status}, path {via:?}, {len} bytes, {} ms from Tor start, tor state {:?}",
        started.elapsed().as_millis(),
        seylock::tor::state()
    );
    assert!(status.is_success() || status.is_redirection(), "{status}");
    assert_eq!(via.as_deref(), Some("tor"));
    seylock::tor::uninstall();
}

fn site_list() -> EndpointList {
    EndpointList {
        v: 2,
        issued_at_ms: 1,
        expires_at_ms: i64::MAX / 2,
        logical: None,
        services: [("site".to_string(), "https://example.com".to_string())]
            .into_iter()
            .collect(),
        paths: vec![PathSpec::Tor],
        tor_bridges: Vec::new(),
    }
}

fn policy(list: EndpointList) -> Policy {
    Policy {
        list,
        memory: PathMemory::default(),
        network_id: "live".into(),
        allow_tor: true,
        allow_socks: false,
        current: None,
        race: Race::default(),
    }
}

async fn fetch(proxy: &proxy::ProxyHandle) -> (http::StatusCode, Option<String>, usize) {
    let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/")
        .header(http::header::HOST, "127.0.0.1")
        .header(HEADER_TRANSPORT_TOKEN, &proxy.token)
        .header(HEADER_SERVICE, "site")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.expect("response");
    let status = res.status();
    let via = res
        .headers()
        .get(HEADER_TRANSPORT_PATH)
        .map(|v| v.to_str().unwrap().to_string());
    let body = res.into_body().collect().await.unwrap().to_bytes();
    (status, via, body.len())
}

#[tokio::test(flavor = "multi_thread")]
#[ignore]
async fn a_request_goes_through_tor() {
    let dir = std::env::var("SEYLOCK_TOR_TEST_DIR")
        .unwrap_or_else(|_| concat!(env!("CARGO_MANIFEST_DIR"), "/target/live-tor").to_string());
    let settings = TorSettings {
        state_dir: format!("{dir}/state"),
        cache_dir: format!("{dir}/cache"),
        bridges: vec![],
        transports: vec![],
    };
    let started = Instant::now();
    let connector =
        ArtiConnector::start_on(&settings, &tokio::runtime::Handle::current()).expect("tor setup");
    seylock::tor::install(connector);

    let proxy = proxy::start(Policy {
        list: EndpointList {
            v: 2,
            issued_at_ms: 1,
            expires_at_ms: i64::MAX / 2,
            logical: None,
            services: [("site".to_string(), "https://example.com".to_string())]
                .into_iter()
                .collect(),
            paths: vec![PathSpec::Tor],
            tor_bridges: Vec::new(),
        },
        memory: PathMemory::default(),
        network_id: "live".into(),
        allow_tor: true,
        allow_socks: false,
        current: None,
        race: Race::default(),
    })
    .await
    .expect("proxy");

    let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
    let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(conn);
    let req = Request::builder()
        .uri("/")
        .header(http::header::HOST, "127.0.0.1")
        .header(HEADER_TRANSPORT_TOKEN, &proxy.token)
        .header(HEADER_SERVICE, "site")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let res = sender.send_request(req).await.expect("response");
    let status = res.status();
    let via = res
        .headers()
        .get(HEADER_TRANSPORT_PATH)
        .map(|v| v.to_str().unwrap().to_string());
    let body = res.into_body().collect().await.unwrap().to_bytes();
    println!(
        "status {status}, path {via:?}, {} bytes, {} ms from Tor start, tor state {:?}",
        body.len(),
        started.elapsed().as_millis(),
        seylock::tor::state()
    );
    assert!(status.is_success() || status.is_redirection(), "{status}");
    assert_eq!(via.as_deref(), Some("tor"));
    assert_eq!(seylock::tor::state(), Some(seylock::tor::TorState::Ready));
    seylock::tor::uninstall();
}
