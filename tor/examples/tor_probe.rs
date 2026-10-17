// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Runs one request through SeyLock's proxy over Tor and reports how long it
//! took, for checking Tor on a device without building an application.
//!
//! ```text
//! tor_probe <data-dir> [bridge lines, one per line]
//! ```
//!
//! Bridges are passed as the signed list's `tor_bridges`. A pluggable
//! transport that is already running is given as
//! `SEYLOCK_TOR_TRANSPORT=obfs4=127.0.0.1:PORT` (several separated by `,`).
//!
//! On Android, build with `--features bundled-sqlite` for the device's
//! target, push the binary to `/data/local/tmp` with `adb` and run it from
//! `adb shell`. It writes Tor's files under `<data-dir>` and removes nothing,
//! so a second run shows the warm start.

use std::time::Instant;

use seylock::endpoints::{EndpointList, PathSpec};
use seylock::proxy::{self, HEADER_SERVICE, HEADER_TRANSPORT_PATH, HEADER_TRANSPORT_TOKEN, Policy};
use seylock_tor::{ArtiConnector, TorSettings};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::main]
async fn main() {
    let mut args = std::env::args().skip(1);
    let dir = args
        .next()
        .expect("usage: tor_probe <data-dir> [bridge line]");
    let bridge: Vec<String> = args
        .collect::<Vec<_>>()
        .join(" ")
        .split('\n')
        .filter(|l| !l.trim().is_empty())
        .map(str::to_string)
        .collect();

    let list = {
        let mut list = EndpointList::v2(
            1,
            i64::MAX / 2,
            [("site".to_string(), "https://example.com".to_string())]
                .into_iter()
                .collect(),
            vec![PathSpec::Tor],
        );
        list.tor_bridges = bridge.clone();
        list
    };
    let proxy = proxy::start({
        let mut policy = Policy::new(list);
        policy.network_id = "probe".into();
        policy.allow_tor = true;
        policy
    })
    .await
    .expect("proxy");

    let started = Instant::now();
    let transports = std::env::var("SEYLOCK_TOR_TRANSPORT")
        .unwrap_or_default()
        .split(',')
        .filter_map(|t| t.split_once('='))
        .map(|(proto, addr)| seylock_tor::LocalTransport {
            protocols: vec![proto.trim().to_string()],
            socks_addr: addr.trim().parse().expect("transport address"),
        })
        .collect::<Vec<_>>();
    let settings = TorSettings {
        state_dir: format!("{dir}/state"),
        cache_dir: format!("{dir}/cache"),
        bridges: vec![],
        transports,
    };
    let connector =
        ArtiConnector::start_on(&settings, &tokio::runtime::Handle::current()).expect("tor setup");
    seylock::tor::install(connector);

    // A plain HTTP/1.0 request, so the probe needs nothing beyond tokio.
    let mut s = TcpStream::connect(("127.0.0.1", proxy.port))
        .await
        .expect("proxy port");
    let req = format!(
        "GET / HTTP/1.0\r\nHost: probe\r\n{HEADER_TRANSPORT_TOKEN}: {}\r\n{HEADER_SERVICE}: site\r\n\r\n",
        proxy.token
    );
    s.write_all(req.as_bytes()).await.unwrap();
    let mut buf = Vec::new();
    let _ = s.read_to_end(&mut buf).await;
    let text = String::from_utf8_lossy(&buf);
    let status = text.lines().next().unwrap_or("(no response)");
    let path = text
        .lines()
        .find(|l| {
            l.to_ascii_lowercase()
                .starts_with(&format!("{HEADER_TRANSPORT_PATH}:"))
        })
        .unwrap_or("(no path header)");
    println!(
        "{status} | {path} | {} ms from Tor start | bridges from list: {} | tor state {:?}",
        started.elapsed().as_millis(),
        bridge.len(),
        seylock::tor::state()
    );
}
