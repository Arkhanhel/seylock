// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Measures how long the first request takes on a network that blocks some
//! paths, trying paths one at a time (version 0.1) and racing them.
//!
//! ```text
//! cargo run --release --example race_lab -- [runs] [blackhole-ip]
//! ```
//!
//! `runs` defaults to 20 per scenario and mode; `blackhole-ip` defaults to
//! `10.255.255.1`. Every run starts a fresh proxy, so it measures a cold start
//! on a new network, with no memory of what worked before.
//!
//! What is real and what is simulated:
//!
//! - **Silent drop** is real: connections go to private addresses that nothing
//!   answers (`10.255.255.1`, `.2`, ...), so the operating system waits for a
//!   SYN-ACK that never comes, exactly as behind a censor that drops packets.
//!   The lab first checks that these addresses really stay silent here.
//! - **Reset** is real: a closed port on loopback refuses at once.
//! - **The working server** is a small HTTP server on loopback, and the
//!   **working proxy** in scenario C is a SOCKS5 server on loopback that
//!   stands in for a volunteer proxy with an open route.
//! - Everything runs over plain HTTP on loopback, so the times below contain
//!   no TLS handshakes and no network latency. On a real network each
//!   successful path adds one to two round trips; the blocked paths cost the
//!   same timeouts as here.
//!
//! Scenarios:
//!
//! - **A**: `direct` and `ip` silently dropped; a mirror works.
//! - **B**: `direct` and `ip` reset; a CDN name works.
//! - **C**: `direct`, `ip`, the mirror and the CDN name silently dropped; only
//!   the proxy works.
//! - **D**: nothing blocked. Racing must cost nothing here: the table counts
//!   connections the server received per request.

use std::net::{Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use seylock::endpoints::{EndpointList, PathSpec};
use seylock::paths::PathMemory;
use seylock::proxy::{self, HEADER_SERVICE, HEADER_TRANSPORT_TOKEN, Policy, Race};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::task::JoinSet;

/// A minimal HTTP server: answers every request with 200 and counts the
/// connections it accepted.
async fn http_server() -> (u16, Arc<AtomicUsize>) {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let connections = Arc::new(AtomicUsize::new(0));
    let counter = connections.clone();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            counter.fetch_add(1, Ordering::SeqCst);
            tokio::spawn(async move {
                if read_head(&mut stream).await.is_some() {
                    let _ = stream
                        .write_all(
                            b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok",
                        )
                        .await;
                }
            });
        }
    });
    (port, connections)
}

/// A minimal SOCKS5 server (no authentication, CONNECT only) that ignores the
/// requested address and connects to `upstream`: a proxy with an open route.
async fn socks_server(upstream: u16) -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        while let Ok((mut client, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut greeting = [0u8; 2];
                client.read_exact(&mut greeting).await.ok()?;
                let mut methods = vec![0u8; greeting[1] as usize];
                client.read_exact(&mut methods).await.ok()?;
                client.write_all(&[5, 0]).await.ok()?;
                let mut head = [0u8; 4];
                client.read_exact(&mut head).await.ok()?;
                let addr_len = match head[3] {
                    1 => 4,
                    4 => 16,
                    3 => {
                        let mut len = [0u8; 1];
                        client.read_exact(&mut len).await.ok()?;
                        len[0] as usize
                    }
                    _ => return None,
                };
                let mut rest = vec![0u8; addr_len + 2];
                client.read_exact(&mut rest).await.ok()?;
                let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, upstream))
                    .await
                    .ok()?;
                client
                    .write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0])
                    .await
                    .ok()?;
                tokio::io::copy_bidirectional(&mut client, &mut server)
                    .await
                    .ok()
            });
        }
    });
    port
}

async fn read_head(stream: &mut TcpStream) -> Option<Vec<u8>> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = stream.read(&mut chunk).await.ok()?;
        if n == 0 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(buf)
}

/// A loopback port with nothing listening: connecting to it is refused.
async fn closed_port() -> u16 {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    listener.local_addr().unwrap().port()
}

/// Checks that connecting to `ip` neither succeeds nor fails within a second
/// and a half, the way a silently dropping network behaves.
async fn stays_silent(ip: Ipv4Addr) -> bool {
    let attempt = TcpStream::connect(SocketAddr::from((ip, 8080)));
    tokio::time::timeout(Duration::from_millis(1_500), attempt)
        .await
        .is_err()
}

struct Scenario {
    name: &'static str,
    what: &'static str,
    list: EndpointList,
    allow_socks: bool,
    /// Connections counter of the server that should answer.
    served_by: Arc<AtomicUsize>,
}

fn list(api: String, paths: Vec<PathSpec>) -> EndpointList {
    EndpointList {
        v: 2,
        issued_at_ms: 1,
        expires_at_ms: i64::MAX / 2,
        logical: None,
        services: [("api".to_string(), api)].into_iter().collect(),
        paths,
        tor_bridges: Vec::new(),
    }
}

fn targets(base: String) -> std::collections::BTreeMap<String, String> {
    [("api".to_string(), base)].into_iter().collect()
}

/// Sends one request through a fresh proxy and returns how long it took, or
/// `None` if it failed.
async fn one_run(list: EndpointList, allow_socks: bool, race: Race) -> Option<Duration> {
    let proxy = proxy::start(Policy {
        list,
        memory: PathMemory::default(),
        network_id: "lab".into(),
        allow_tor: false,
        allow_socks,
        current: None,
        race,
    })
    .await
    .ok()?;
    let started = Instant::now();
    let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port))
        .await
        .ok()?;
    let request = format!(
        "GET /health HTTP/1.1\r\nHost: lab\r\n{HEADER_TRANSPORT_TOKEN}: {}\r\n{HEADER_SERVICE}: api\r\nConnection: close\r\n\r\n",
        proxy.token
    );
    stream.write_all(request.as_bytes()).await.ok()?;
    let mut response = Vec::new();
    stream.read_to_end(&mut response).await.ok()?;
    let elapsed = started.elapsed();
    response.starts_with(b"HTTP/1.1 200").then_some(elapsed)
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn secs(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().collect();
    let runs: usize = args.get(1).and_then(|s| s.parse().ok()).unwrap_or(20);
    let base: Ipv4Addr = args
        .get(2)
        .and_then(|s| s.parse().ok())
        .unwrap_or(Ipv4Addr::new(10, 255, 255, 1));
    let hole = |n: u8| {
        let o = base.octets();
        Ipv4Addr::new(o[0], o[1], o[2], o[3].wrapping_add(n))
    };

    for n in 0..4 {
        if !stays_silent(hole(n)).await {
            eprintln!(
                "{} answers or refuses at once on this machine, so it cannot stand in for a \
                 silently dropping network. Pass another unused address as the second argument.",
                hole(n)
            );
            std::process::exit(2);
        }
    }

    let (up_a, served_a) = http_server().await;
    let (up_b, served_b) = http_server().await;
    let (up_c, served_c) = http_server().await;
    let (up_d, served_d) = http_server().await;
    let socks = socks_server(up_c).await;
    let closed = closed_port().await;
    let local = |port: u16| format!("http://127.0.0.1:{port}");
    let dropped = |n: u8| format!("http://{}:8080", hole(n));

    let scenarios = vec![
        Scenario {
            name: "A",
            what: "direct and ip silently dropped, mirror works",
            list: list(
                dropped(0),
                vec![
                    PathSpec::Direct,
                    PathSpec::Ip {
                        ip: hole(1).to_string(),
                    },
                    PathSpec::Mirror {
                        keys: None,
                        relay: None,
                        targets: targets(local(up_a)),
                        ip: None,
                    },
                ],
            ),
            allow_socks: false,
            served_by: served_a,
        },
        Scenario {
            name: "B",
            what: "direct and ip reset, CDN name works",
            list: list(
                local(closed),
                vec![
                    PathSpec::Direct,
                    PathSpec::Ip {
                        ip: "127.0.0.1".into(),
                    },
                    PathSpec::Cdn {
                        keys: None,
                        relay: None,
                        targets: targets(local(up_b)),
                    },
                ],
            ),
            allow_socks: false,
            served_by: served_b,
        },
        Scenario {
            name: "C",
            what: "direct, ip, mirror and CDN silently dropped, only the proxy works",
            list: list(
                dropped(0),
                vec![
                    PathSpec::Direct,
                    PathSpec::Ip {
                        ip: hole(1).to_string(),
                    },
                    PathSpec::Mirror {
                        keys: None,
                        relay: None,
                        targets: targets(dropped(2)),
                        ip: None,
                    },
                    PathSpec::Cdn {
                        keys: None,
                        relay: None,
                        targets: targets(dropped(3)),
                    },
                    PathSpec::Socks {
                        addr: format!("127.0.0.1:{socks}"),
                    },
                ],
            ),
            allow_socks: true,
            served_by: served_c,
        },
        Scenario {
            name: "D",
            what: "nothing blocked",
            list: list(
                local(up_d),
                vec![
                    PathSpec::Direct,
                    PathSpec::Ip {
                        ip: "127.0.0.1".into(),
                    },
                    PathSpec::Mirror {
                        keys: None,
                        relay: None,
                        targets: targets(local(up_d)),
                        ip: None,
                    },
                ],
            ),
            allow_socks: false,
            served_by: served_d,
        },
    ];

    println!(
        "seylock {} race lab, {runs} cold runs per row, blackhole {base}+\n",
        seylock::version()
    );
    println!(
        "| Scenario | Mode | OK | Median, s | 95th pct, s | Max, s | Server connections per request |"
    );
    println!("|---|---|---:|---:|---:|---:|---:|");
    for s in &scenarios {
        for (mode, race) in [
            ("one at a time (0.1)", Race::SEQUENTIAL),
            ("racing (default: 250 ms, 3 at once)", Race::default()),
            (
                "racing, 5 at once",
                Race {
                    delay_ms: 250,
                    max_parallel: 5,
                },
            ),
        ] {
            let before = s.served_by.load(Ordering::SeqCst);
            let mut set = JoinSet::new();
            for _ in 0..runs {
                set.spawn(one_run(s.list.clone(), s.allow_socks, race));
            }
            let mut times: Vec<Duration> = Vec::new();
            while let Some(r) = set.join_next().await {
                if let Ok(Some(t)) = r {
                    times.push(t);
                }
            }
            let ok = times.len();
            let per_request = (s.served_by.load(Ordering::SeqCst) - before) as f64 / runs as f64;
            times.sort();
            if times.is_empty() {
                println!("| {} | {mode} | 0/{runs} | – | – | – | – |", s.name);
                continue;
            }
            println!(
                "| {} | {mode} | {ok}/{runs} | {} | {} | {} | {per_request:.2} |",
                s.name,
                secs(percentile(&times, 0.5)),
                secs(percentile(&times, 0.95)),
                secs(*times.last().unwrap()),
            );
        }
    }
    println!();
    for s in &scenarios {
        println!("- {}: {}", s.name, s.what);
    }
}
