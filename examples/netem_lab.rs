// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! The network lab: the first request on a new network, over real TCP and
//! real TLS, with blocking done by `iptables` and latency and loss by
//! `tc netem`. Linux only, driven by `tools/netem_lab.sh`, which builds the
//! network and runs both halves:
//!
//! ```text
//! netem_lab serve <dir>                    # in the server namespace
//! netem_lab header                         # prints the table header
//! netem_lab run <dir> <scenario> <runs> <runs-one-at-a-time> <settle-ms>
//! ```
//!
//! `serve` creates a certificate authority, writes it to `<dir>/ca.der` and
//! answers HTTPS on every lab address. One address is a volunteer proxy: it
//! ends the outer TLS and passes the inner TLS on to the server, as
//! `server/proxy/tlsproxy` does. The server counts the TCP connections it
//! accepts on each address and reports them over `<dir>/stats.sock`.
//!
//! `run` trusts that authority (the `lab-roots` feature, never enabled in an
//! application), then starts a fresh proxy for every request: a cold start on
//! a new network, with no memory of earlier ones. After each request it waits
//! `settle-ms` for late connections and reads the server's counters, so the
//! table shows what racing costs the server, not only what it saves the user.
//!
//! The endpoint list is the same in every scenario, as an operator would
//! publish it: `direct`, `ip`, `mirror`, `cdn`, then `proxy`.

use std::collections::BTreeMap;
use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use seylock::endpoints::{EndpointList, PathSpec};
use seylock::proxy::{self, HEADER_SERVICE, HEADER_TRANSPORT_TOKEN, Policy, Race};
use tokio::io::{AsyncBufReadExt, AsyncReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream, UnixListener, UnixStream};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};

/// The lab addresses, as `tools/netem_lab.sh` assigns them in the server
/// namespace, and what each one stands for.
const ADDRESSES: [(Ipv4Addr, &str); 5] = [
    (Ipv4Addr::new(10, 77, 0, 10), "direct"),
    (Ipv4Addr::new(10, 77, 0, 11), "ip"),
    (Ipv4Addr::new(10, 77, 0, 12), "mirror"),
    (Ipv4Addr::new(10, 77, 0, 13), "cdn"),
    (Ipv4Addr::new(10, 77, 0, 14), "proxy"),
];
const PROXY_ADDRESS: Ipv4Addr = Ipv4Addr::new(10, 77, 0, 14);
const NAMES: [&str; 4] = [
    "api.lab.test",
    "mirror.lab.test",
    "cdn.lab.test",
    "proxy.lab.test",
];
/// Longest a single request may take before the run counts as failed.
const REQUEST_LIMIT: Duration = Duration::from_secs(90);
/// Longest the server waits for a client that went quiet.
const SERVER_IDLE: Duration = Duration::from_secs(30);

const SCENARIOS: [(&str, &str); 5] = [
    ("A", "`direct` and `ip` silently dropped; RTT 100 ms"),
    (
        "B",
        "connections reset on the SNI of `api` and `mirror`; RTT 100 ms",
    ),
    (
        "C",
        "everything but the volunteer proxy silently dropped; RTT 100 ms",
    ),
    (
        "D",
        "nothing blocked, slow network: RTT 800 ms, 5 % loss each way",
    ),
    ("E", "nothing blocked, ordinary network: RTT 100 ms"),
];

// ---------------------------------------------------------------- server

type Counts = Arc<Mutex<BTreeMap<&'static str, usize>>>;

fn label(addr: IpAddr) -> Option<&'static str> {
    ADDRESSES
        .iter()
        .find(|(a, _)| IpAddr::V4(*a) == addr)
        .map(|(_, l)| *l)
}

fn tls_config(dir: &Path) -> Arc<ServerConfig> {
    let ca_key = rcgen::KeyPair::generate().expect("CA key");
    let mut ca = rcgen::CertificateParams::new(Vec::<String>::new()).expect("CA params");
    ca.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca.distinguished_name
        .push(rcgen::DnType::CommonName, "SeyLock lab CA");
    let ca = ca.self_signed(&ca_key).expect("CA certificate");

    let key = rcgen::KeyPair::generate().expect("server key");
    let names = NAMES.iter().map(|n| n.to_string()).collect::<Vec<_>>();
    let leaf = rcgen::CertificateParams::new(names)
        .expect("server params")
        .signed_by(&key, &ca, &ca_key)
        .expect("server certificate");

    std::fs::write(dir.join("ca.der"), ca.der()).expect("write ca.der");
    let config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(
            vec![leaf.der().clone(), ca.der().clone()],
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key.serialize_der())),
        )
        .expect("server TLS config");
    Arc::new(config)
}

/// Reads an HTTP request head; `None` if the peer closed or went quiet.
async fn read_head<S: tokio::io::AsyncRead + Unpin>(stream: &mut S) -> Option<()> {
    let mut buf = Vec::new();
    let mut chunk = [0u8; 1024];
    while !buf.windows(4).any(|w| w == b"\r\n\r\n") {
        let n = tokio::time::timeout(SERVER_IDLE, stream.read(&mut chunk))
            .await
            .ok()?
            .ok()?;
        if n == 0 || buf.len() > 64 * 1024 {
            return None;
        }
        buf.extend_from_slice(&chunk[..n]);
    }
    Some(())
}

async fn serve_connection(tcp: TcpStream, tls: TlsAcceptor, is_proxy: bool) -> Option<()> {
    tcp.set_nodelay(true).ok();
    let mut stream = tokio::time::timeout(SERVER_IDLE, tls.accept(tcp))
        .await
        .ok()?
        .ok()?;
    if is_proxy {
        // The volunteer proxy: the outer TLS ends here and the inner TLS goes
        // on, untouched, to the server over loopback, which is not counted.
        let mut server = TcpStream::connect((Ipv4Addr::LOCALHOST, 443)).await.ok()?;
        server.set_nodelay(true).ok();
        tokio::io::copy_bidirectional(&mut stream, &mut server)
            .await
            .ok()?;
        return Some(());
    }
    read_head(&mut stream).await?;
    stream
        .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok")
        .await
        .ok()?;
    stream.shutdown().await.ok()
}

async fn stats(listener: UnixListener, counts: Counts) {
    while let Ok((stream, _)) = listener.accept().await {
        let counts = counts.clone();
        tokio::spawn(async move {
            let (read, mut write) = stream.into_split();
            let mut lines = BufReader::new(read).lines();
            while let Ok(Some(line)) = lines.next_line().await {
                let reply = match line.trim() {
                    "reset" => {
                        counts.lock().unwrap().clear();
                        "ok".to_string()
                    }
                    "get" => counts
                        .lock()
                        .unwrap()
                        .iter()
                        .map(|(k, v)| format!("{k}={v}"))
                        .collect::<Vec<_>>()
                        .join(" "),
                    _ => "?".to_string(),
                };
                if write
                    .write_all(format!("{reply}\n").as_bytes())
                    .await
                    .is_err()
                {
                    break;
                }
            }
        });
    }
}

async fn serve(dir: PathBuf) {
    let tls = TlsAcceptor::from(tls_config(&dir));
    let counts: Counts = Arc::default();
    let socket = dir.join("stats.sock");
    let _ = std::fs::remove_file(&socket);
    tokio::spawn(stats(
        UnixListener::bind(&socket).expect("bind stats.sock"),
        counts.clone(),
    ));
    let listener = TcpListener::bind((Ipv4Addr::UNSPECIFIED, 443))
        .await
        .expect("bind :443 (run as root, in the server namespace)");
    eprintln!("netem_lab: serving on :443, CA in {}", dir.display());
    while let Ok((tcp, _)) = listener.accept().await {
        let Ok(local) = tcp.local_addr() else {
            continue;
        };
        if let Some(l) = label(local.ip()) {
            *counts.lock().unwrap().entry(l).or_default() += 1;
        }
        let is_proxy = local.ip() == IpAddr::V4(PROXY_ADDRESS);
        tokio::spawn(serve_connection(tcp, tls.clone(), is_proxy));
    }
}

// ---------------------------------------------------------------- client

fn lab_list() -> EndpointList {
    let target = |name: &str| -> BTreeMap<String, String> {
        [("api".to_string(), format!("https://{name}"))]
            .into_iter()
            .collect()
    };
    EndpointList::v2(
        1,
        i64::MAX / 2,
        [("api".to_string(), "https://api.lab.test".to_string())]
            .into_iter()
            .collect(),
        vec![
            PathSpec::Direct,
            PathSpec::Ip {
                ip: ADDRESSES[1].0.to_string(),
            },
            PathSpec::Mirror {
                keys: None,
                relay: None,
                targets: target("mirror.lab.test"),
                ip: None,
            },
            PathSpec::Cdn {
                keys: None,
                relay: None,
                targets: target("cdn.lab.test"),
            },
            PathSpec::Proxy {
                host: "proxy.lab.test".into(),
                port: 443,
            },
        ],
    )
}

struct Stats(BufReader<UnixStream>);

impl Stats {
    async fn ask(&mut self, command: &str) -> String {
        self.0
            .get_mut()
            .write_all(format!("{command}\n").as_bytes())
            .await
            .expect("stats socket");
        let mut line = String::new();
        self.0.read_line(&mut line).await.expect("stats socket");
        line.trim().to_string()
    }

    async fn get(&mut self) -> BTreeMap<String, usize> {
        self.ask("get")
            .await
            .split_whitespace()
            .filter_map(|kv| {
                let (k, v) = kv.split_once('=')?;
                Some((k.to_string(), v.parse().ok()?))
            })
            .collect()
    }
}

/// One cold request. Returns the time to the response and the path that
/// carried it, or `None` if it failed.
async fn one_run(race: Race) -> Option<(Duration, String)> {
    let proxy = proxy::start({
        let mut policy = Policy::new(lab_list());
        policy.network_id = "lab".into();
        policy.race = race;
        policy
    })
    .await
    .ok()?;
    let started = Instant::now();
    let request = async {
        let mut stream = TcpStream::connect((Ipv4Addr::LOCALHOST, proxy.port))
            .await
            .ok()?;
        let head = format!(
            "GET /health HTTP/1.1\r\nHost: lab\r\n{HEADER_TRANSPORT_TOKEN}: {}\r\n{HEADER_SERVICE}: api\r\nConnection: close\r\n\r\n",
            proxy.token
        );
        stream.write_all(head.as_bytes()).await.ok()?;
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.ok()?;
        Some(response)
    };
    let response = tokio::time::timeout(REQUEST_LIMIT, request).await.ok()??;
    let elapsed = started.elapsed();
    let text = String::from_utf8_lossy(&response);
    if !text.starts_with("HTTP/1.1 200") {
        return None;
    }
    let path = text
        .lines()
        .find_map(|l| {
            let (name, value) = l.split_once(':')?;
            name.eq_ignore_ascii_case("x-transport-path")
                .then(|| value.trim().to_string())
        })
        .unwrap_or_else(|| "?".into());
    Some((elapsed, path))
}

fn percentile(sorted: &[Duration], p: f64) -> Duration {
    let rank = ((p * sorted.len() as f64).ceil() as usize).clamp(1, sorted.len());
    sorted[rank - 1]
}

fn secs(d: Duration) -> String {
    format!("{:.2}", d.as_secs_f64())
}

/// `direct 1.00 · ip 0.97`, in list order, leaving out zeros.
fn per_path(totals: &BTreeMap<String, usize>, runs: usize) -> String {
    let parts: Vec<String> = ADDRESSES
        .iter()
        .filter_map(|(_, l)| {
            let n = *totals.get(*l)?;
            (n > 0).then(|| format!("{l} {:.2}", n as f64 / runs as f64))
        })
        .collect();
    if parts.is_empty() {
        "–".into()
    } else {
        parts.join(" · ")
    }
}

async fn run(
    dir: PathBuf,
    scenario: String,
    runs: usize,
    runs_sequential: usize,
    settle: Duration,
) {
    seylock::lab::add_root(std::fs::read(dir.join("ca.der")).expect("read ca.der"));
    let mut stats = Stats(BufReader::new(
        UnixStream::connect(dir.join("stats.sock"))
            .await
            .expect("connect stats.sock"),
    ));
    let modes = [
        ("one at a time (0.1)", Race::SEQUENTIAL, runs_sequential),
        ("racing (default: 250 ms, 3 at once)", Race::default(), runs),
        (
            "racing, 5 at once",
            Race {
                delay_ms: 250,
                max_parallel: 5,
            },
            runs,
        ),
        (
            "racing, 1 s apart",
            Race {
                delay_ms: 1_000,
                max_parallel: 3,
            },
            runs,
        ),
    ];
    for (mode, race, n) in modes {
        if n == 0 {
            continue;
        }
        let mut times = Vec::new();
        let mut winners: BTreeMap<String, usize> = BTreeMap::new();
        let mut totals: BTreeMap<String, usize> = BTreeMap::new();
        let mut most = 0;
        for _ in 0..n {
            assert_eq!(stats.ask("reset").await, "ok");
            if let Some((t, path)) = one_run(race).await {
                times.push(t);
                *winners.entry(path).or_default() += 1;
            }
            tokio::time::sleep(settle).await;
            let counts = stats.get().await;
            most = most.max(counts.values().sum::<usize>());
            for (k, v) in counts {
                *totals.entry(k).or_default() += v;
            }
        }
        times.sort();
        let all: usize = totals.values().sum();
        let won = winners
            .iter()
            .map(|(k, v)| format!("{k} {v}"))
            .collect::<Vec<_>>()
            .join(", ");
        let (median, p95, max) = match times.last() {
            Some(last) => (
                secs(percentile(&times, 0.5)),
                secs(percentile(&times, 0.95)),
                secs(*last),
            ),
            None => ("–".into(), "–".into(), "–".into()),
        };
        println!(
            "| {scenario} | {mode} | {}/{n} | {median} | {p95} | {max} | {:.2} | {most} | {} | {} |",
            times.len(),
            all as f64 / n as f64,
            per_path(&totals, n),
            if won.is_empty() { "–".into() } else { won },
        );
    }
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let usage = "usage: netem_lab serve <dir> | header | legend | \
                 run <dir> <scenario> <runs> <runs-one-at-a-time> <settle-ms>";
    match args.first().map(String::as_str) {
        Some("serve") if args.len() == 2 => serve(PathBuf::from(&args[1])).await,
        Some("header") => {
            println!(
                "| Scenario | Mode | OK | Median, s | 95th pct, s | Max, s | \
                 Server connections per request | Most in one request | By address | Answered by |"
            );
            println!("|---|---|---:|---:|---:|---:|---:|---:|---|---|");
        }
        Some("legend") => {
            println!("| Scenario | Network |\n|---|---|");
            for (name, what) in SCENARIOS {
                println!("| {name} | {what} |");
            }
        }
        Some("run") if args.len() == 6 => {
            let number = |i: usize| -> u64 { args[i].parse().expect(usage) };
            run(
                PathBuf::from(&args[1]),
                args[2].clone(),
                number(3) as usize,
                number(4) as usize,
                Duration::from_millis(number(5)),
            )
            .await
        }
        _ => {
            eprintln!("{usage}");
            std::process::exit(2);
        }
    }
}
