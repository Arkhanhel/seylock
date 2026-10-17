// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Local reverse proxy.
//!
//! The client connects to `http://127.0.0.1:<port>` and knows nothing about
//! paths. It only says which service it wants (the `X-Transport-Service`
//! header, a name from the list) and presents a token (`X-Transport-Token`),
//! so that the proxy cannot be used by other applications on the same device.
//! Everything else (choosing a path, TLS with the right SNI, TLS inside TLS for
//! Signal-style proxies, SOCKS) is done by this library. It adds
//! `X-Transport-Path` to the response so the client knows which path the
//! response came by (and, for example, does not trust a `Date` header from a
//! foreign node).
//!
//! The format 1 header names (`X-Secretly-Upstream`, `X-Secretly-Proxy-Token`,
//! `X-Secretly-Path`) keep working, so applications built against 0.1 need no
//! change.
//!
//! Why a reverse proxy rather than a client-side `findProxy` with CONNECT:
//! `dart:io` cannot start TLS over an already protected socket, and TLS inside
//! TLS is exactly the path through a volunteer's proxy. Here all TLS is done in
//! Rust.
//!
//! Upgrades (WebSocket and any other `Upgrade` protocol): after a 101
//! response the connection becomes two raw streams copied in opposite
//! directions.
//!
//! Paths race at the connection stage, in the manner of Happy Eyeballs
//! (RFC 8305): the next path starts if the previous one has not connected
//! within [`Race::delay_ms`], or at once if it failed. The first connection to
//! complete (TCP and, for `https`, the TLS handshake with certificate
//! verification) carries the request; the others are dropped. Only
//! connections race, never requests: a request body is sent exactly once.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, AtomicU64, Ordering};
use std::task::{Context, Poll};
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::{Body, Frame, Incoming, SizeHint};
use hyper_util::rt::{TokioIo, TokioTimer};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, Notify, watch};
use tokio::task::JoinSet;
use tokio_rustls::TlsConnector;
use tokio_rustls::rustls::ClientConfig;
use tokio_rustls::rustls::pki_types::ServerName;

use serde::{Deserialize, Serialize};

use crate::endpoints::{EndpointList, PathKind, PathSpec};
use crate::paths::PathMemory;

/// Request header naming the service to reach, as named in the list. The
/// proxy removes it before forwarding.
pub const HEADER_SERVICE: &str = "x-transport-service";
/// Request header carrying the random token returned at start. The proxy
/// removes it before forwarding.
pub const HEADER_TRANSPORT_TOKEN: &str = "x-transport-token";
/// Response header added by the proxy; its value is the kind of the path that
/// served the request, such as `direct` or `proxy`.
pub const HEADER_TRANSPORT_PATH: &str = "x-transport-path";

/// Format 1 name of [`HEADER_SERVICE`], still accepted: `keys` or `relay`.
pub const HEADER_UPSTREAM: &str = "x-secretly-upstream";
/// Format 1 name of [`HEADER_TRANSPORT_TOKEN`], still accepted.
pub const HEADER_TOKEN: &str = "x-secretly-proxy-token";
/// Format 1 name of [`HEADER_TRANSPORT_PATH`]. Every response carries both.
pub const HEADER_PATH: &str = "x-secretly-path";

const CONNECT_TIMEOUT_CHEAP: Duration = Duration::from_secs(6);
const CONNECT_TIMEOUT_EXPENSIVE: Duration = Duration::from_secs(12);
/// Tor may still be bootstrapping: a cold start with an empty directory cache
/// takes 10 to 20 seconds before the first circuit.
const CONNECT_TIMEOUT_TOR: Duration = Duration::from_secs(60);
/// How long a local client may take to send a request head. Without it any
/// other application on the device could hold idle connections open without
/// the token.
const LOCAL_HEADER_TIMEOUT: Duration = Duration::from_secs(30);
/// Pause after a failed `accept`, doubling up to the maximum.
const ACCEPT_BACKOFF_MIN: Duration = Duration::from_millis(50);
const ACCEPT_BACKOFF_MAX: Duration = Duration::from_secs(1);

/// Bounds applied to [`Race`] values, so a bad setting cannot turn the proxy
/// into a connection flood or make it wait for minutes.
const RACE_DELAY_MIN_MS: u64 = 10;
const RACE_DELAY_MAX_MS: u64 = 5_000;
const RACE_PARALLEL_MAX: usize = 8;
/// Bounds applied to [`Policy::response_timeout_ms`].
const RESPONSE_TIMEOUT_MIN_MS: u64 = 1_000;
const RESPONSE_TIMEOUT_MAX_MS: u64 = 600_000;
/// Requests with a larger body are not timed: the end of such a body may
/// still sit in socket buffers on its way to the server, and on a slow link
/// draining them can take longer than any sensible timeout.
const RESPONSE_TIMEOUT_BODY_LIMIT: u64 = 64 * 1024;

/// How paths race at the connection stage.
///
/// The default starts the next path after 250 ms and keeps at most three
/// attempts in flight. [`Race::SEQUENTIAL`] tries one path at a time, which
/// is the behaviour of version 0.1.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Race {
    /// How long to wait for a path to connect before also starting the next
    /// one, in milliseconds. A failed attempt starts the next one at once.
    /// Clamped to 10..=5000.
    pub delay_ms: u64,
    /// Most connection attempts in flight at once. `1` tries paths strictly
    /// one after another. Clamped to 1..=8.
    pub max_parallel: usize,
}

impl Race {
    /// One path at a time, as in version 0.1.
    pub const SEQUENTIAL: Race = Race {
        delay_ms: 250,
        max_parallel: 1,
    };

    fn delay(self) -> Duration {
        Duration::from_millis(self.delay_ms.clamp(RACE_DELAY_MIN_MS, RACE_DELAY_MAX_MS))
    }

    fn parallel(self) -> usize {
        self.max_parallel.clamp(1, RACE_PARALLEL_MAX)
    }
}

impl Default for Race {
    fn default() -> Self {
        Race {
            delay_ms: 250,
            max_parallel: 3,
        }
    }
}

type OutBody = BoxBody<Bytes, hyper::Error>;

/// State the client can change on the fly: the list, the memory, the
/// prohibitions.
///
/// Build it with [`Policy::new`] and set the fields you need; new fields may
/// be added in later versions.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Policy {
    /// The accepted endpoint list the proxy chooses paths from.
    pub list: EndpointList,
    /// What worked and failed on each network; the application persists it
    /// between runs.
    pub memory: PathMemory,
    /// Opaque identifier of the current network, chosen by the application.
    /// Selects which entry of `memory` applies.
    pub network_id: String,
    /// Whether `tor` paths may be tried. When false they are skipped.
    pub allow_tor: bool,
    /// Whether `socks` paths may be tried. When false they are skipped.
    pub allow_socks: bool,
    /// The path the proxy is currently using, until it fails.
    pub current: Option<usize>,
    /// How paths race at the connection stage.
    pub race: Race,
    /// How long to wait for the response head once the whole request has
    /// been sent, in milliseconds, clamped to 1 s..10 min. A path that
    /// accepts the request and then stays silent is a common way of
    /// blocking; when the time runs out the client gets `504` and the path is
    /// recorded as failed, so the next request tries another. Applies to
    /// requests with a body of at most 64 KiB, which covers API calls; larger
    /// uploads wait as long as the client does. `None` never times out,
    /// which suits long polling. The request is never retried either way.
    pub response_timeout_ms: Option<u64>,
}

impl Policy {
    /// A policy for `list` with no memory, an empty network id, `tor` and
    /// `socks` paths not allowed, racing with the defaults and no response
    /// timeout.
    pub fn new(list: EndpointList) -> Policy {
        Policy {
            list,
            memory: PathMemory::default(),
            network_id: String::new(),
            allow_tor: false,
            allow_socks: false,
            current: None,
            race: Race::default(),
            response_timeout_ms: None,
        }
    }

    fn response_timeout(&self) -> Option<Duration> {
        self.response_timeout_ms.map(|ms| {
            Duration::from_millis(ms.clamp(RESPONSE_TIMEOUT_MIN_MS, RESPONSE_TIMEOUT_MAX_MS))
        })
    }

    fn allowed(&self, kind: PathKind) -> bool {
        match kind {
            PathKind::Tor => self.allow_tor,
            PathKind::Socks => self.allow_socks,
            _ => true,
        }
    }

    fn order(&self, now_ms: i64) -> Vec<usize> {
        let allowed = |k: PathKind| self.allowed(k);
        let mut order = self
            .memory
            .order(&self.network_id, &self.list.paths, &allowed, now_ms);
        if let Some(cur) = self.current
            && let Some(pos) = order.iter().position(|i| *i == cur)
        {
            order.remove(pos);
            order.insert(0, cur);
        }
        order
    }
}

/// What to return to the client with the response, and what to remember.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Served {
    /// Index into the list's `paths` of the path used.
    pub path_index: usize,
    /// Kind of that path, reported in the `x-transport-path` and
    /// `x-secretly-path` headers.
    pub kind: PathKind,
}

/// Handle to a running local proxy. Dropping it stops the proxy.
///
/// Stopping closes the listener and every open connection, WebSocket tunnels
/// included, so nothing keeps forwarding under an old policy.
pub struct ProxyHandle {
    /// TCP port on `127.0.0.1` the proxy listens on.
    pub port: u16,
    /// Random token that requests must present in `x-transport-token` (or the
    /// format 1 `x-secretly-proxy-token`).
    pub token: String,
    policy: Arc<Mutex<Policy>>,
    generation: Arc<AtomicU64>,
    shutdown: Option<watch::Sender<()>>,
}

impl ProxyHandle {
    /// Modifies the policy in place. The change applies to requests that start
    /// afterwards.
    pub async fn update_policy(&self, f: impl FnOnce(&mut Policy)) {
        let mut p = self.policy.lock().await;
        f(&mut p);
        // Requests already in flight belong to the old policy: their
        // outcomes are not recorded against the new network or list.
        self.generation.fetch_add(1, Ordering::SeqCst);
        // A new list may carry new Tor bridges.
        crate::tor::set_list_bridges(&p.list.tor_bridges);
    }

    /// Returns a snapshot of the current policy.
    pub async fn policy(&self) -> Policy {
        self.policy.lock().await.clone()
    }

    /// Stops the proxy: closes the listener and every open connection.
    /// Repeated calls have no effect.
    pub fn stop(&mut self) {
        // Dropping the sender wakes every task watching it.
        self.shutdown.take();
    }
}

impl Drop for ProxyHandle {
    fn drop(&mut self) {
        self.stop();
    }
}

#[derive(Clone)]
struct Shared {
    token: String,
    policy: Arc<Mutex<Policy>>,
    /// Bumped on every policy change.
    generation: Arc<AtomicU64>,
    tls: TlsConnector,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
    /// Closes when the proxy stops.
    shutdown: watch::Receiver<()>,
}

impl Shared {
    /// Records the outcome of a path, unless the policy changed since the
    /// request started: then the network or the list may differ, and the
    /// index or the network id would be wrong.
    async fn note(&self, generation: u64, idx: usize, ok: bool, now_ms: i64) {
        let mut policy = self.policy.lock().await;
        if self.generation.load(Ordering::SeqCst) == generation {
            policy.note(idx, ok, now_ms);
        }
    }
}

/// Resolves when the proxy stops.
async fn stopped(mut shutdown: watch::Receiver<()>) {
    while shutdown.changed().await.is_ok() {}
}

fn now_ms_system() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_millis() as i64)
        .unwrap_or(0)
}

/// Starts the proxy on loopback with a random port and token.
pub async fn start(policy: Policy) -> std::io::Result<ProxyHandle> {
    start_with_clock(policy, Arc::new(now_ms_system)).await
}

/// Like [`start`], with an injected clock returning Unix milliseconds, so tests
/// can control time.
pub async fn start_with_clock(
    policy: Policy,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
) -> std::io::Result<ProxyHandle> {
    let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0)).await?;
    let port = listener.local_addr()?.port();
    let token = URL_SAFE_NO_PAD.encode(rand::random::<[u8; 24]>());
    crate::tor::set_list_bridges(&policy.list.tor_bridges);
    let policy = Arc::new(Mutex::new(policy));
    let generation = Arc::new(AtomicU64::new(0));
    let (tx, rx) = watch::channel(());
    let shared = Shared {
        token: token.clone(),
        policy: policy.clone(),
        generation: generation.clone(),
        tls: tls_connector(),
        now_ms,
        shutdown: rx.clone(),
    };
    tokio::spawn(async move {
        let stop = stopped(rx);
        tokio::pin!(stop);
        let mut backoff = ACCEPT_BACKOFF_MIN;
        loop {
            tokio::select! {
                _ = &mut stop => break,
                accepted = listener.accept() => {
                    let (stream, peer) = match accepted {
                        Ok(pair) => {
                            backoff = ACCEPT_BACKOFF_MIN;
                            pair
                        }
                        Err(e) => {
                            // Out of file descriptors, or the socket taken
                            // away while the app was suspended: wait instead
                            // of spinning, and keep the proxy alive.
                            tracing::warn!(target: "seylock", "accept: {e}");
                            tokio::time::sleep(backoff).await;
                            backoff = (backoff * 2).min(ACCEPT_BACKOFF_MAX);
                            continue;
                        }
                    };
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let shutdown = shared.shutdown.clone();
                        let io = TokioIo::new(stream);
                        let service = hyper::service::service_fn(move |req| {
                            let shared = shared.clone();
                            async move { Ok::<_, hyper::Error>(handle(shared, req).await) }
                        });
                        let mut builder = hyper::server::conn::http1::Builder::new();
                        builder
                            .timer(TokioTimer::new())
                            .header_read_timeout(LOCAL_HEADER_TIMEOUT);
                        let conn = builder.serve_connection(io, service).with_upgrades();
                        tokio::select! {
                            result = conn => {
                                if let Err(e) = result {
                                    tracing::debug!(target: "seylock", "client conn: {e}");
                                }
                            }
                            _ = stopped(shutdown) => {}
                        }
                    });
                }
            }
        }
    });
    Ok(ProxyHandle {
        port,
        token,
        policy,
        generation,
        shutdown: Some(tx),
    })
}

fn tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    #[cfg(feature = "lab-roots")]
    for root in crate::lab::roots() {
        tracing::warn!(target: "seylock", "trusting a lab root certificate (lab-roots feature)");
        let _ = roots.add(root);
    }
    // The provider is named, not taken from the process default: an
    // application whose other dependencies enable another rustls provider
    // would otherwise make this call panic.
    let config =
        ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
            .with_safe_default_protocol_versions()
            .expect("ring supports the default protocol versions")
            .with_root_certificates(roots)
            .with_no_client_auth();
    TlsConnector::from(Arc::new(config))
}

fn reply(status: StatusCode, text: &'static str) -> Response<OutBody> {
    Response::builder()
        .status(status)
        .body(
            Full::new(Bytes::from_static(text.as_bytes()))
                .map_err(|e| match e {})
                .boxed(),
        )
        .unwrap()
}

/// Compares the presented token with ours in time that does not depend on
/// where the first difference is, so another process on the device cannot
/// guess the token byte by byte from response timing.
fn token_eq(presented: &[u8], expected: &[u8]) -> bool {
    if presented.len() != expected.len() {
        return false;
    }
    presented
        .iter()
        .zip(expected)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b))
        == 0
}

async fn handle(shared: Shared, mut req: Request<Incoming>) -> Response<OutBody> {
    let headers = req.headers_mut();
    // Both spellings are removed whichever one was used, so neither the token
    // nor the control header ever reaches the server.
    let token_new = headers.remove(HEADER_TRANSPORT_TOKEN);
    let token_old = headers.remove(HEADER_TOKEN);
    let service_new = headers.remove(HEADER_SERVICE);
    let service_old = headers.remove(HEADER_UPSTREAM);
    let token_ok = token_new
        .or(token_old)
        .map(|v| token_eq(v.as_bytes(), shared.token.as_bytes()))
        .unwrap_or(false);
    if !token_ok {
        return reply(StatusCode::FORBIDDEN, "proxy token");
    }
    let service = match service_new
        .or(service_old)
        .and_then(|v| v.to_str().ok().map(str::to_ascii_lowercase))
    {
        Some(s) if !s.is_empty() => s,
        _ => return reply(StatusCode::BAD_REQUEST, "service"),
    };

    let (policy, generation) = {
        let policy = shared.policy.lock().await;
        (policy.clone(), shared.generation.load(Ordering::SeqCst))
    };
    if policy.list.service_base(&service).is_none() {
        return reply(StatusCode::BAD_REQUEST, "unknown service");
    }
    let now = (shared.now_ms)();
    let order = policy.order(now);
    if order.is_empty() {
        return reply(StatusCode::SERVICE_UNAVAILABLE, "no paths");
    }

    // A request body can be sent only once, so paths race at the connection
    // stage and the request goes once, over the connection that won.
    let candidates: VecDeque<Candidate> = order
        .into_iter()
        .filter_map(|idx| {
            let spec = policy.list.paths[idx].clone();
            // A path that does not lead to this service is skipped without
            // recording a failure: that is a property of the list, not of the
            // network.
            Target::resolve(&policy.list, &spec, &service).map(|target| Candidate {
                idx,
                spec,
                target,
            })
        })
        .collect();
    match race_connect(&shared, candidates, policy.race, generation, now).await {
        Ok((winner, stream)) => {
            let served = Served {
                path_index: winner.idx,
                kind: winner.spec.kind(),
            };
            // A path counts as working only once a request through it has
            // actually succeeded. Counting the connection alone let a mirror
            // that drops every request right after TLS stay current forever,
            // and the proxy never moved on.
            let (response, outcome) = forward(
                req,
                stream,
                &winner.target,
                served,
                policy.response_timeout(),
                shared.shutdown.clone(),
            )
            .await;
            if let Some(ok) = outcome {
                shared.note(generation, winner.idx, ok, now).await;
            }
            response
        }
        Err(last_err) => {
            tracing::info!(target: "seylock", "all paths failed: {last_err}");
            reply(StatusCode::BAD_GATEWAY, "all paths failed")
        }
    }
}

/// A path ready to be tried for one request.
struct Candidate {
    idx: usize,
    spec: PathSpec,
    target: Target,
}

type Attempt = (Candidate, Result<Upstream_, String>);

/// Races the candidates at the connection stage and returns the first one
/// that connected, with its stream. Attempts still in flight are dropped.
/// Failures are recorded in the path memory; attempts dropped because another
/// path won are not, since nothing was learned about them.
async fn race_connect(
    shared: &Shared,
    mut queue: VecDeque<Candidate>,
    race: Race,
    generation: u64,
    now_ms: i64,
) -> Result<(Candidate, Upstream_), String> {
    let delay = race.delay();
    let parallel = race.parallel();
    let mut attempts: JoinSet<Attempt> = JoinSet::new();
    let mut last_err = String::from("no path leads to this service");
    let mut next_start = tokio::time::Instant::now();
    loop {
        let start_now = !queue.is_empty()
            && attempts.len() < parallel
            && (attempts.is_empty() || tokio::time::Instant::now() >= next_start);
        if start_now {
            let candidate = queue.pop_front().expect("queue is not empty");
            let shared = shared.clone();
            attempts.spawn(async move {
                let result = connect(&shared, &candidate.spec, &candidate.target).await;
                (candidate, result)
            });
            next_start = tokio::time::Instant::now() + delay;
            continue;
        }
        if attempts.is_empty() {
            return Err(last_err);
        }
        let may_start_more = !queue.is_empty() && attempts.len() < parallel;
        tokio::select! {
            joined = attempts.join_next() => match joined {
                Some(Ok((candidate, Ok(stream)))) => {
                    attempts.abort_all();
                    return Ok((candidate, stream));
                }
                Some(Ok((candidate, Err(e)))) => {
                    last_err = format!("{}: {e}", candidate.spec.kind().as_str());
                    shared.note(generation, candidate.idx, false, now_ms).await;
                    // The slot is free: the next path starts at once.
                    next_start = tokio::time::Instant::now();
                }
                Some(Err(e)) => {
                    last_err = format!("connection attempt: {e}");
                    next_start = tokio::time::Instant::now();
                }
                None => {}
            },
            _ = tokio::time::sleep_until(next_start), if may_start_more => {}
        }
    }
}

impl Policy {
    fn note(&mut self, idx: usize, ok: bool, now_ms: i64) {
        let network_id = self.network_id.clone();
        self.memory.report(&network_id, idx, ok, now_ms);
        if ok {
            self.current = Some(idx);
        } else if self.current == Some(idx) {
            self.current = None;
        }
    }
}

/// Where exactly to connect and what to write in `Host`.
#[derive(Clone, Debug)]
struct Target {
    /// Name for TLS (SNI and certificate verification) and for `Host`.
    host: String,
    port: u16,
    /// Address for TCP, if it differs from the name.
    connect_ip: Option<String>,
    /// Path prefix (a mirror may serve `/k/...`).
    path_prefix: String,
    tls: bool,
}

impl Target {
    /// `None` when the path cannot reach `service`: a mirror or CDN name that
    /// does not serve it, or an address that is not a valid URL. The caller
    /// skips such a path without recording a network failure.
    fn resolve(list: &EndpointList, spec: &PathSpec, service: &str) -> Option<Target> {
        match spec {
            PathSpec::Direct | PathSpec::Proxy { .. } | PathSpec::Socks { .. } | PathSpec::Tor => {
                Target::from_base(list.service_base(service)?, None)
            }
            PathSpec::Ip { ip } => Target::from_base(list.service_base(service)?, Some(ip.clone())),
            PathSpec::Mirror { ip, .. } => {
                Target::from_base(spec.target_base(service)?, ip.clone())
            }
            PathSpec::Cdn { .. } => Target::from_base(spec.target_base(service)?, None),
        }
    }

    fn from_base(base: &str, connect_ip: Option<String>) -> Option<Target> {
        let uri: Uri = base.parse().ok()?;
        let tls = match uri.scheme_str() {
            Some("https") => true,
            // Plain HTTP is for tests and loopback only; a production client
            // policy does not let such base URLs through.
            Some("http") => false,
            _ => return None,
        };
        // An IPv6 literal comes bracketed; TLS and TCP want it bare.
        let host = uri
            .host()?
            .trim_start_matches('[')
            .trim_end_matches(']')
            .to_string();
        let port = uri.port_u16().unwrap_or(if tls { 443 } else { 80 });
        let path_prefix = uri.path().trim_end_matches('/').to_string();
        Some(Target {
            host,
            port,
            connect_ip,
            path_prefix,
            tls,
        })
    }

    fn addr(&self) -> String {
        format!(
            "{}:{}",
            bracket_v6(self.connect_ip.as_deref().unwrap_or(&self.host)),
            self.port
        )
    }
}

/// `[2001:db8::1]` for an IPv6 literal, anything else unchanged: the form
/// `host:port` strings and the `Host` header need.
fn bracket_v6(host: &str) -> std::borrow::Cow<'_, str> {
    if host.contains(':') {
        format!("[{host}]").into()
    } else {
        host.into()
    }
}

/// A stream to the server: any `AsyncRead + AsyncWrite`.
type Upstream_ = Box<dyn AsyncReadWrite>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn connect(shared: &Shared, spec: &PathSpec, target: &Target) -> Result<Upstream_, String> {
    let timeout = match spec.kind() {
        PathKind::Direct | PathKind::Ip => CONNECT_TIMEOUT_CHEAP,
        PathKind::Tor => CONNECT_TIMEOUT_TOR,
        _ => CONNECT_TIMEOUT_EXPENSIVE,
    };
    tokio::time::timeout(timeout, connect_inner(shared, spec, target))
        .await
        .map_err(|_| "timeout".to_string())?
}

async fn connect_inner(
    shared: &Shared,
    spec: &PathSpec,
    target: &Target,
) -> Result<Upstream_, String> {
    let io_err = |e: std::io::Error| e.to_string();
    match spec {
        PathSpec::Direct | PathSpec::Ip { .. } | PathSpec::Mirror { .. } | PathSpec::Cdn { .. } => {
            let tcp = TcpStream::connect(target.addr()).await.map_err(io_err)?;
            tcp.set_nodelay(true).ok();
            maybe_tls(shared, tcp, target).await
        }
        PathSpec::Proxy { host, port } => {
            // Outer TLS to the volunteer, inner TLS to the real name.
            let tcp = TcpStream::connect((host.as_str(), *port))
                .await
                .map_err(io_err)?;
            tcp.set_nodelay(true).ok();
            let outer_name = ServerName::try_from(host.clone()).map_err(|e| e.to_string())?;
            let outer = shared.tls.connect(outer_name, tcp).await.map_err(io_err)?;
            maybe_tls(shared, outer, target).await
        }
        PathSpec::Socks { addr } => {
            let proxy: SocketAddr = addr.parse().map_err(|_| "socks addr".to_string())?;
            let stream =
                tokio_socks::tcp::Socks5Stream::connect(proxy, (target.host.as_str(), target.port))
                    .await
                    .map_err(|e| e.to_string())?;
            maybe_tls(shared, stream, target).await
        }
        PathSpec::Tor => {
            let Some(connector) = crate::tor::installed() else {
                return Err("tor: no Tor connector installed".to_string());
            };
            let stream = connector.connect(&target.host, target.port).await?;
            maybe_tls(shared, stream, target).await
        }
    }
}

async fn maybe_tls<S>(shared: &Shared, stream: S, target: &Target) -> Result<Upstream_, String>
where
    S: AsyncRead + AsyncWrite + Unpin + Send + 'static,
{
    if !target.tls {
        return Ok(Box::new(stream));
    }
    let name = ServerName::try_from(target.host.clone()).map_err(|e| e.to_string())?;
    let tls = shared
        .tls
        .connect(name, stream)
        .await
        .map_err(|e| e.to_string())?;
    Ok(Box::new(tls))
}

async fn forward(
    req: Request<Incoming>,
    stream: Upstream_,
    target: &Target,
    served: Served,
    response_timeout: Option<Duration>,
    shutdown: watch::Receiver<()>,
) -> (Response<OutBody>, Option<bool>) {
    // Re-address the request to the target: the path gets the mirror's
    // prefix and `Host` becomes the target's name. Request signatures that
    // applications add must not cover the host for this to be safe; the
    // Secretly protocol's do not.
    let (parts, body) = req.into_parts();
    let body_state = Arc::new(BodyState::default());
    if body.is_end_stream() {
        body_state.finish(BODY_COMPLETE);
    }
    let mut req = Request::from_parts(
        parts,
        WatchedBody {
            inner: body,
            state: body_state.clone(),
        },
    );
    let path_and_query = req
        .uri()
        .path_and_query()
        .map(|p| p.as_str().to_string())
        .unwrap_or_else(|| "/".to_string());
    let new_path = format!("{}{}", target.path_prefix, path_and_query);
    *req.uri_mut() = match new_path.parse::<Uri>() {
        Ok(u) => u,
        Err(_) => return (reply(StatusCode::BAD_REQUEST, "uri"), None),
    };
    let host_value = if (target.tls && target.port == 443) || (!target.tls && target.port == 80) {
        bracket_v6(&target.host).into_owned()
    } else {
        format!("{}:{}", bracket_v6(&target.host), target.port)
    };
    match HeaderValue::from_str(&host_value) {
        Ok(v) => {
            req.headers_mut().insert(HOST, v);
        }
        Err(_) => return (reply(StatusCode::BAD_REQUEST, "host"), None),
    }

    // Any protocol upgrade, WebSocket or another, is tunnelled after a 101;
    // otherwise the client would get a 101 and then nothing.
    let is_upgrade = req.headers().contains_key(http::header::UPGRADE);

    let (mut sender, conn) = match hyper::client::conn::http1::handshake(TokioIo::new(stream)).await
    {
        Ok(pair) => pair,
        Err(e) => {
            tracing::debug!(target: "seylock", "upstream handshake: {e}");
            return (
                reply(StatusCode::BAD_GATEWAY, "upstream handshake"),
                Some(false),
            );
        }
    };
    let conn = conn.with_upgrades();
    tokio::spawn(async move {
        if let Err(e) = conn.await {
            tracing::debug!(target: "seylock", "upstream conn: {e}");
        }
    });

    // An upgrade needs the client side of the request, which has to be taken
    // from the request before it is sent.
    let client_upgrade = if is_upgrade {
        Some(hyper::upgrade::on(&mut req))
    } else {
        None
    };

    let sent = sender.send_request(req);
    let result = match response_timeout {
        None => sent.await.map_err(Some),
        Some(limit) => {
            // The clock starts once the whole request has been sent, so a
            // long upload is never cut short; only silence afterwards counts.
            let state = body_state.clone();
            let silence = async move {
                state.done.notified().await;
                if state.status.load(Ordering::SeqCst) != BODY_COMPLETE
                    || state.sent.load(Ordering::SeqCst) > RESPONSE_TIMEOUT_BODY_LIMIT
                {
                    std::future::pending::<()>().await;
                }
                tokio::time::sleep(limit).await;
            };
            tokio::select! {
                r = sent => r.map_err(Some),
                _ = silence => Err(None),
            }
        }
    };
    let mut response = match result {
        Ok(r) => r,
        Err(None) => {
            tracing::debug!(target: "seylock", "no response within {response_timeout:?}");
            return (
                reply(StatusCode::GATEWAY_TIMEOUT, "no response"),
                Some(false),
            );
        }
        Err(Some(e)) => {
            tracing::debug!(target: "seylock", "upstream request: {e}");
            // When the client broke off its own upload, the path did nothing
            // wrong and nothing is recorded.
            let client_broke_off = body_state.status.load(Ordering::SeqCst) == BODY_CLIENT_ERROR;
            return (
                reply(StatusCode::BAD_GATEWAY, "upstream request"),
                (!client_broke_off).then_some(false),
            );
        }
    };
    if let Ok(v) = HeaderValue::from_str(served.kind.as_str()) {
        let headers = response.headers_mut();
        headers.insert(HeaderName::from_static(HEADER_TRANSPORT_PATH), v.clone());
        headers.insert(HeaderName::from_static(HEADER_PATH), v);
    }
    // Every service is reached at the same local URL; this keeps an HTTP
    // cache from answering a request for one service with another's
    // response.
    for name in [HEADER_SERVICE, HEADER_UPSTREAM] {
        response
            .headers_mut()
            .append(http::header::VARY, HeaderValue::from_static(name));
    }

    if response.status() == StatusCode::SWITCHING_PROTOCOLS {
        if let Some(client_upgrade) = client_upgrade {
            let upstream_upgrade = hyper::upgrade::on(&mut response);
            tokio::spawn(async move {
                let (Ok(client), Ok(upstream)) = (client_upgrade.await, upstream_upgrade.await)
                else {
                    return;
                };
                let mut client = TokioIo::new(client);
                let mut upstream = TokioIo::new(upstream);
                tokio::select! {
                    _ = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {}
                    _ = stopped(shutdown) => {}
                }
            });
        }
        let (parts, _) = response.into_parts();
        return (
            Response::from_parts(parts, Empty::<Bytes>::new().map_err(|e| match e {}).boxed()),
            Some(true),
        );
    }

    // A gateway error means a mirror, CDN name or proxy answered but could
    // not reach the server: the response goes to the client as it is, and the
    // path is not taken as working, so the next request tries another. Any
    // other status, errors included, comes from the server itself.
    let path_worked = !matches!(
        response.status(),
        StatusCode::BAD_GATEWAY | StatusCode::GATEWAY_TIMEOUT
    );
    let (parts, body) = response.into_parts();
    (Response::from_parts(parts, body.boxed()), Some(path_worked))
}

/// The request body from the local client, watched so the proxy knows when
/// all of it has been sent and whether the client broke it off.
struct WatchedBody {
    inner: Incoming,
    state: Arc<BodyState>,
}

const BODY_SENDING: u8 = 0;
const BODY_COMPLETE: u8 = 1;
const BODY_CLIENT_ERROR: u8 = 2;

#[derive(Default)]
struct BodyState {
    status: AtomicU8,
    /// Body bytes passed on so far.
    sent: AtomicU64,
    /// Signalled once, when the body completes or breaks off.
    done: Notify,
}

impl BodyState {
    fn finish(&self, status: u8) {
        if self
            .status
            .compare_exchange(BODY_SENDING, status, Ordering::SeqCst, Ordering::SeqCst)
            .is_ok()
        {
            // Stores a permit if nobody waits yet.
            self.done.notify_one();
        }
    }
}

impl Body for WatchedBody {
    type Data = Bytes;
    type Error = hyper::Error;

    fn poll_frame(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, hyper::Error>>> {
        let polled = Pin::new(&mut self.inner).poll_frame(cx);
        if let Poll::Ready(Some(Ok(frame))) = &polled
            && let Some(data) = frame.data_ref()
        {
            self.state
                .sent
                .fetch_add(data.len() as u64, Ordering::SeqCst);
        }
        match &polled {
            Poll::Ready(None) => self.state.finish(BODY_COMPLETE),
            Poll::Ready(Some(Err(_))) => self.state.finish(BODY_CLIENT_ERROR),
            Poll::Ready(Some(Ok(_))) if self.inner.is_end_stream() => {
                self.state.finish(BODY_COMPLETE)
            }
            _ => {}
        }
        polled
    }

    fn is_end_stream(&self) -> bool {
        self.inner.is_end_stream()
    }

    fn size_hint(&self) -> SizeHint {
        self.inner.size_hint()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::Logical;
    use http_body_util::BodyExt;
    use hyper::service::service_fn;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    /// Test server: replies "host=... path=...", and echoes on upgrade.
    async fn upstream_server() -> (u16, Arc<AtomicUsize>) {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let hits = Arc::new(AtomicUsize::new(0));
        let hits_c = hits.clone();
        tokio::spawn(async move {
            loop {
                let Ok((stream, _)) = listener.accept().await else {
                    break;
                };
                let hits = hits_c.clone();
                tokio::spawn(async move {
                    let svc = service_fn(move |mut req: Request<Incoming>| {
                        hits.fetch_add(1, Ordering::SeqCst);
                        async move {
                            let host = req
                                .headers()
                                .get(HOST)
                                .and_then(|v| v.to_str().ok())
                                .unwrap_or("")
                                .to_string();
                            let path = req.uri().path().to_string();
                            let is_upgrade = req.headers().contains_key(http::header::UPGRADE);
                            let leaked = req.headers().contains_key(HEADER_TOKEN)
                                || req.headers().contains_key(HEADER_UPSTREAM)
                                || req.headers().contains_key(HEADER_TRANSPORT_TOKEN)
                                || req.headers().contains_key(HEADER_SERVICE);
                            if is_upgrade {
                                let up = hyper::upgrade::on(&mut req);
                                tokio::spawn(async move {
                                    if let Ok(io) = up.await {
                                        let mut io = TokioIo::new(io);
                                        let mut buf = [0u8; 64];
                                        if let Ok(n) = io.read(&mut buf).await {
                                            let _ = io.write_all(&buf[..n]).await;
                                        }
                                    }
                                });
                                return Ok::<_, hyper::Error>(
                                    Response::builder()
                                        .status(StatusCode::SWITCHING_PROTOCOLS)
                                        .header(http::header::UPGRADE, "websocket")
                                        .header(http::header::CONNECTION, "upgrade")
                                        .body(Empty::<Bytes>::new().map_err(|e| match e {}).boxed())
                                        .unwrap(),
                                );
                            }
                            let body = format!("host={host} path={path} leaked={leaked}");
                            Ok(Response::new(
                                Full::new(Bytes::from(body)).map_err(|e| match e {}).boxed(),
                            ))
                        }
                    });
                    let _ = hyper::server::conn::http1::Builder::new()
                        .serve_connection(TokioIo::new(stream), svc)
                        .with_upgrades()
                        .await;
                });
            }
        });
        (port, hits)
    }

    fn policy(paths: Vec<PathSpec>) -> Policy {
        Policy {
            list: EndpointList {
                v: 1,
                issued_at_ms: 1,
                expires_at_ms: i64::MAX / 2,
                logical: Some(Logical {
                    keys: "https://keys.invalid".into(),
                    relay: "https://relay.invalid".into(),
                }),
                services: Default::default(),
                paths,
                tor_bridges: Vec::new(),
            },
            memory: PathMemory::default(),
            network_id: "test".into(),
            allow_tor: false,
            allow_socks: false,
            current: None,
            race: Race::default(),
            response_timeout_ms: None,
        }
    }

    fn mirror(port: u16) -> PathSpec {
        PathSpec::Mirror {
            keys: Some(format!("http://127.0.0.1:{port}/k")),
            relay: Some(format!("http://127.0.0.1:{port}/r")),
            targets: Default::default(),
            ip: None,
        }
    }

    async fn get(
        proxy: &ProxyHandle,
        token: &str,
        upstream: &str,
        path: &str,
    ) -> (StatusCode, Option<String>, String) {
        let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri(path)
            .header(HOST, "127.0.0.1")
            .header(HEADER_TOKEN, token)
            .header(HEADER_UPSTREAM, upstream)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        let status = res.status();
        let via = res
            .headers()
            .get(HEADER_PATH)
            .map(|v| v.to_str().unwrap().to_string());
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (status, via, String::from_utf8_lossy(&body).to_string())
    }

    #[tokio::test]
    async fn routes_by_upstream_and_strips_private_headers() {
        let (port, _) = upstream_server().await;
        let proxy = start(policy(vec![mirror(port)])).await.unwrap();
        let (status, via, body) = get(&proxy, &proxy.token, "keys", "/v1/config?x=1").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(via.as_deref(), Some("mirror"));
        assert_eq!(
            body,
            format!("host=127.0.0.1:{port} path=/k/v1/config leaked=false")
        );
        let (_, _, body) = get(&proxy, &proxy.token, "relay", "/ws").await;
        assert!(body.contains("path=/r/ws"));
    }

    #[test]
    fn token_comparison_is_exact() {
        assert!(token_eq(b"abc", b"abc"));
        assert!(!token_eq(b"abd", b"abc"));
        assert!(!token_eq(b"ab", b"abc"));
        assert!(!token_eq(b"", b"abc"));
    }

    #[tokio::test]
    async fn rejects_without_token_or_upstream() {
        let (port, hits) = upstream_server().await;
        let proxy = start(policy(vec![mirror(port)])).await.unwrap();
        assert_eq!(
            get(&proxy, "wrong", "keys", "/x").await.0,
            StatusCode::FORBIDDEN
        );
        assert_eq!(
            get(&proxy, &proxy.token, "", "/x").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0, "nothing reached the server");
    }

    #[tokio::test]
    async fn a_path_that_drops_requests_after_connecting_is_abandoned() {
        let (port, _) = upstream_server().await;
        // Accepts TCP and closes at once: connect succeeds, the request fails.
        let dropper = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let drop_port = dropper.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((stream, _)) = dropper.accept().await {
                drop(stream);
            }
        });
        let proxy = start(policy(vec![mirror(drop_port), mirror(port)]))
            .await
            .unwrap();
        let (status, _, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        let p = proxy.policy().await;
        assert_eq!(p.current, None, "a failed request must not pin the path");
        let (status, _, body) = get(&proxy, &proxy.token, "keys", "/b").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("path=/k/b"));
        assert_eq!(proxy.policy().await.current, Some(1));
    }

    #[tokio::test]
    async fn fails_over_to_the_next_path_and_remembers_it() {
        let (port, _) = upstream_server().await;
        // The first path is a closed port; the second one works.
        let dead = {
            let l = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
                .await
                .unwrap();
            l.local_addr().unwrap().port()
        };
        let proxy = start(policy(vec![mirror(dead), mirror(port)]))
            .await
            .unwrap();
        let (status, via, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(via.as_deref(), Some("mirror"));
        let p = proxy.policy().await;
        assert_eq!(p.current, Some(1));
        assert_eq!(
            p.memory.order("test", &p.list.paths, &|_| true, 2),
            vec![1, 0]
        );
    }

    #[tokio::test]
    async fn forbidden_kinds_are_skipped_and_empty_order_is_503() {
        let proxy = start(policy(vec![PathSpec::Tor])).await.unwrap();
        let (status, _, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    }

    /// WebSocket and any other `Upgrade` protocol are tunnelled after a 101,
    /// and stopping the proxy closes the tunnel.
    #[tokio::test]
    async fn upgrades_are_tunnelled_and_closed_on_stop() {
        for protocol in ["websocket", "h2c"] {
            let (port, _) = upstream_server().await;
            let mut proxy = start(policy(vec![mirror(port)])).await.unwrap();
            let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
            let req = format!(
                "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\n{HEADER_TOKEN}: {}\r\n{HEADER_UPSTREAM}: relay\r\nConnection: Upgrade\r\nUpgrade: {protocol}\r\n\r\n",
                proxy.token
            );
            stream.write_all(req.as_bytes()).await.unwrap();
            let mut buf = vec![0u8; 1024];
            let n = stream.read(&mut buf).await.unwrap();
            let head = String::from_utf8_lossy(&buf[..n]).to_string();
            assert!(head.starts_with("HTTP/1.1 101"), "{protocol}: {head}");
            assert!(
                head.to_lowercase()
                    .contains(&format!("{HEADER_PATH}: mirror")),
                "{head}"
            );
            stream.write_all(b"ping-through").await.unwrap();
            let mut echo = [0u8; 12];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut echo))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&echo, b"ping-through", "{protocol}");

            proxy.stop();
            let closed = tokio::time::timeout(Duration::from_secs(5), stream.read(&mut buf))
                .await
                .expect("the tunnel closes when the proxy stops");
            assert!(matches!(closed, Ok(0) | Err(_)), "{protocol}: {closed:?}");
        }
    }

    fn v2_policy(paths: Vec<PathSpec>) -> Policy {
        let mut p = policy(paths);
        p.list.v = 2;
        p.list.logical = None;
        p.list.services = [
            ("api".to_string(), "https://api.invalid".to_string()),
            ("media".to_string(), "https://media.invalid".to_string()),
        ]
        .into_iter()
        .collect();
        p
    }

    fn v2_mirror(port: u16, services: &[&str]) -> PathSpec {
        PathSpec::Mirror {
            keys: None,
            relay: None,
            targets: services
                .iter()
                .map(|s| (s.to_string(), format!("http://127.0.0.1:{port}/{s}")))
                .collect(),
            ip: None,
        }
    }

    async fn get_v2(
        proxy: &ProxyHandle,
        service: &str,
        path: &str,
    ) -> (StatusCode, Option<String>, Option<String>, String) {
        let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .uri(path)
            .header(HOST, "127.0.0.1")
            .header(HEADER_TRANSPORT_TOKEN, &proxy.token)
            .header(HEADER_SERVICE, service)
            .body(Empty::<Bytes>::new())
            .unwrap();
        let res = sender.send_request(req).await.unwrap();
        let header = |n: &str| {
            res.headers()
                .get(n)
                .map(|v| v.to_str().unwrap().to_string())
        };
        let (via_new, via_old) = (header(HEADER_TRANSPORT_PATH), header(HEADER_PATH));
        let status = res.status();
        let body = res.into_body().collect().await.unwrap().to_bytes();
        (
            status,
            via_new,
            via_old,
            String::from_utf8_lossy(&body).to_string(),
        )
    }

    #[tokio::test]
    async fn v2_routes_named_services_and_strips_new_headers() {
        let (port, _) = upstream_server().await;
        let proxy = start(v2_policy(vec![v2_mirror(port, &["api", "media"])]))
            .await
            .unwrap();
        let (status, via_new, via_old, body) = get_v2(&proxy, "media", "/v1/x").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(via_new.as_deref(), Some("mirror"));
        assert_eq!(via_old.as_deref(), Some("mirror"), "both header spellings");
        assert_eq!(
            body,
            format!("host=127.0.0.1:{port} path=/media/v1/x leaked=false")
        );
    }

    #[tokio::test]
    async fn v2_skips_a_mirror_that_does_not_serve_the_service() {
        let (port, _) = upstream_server().await;
        // The first mirror serves only `api`; a `media` request must go to the
        // second one without marking the first as failed.
        let proxy = start(v2_policy(vec![
            v2_mirror(port, &["api"]),
            v2_mirror(port, &["media"]),
        ]))
        .await
        .unwrap();
        let (status, _, _, body) = get_v2(&proxy, "media", "/m").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("path=/media/m"), "{body}");
        let p = proxy.policy().await;
        assert_eq!(p.current, Some(1));
        assert_eq!(
            p.memory.order("test", &p.list.paths, &|_| true, 2),
            vec![1, 0],
            "the skipped mirror is not recorded as failed, only ranked after the one that worked"
        );
    }

    #[tokio::test]
    async fn v2_unknown_service_is_400_and_sends_nothing() {
        let (port, hits) = upstream_server().await;
        let proxy = start(v2_policy(vec![v2_mirror(port, &["api"])]))
            .await
            .unwrap();
        assert_eq!(
            get_v2(&proxy, "keys", "/x").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(
            get_v2(&proxy, "nope", "/x").await.0,
            StatusCode::BAD_REQUEST
        );
        assert_eq!(hits.load(Ordering::SeqCst), 0);
    }

    /// Accepts TCP and never answers: a TLS handshake against it hangs until
    /// the connect timeout, as it does behind a censor that silently drops.
    async fn stalling_server() -> u16 {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            let mut held = Vec::new();
            while let Ok((stream, _)) = listener.accept().await {
                held.push(stream);
            }
        });
        port
    }

    fn stalled_tls_mirror(port: u16) -> PathSpec {
        PathSpec::Mirror {
            keys: Some(format!("https://127.0.0.1:{port}/k")),
            relay: Some(format!("https://127.0.0.1:{port}/r")),
            targets: Default::default(),
            ip: None,
        }
    }

    #[tokio::test]
    async fn racing_reaches_a_working_path_behind_a_stalled_one() {
        let stalled = stalling_server().await;
        let (port, hits) = upstream_server().await;
        let proxy = start(policy(vec![stalled_tls_mirror(stalled), mirror(port)]))
            .await
            .unwrap();
        let t0 = std::time::Instant::now();
        let (status, _, body) = get(&proxy, &proxy.token, "keys", "/a").await;
        let elapsed = t0.elapsed();
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("path=/k/a"), "{body}");
        // One-at-a-time would wait for the 12 s timeout of the stalled path.
        assert!(elapsed < Duration::from_secs(3), "took {elapsed:?}");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        let p = proxy.policy().await;
        assert_eq!(p.current, Some(1));
        // The stalled attempt was dropped, not failed: nothing is learned
        // about it, so it is not pushed back for six hours.
        assert_eq!(
            p.memory.order("test", &p.list.paths, &|_| true, 2),
            vec![1, 0]
        );
        assert!(
            !p.memory.networks["test"].failed_at_ms.contains_key(&0),
            "a dropped attempt is not a failure"
        );
    }

    #[tokio::test]
    async fn a_request_body_is_sent_once_when_several_paths_connect() {
        let (a, hits_a) = upstream_server().await;
        let (b, hits_b) = upstream_server().await;
        let mut p = policy(vec![mirror(a), mirror(b)]);
        // Both connect at once; only the winner may carry the request.
        p.race = Race {
            delay_ms: 10,
            max_parallel: 2,
        };
        let proxy = start(p).await.unwrap();
        for _ in 0..20 {
            let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .unwrap();
            tokio::spawn(conn);
            let req = Request::builder()
                .method("POST")
                .uri("/v1/send")
                .header(HOST, "127.0.0.1")
                .header(HEADER_TOKEN, &proxy.token)
                .header(HEADER_UPSTREAM, "relay")
                .body(Full::new(Bytes::from_static(b"message")))
                .unwrap();
            let res = sender.send_request(req).await.unwrap();
            assert_eq!(res.status(), StatusCode::OK);
            // Forget the winner so that both paths race again next time.
            proxy.update_policy(|p| p.current = None).await;
        }
        let total = hits_a.load(Ordering::SeqCst) + hits_b.load(Ordering::SeqCst);
        assert_eq!(total, 20, "every request reached exactly one server once");
    }

    #[tokio::test]
    async fn sequential_race_tries_one_path_at_a_time() {
        let stalled = stalling_server().await;
        let (port, hits) = upstream_server().await;
        let mut p = policy(vec![stalled_tls_mirror(stalled), mirror(port)]);
        p.race = Race::SEQUENTIAL;
        let proxy = start(p).await.unwrap();
        let token = proxy.token.clone();
        let port_proxy = proxy.port;
        let pending = tokio::spawn(async move {
            let stream = TcpStream::connect(("127.0.0.1", port_proxy)).await.unwrap();
            let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
                .await
                .unwrap();
            tokio::spawn(conn);
            let req = Request::builder()
                .uri("/a")
                .header(HOST, "127.0.0.1")
                .header(HEADER_TOKEN, token)
                .header(HEADER_UPSTREAM, "keys")
                .body(Empty::<Bytes>::new())
                .unwrap();
            let _ = sender.send_request(req).await;
        });
        tokio::time::sleep(Duration::from_millis(1_000)).await;
        assert_eq!(
            hits.load(Ordering::SeqCst),
            0,
            "the second path must wait for the first to time out"
        );
        pending.abort();
    }

    #[test]
    fn race_settings_are_clamped() {
        let wild = Race {
            delay_ms: 0,
            max_parallel: 1_000,
        };
        assert_eq!(wild.delay(), Duration::from_millis(RACE_DELAY_MIN_MS));
        assert_eq!(wild.parallel(), RACE_PARALLEL_MAX);
        let zero = Race {
            delay_ms: u64::MAX,
            max_parallel: 0,
        };
        assert_eq!(zero.delay(), Duration::from_millis(RACE_DELAY_MAX_MS));
        assert_eq!(zero.parallel(), 1);
    }

    /// A stand-in for a Tor client: opens a plain TCP connection and counts.
    struct FakeTor {
        hits: Arc<AtomicUsize>,
        bridges: Arc<std::sync::Mutex<Vec<Vec<String>>>>,
    }

    impl crate::tor::TorConnector for FakeTor {
        fn connect<'a>(&'a self, host: &'a str, port: u16) -> crate::tor::ConnectFuture<'a> {
            Box::pin(async move {
                self.hits.fetch_add(1, Ordering::SeqCst);
                let s = TcpStream::connect((host, port))
                    .await
                    .map_err(|e| e.to_string())?;
                Ok(Box::new(s) as Box<dyn crate::tor::TorStream>)
            })
        }

        fn state(&self) -> crate::tor::TorState {
            crate::tor::TorState::Ready
        }

        fn set_bridges(&self, bridges: &[String]) {
            self.bridges.lock().unwrap().push(bridges.to_vec());
        }
    }

    // The connector is process-wide, so every case that touches it lives in
    // this one test.
    #[tokio::test]
    async fn tor_path_uses_the_installed_connector_only_when_allowed() {
        let (port, hits) = upstream_server().await;
        let mut p = policy(vec![PathSpec::Tor]);
        p.list.logical = Some(Logical {
            keys: format!("http://127.0.0.1:{port}/k"),
            relay: format!("http://127.0.0.1:{port}/r"),
        });
        p.allow_tor = true;
        let proxy = start(p).await.unwrap();

        // No connector installed: the path fails and nothing is sent.
        crate::tor::uninstall();
        let (status, _, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY);
        assert_eq!(hits.load(Ordering::SeqCst), 0);

        // Installed: the request goes through it, and the path is reported.
        let tor_hits = Arc::new(AtomicUsize::new(0));
        let received = Arc::new(std::sync::Mutex::new(Vec::new()));
        crate::tor::install(Arc::new(FakeTor {
            hits: tor_hits.clone(),
            bridges: received.clone(),
        }));
        assert_eq!(crate::tor::state(), Some(crate::tor::TorState::Ready));
        let (status, via, body) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(via.as_deref(), Some("tor"));
        assert!(body.contains("path=/k/a"), "{body}");
        assert_eq!(tor_hits.load(Ordering::SeqCst), 1);

        // Not allowed by the application: Tor is never touched.
        proxy.update_policy(|p| p.allow_tor = false).await;
        let (status, _, _) = get(&proxy, &proxy.token, "keys", "/b").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(tor_hits.load(Ordering::SeqCst), 1);

        // Bridges from a new list reach the connector. Other tests start
        // proxies concurrently and reset the list's bridges, so look for
        // ours among everything the connector received.
        let line =
            "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
        proxy
            .update_policy(|p| p.list.tor_bridges = vec![line.to_string()])
            .await;
        assert!(
            received
                .lock()
                .unwrap()
                .iter()
                .any(|b| b == &vec![line.to_string()]),
            "the connector got the list's bridges"
        );

        assert!(crate::tor::uninstall());
        assert_eq!(crate::tor::state(), None);
    }

    #[tokio::test]
    async fn stop_closes_the_listener() {
        let (port, _) = upstream_server().await;
        let mut proxy = start(policy(vec![mirror(port)])).await.unwrap();
        let p = proxy.port;
        proxy.stop();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(("127.0.0.1", p)).await.is_err());
    }

    /// A server on loopback that hands every connection to `behaviour`.
    async fn raw_server<F, Fut>(behaviour: F) -> u16
    where
        F: Fn(TcpStream) -> Fut + Send + Sync + 'static,
        Fut: std::future::Future<Output = ()> + Send + 'static,
    {
        let listener = TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let port = listener.local_addr().unwrap().port();
        let behaviour = Arc::new(behaviour);
        tokio::spawn(async move {
            while let Ok((stream, _)) = listener.accept().await {
                tokio::spawn(behaviour(stream));
            }
        });
        port
    }

    /// Reads whatever arrives first, answers with `reply` (if any), then
    /// keeps the connection open without a word.
    async fn answer(mut stream: TcpStream, reply: Option<&'static [u8]>, delay: Duration) {
        let mut buf = [0u8; 4096];
        let _ = stream.read(&mut buf).await;
        tokio::time::sleep(delay).await;
        if let Some(reply) = reply {
            let _ = stream.write_all(reply).await;
        }
        tokio::time::sleep(Duration::from_secs(30)).await;
    }

    const OK_REPLY: &[u8] = b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\nConnection: close\r\n\r\nok";

    #[tokio::test]
    async fn a_path_that_accepts_and_stays_silent_is_abandoned_after_the_response_timeout() {
        let (port, _) = upstream_server().await;
        let silent = raw_server(|s| answer(s, None, Duration::ZERO)).await;
        let mut p = policy(vec![mirror(silent), mirror(port)]);
        p.response_timeout_ms = Some(1_000);
        let proxy = start(p).await.unwrap();
        let started = std::time::Instant::now();
        let (status, _, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::GATEWAY_TIMEOUT);
        assert!(started.elapsed() < Duration::from_secs(5));
        assert_eq!(proxy.policy().await.current, None);
        let (status, _, body) = get(&proxy, &proxy.token, "keys", "/b").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("path=/k/b"), "{body}");
        assert_eq!(proxy.policy().await.current, Some(1));
    }

    #[tokio::test]
    async fn a_small_request_body_is_timed_too() {
        let silent = raw_server(|s| answer(s, None, Duration::ZERO)).await;
        let mut p = policy(vec![mirror(silent)]);
        p.response_timeout_ms = Some(1_000);
        let proxy = start(p).await.unwrap();
        let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .method("POST")
            .uri("/send")
            .header(HOST, "127.0.0.1")
            .header(HEADER_TOKEN, proxy.token.as_str())
            .header(HEADER_UPSTREAM, "keys")
            .body(Full::new(Bytes::from_static(b"{\"message\":1}")))
            .unwrap();
        let res = tokio::time::timeout(Duration::from_secs(5), sender.send_request(req))
            .await
            .expect("the proxy answers within the timeout")
            .unwrap();
        assert_eq!(res.status(), StatusCode::GATEWAY_TIMEOUT);
    }

    #[tokio::test]
    async fn a_large_upload_is_not_cut_short_by_the_response_timeout() {
        // The server reads slowly: the upload takes longer than the timeout,
        // and the answer comes once all of it has arrived.
        let slow_reader = raw_server(|mut s| async move {
            let mut total = 0;
            let mut buf = [0u8; 16 * 1024];
            while total < 2_000_000 {
                match s.read(&mut buf).await {
                    Ok(0) | Err(_) => return,
                    Ok(n) => total += n,
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
            let _ = s.write_all(OK_REPLY).await;
        })
        .await;
        let mut p = policy(vec![mirror(slow_reader)]);
        p.response_timeout_ms = Some(1_000);
        let proxy = start(p).await.unwrap();
        let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let req = Request::builder()
            .method("POST")
            .uri("/upload")
            .header(HOST, "127.0.0.1")
            .header(HEADER_TOKEN, proxy.token.as_str())
            .header(HEADER_UPSTREAM, "keys")
            .body(Full::new(Bytes::from(vec![b'x'; 2_000_000])))
            .unwrap();
        let started = std::time::Instant::now();
        let res = sender.send_request(req).await.unwrap();
        assert_eq!(res.status(), StatusCode::OK);
        assert!(
            started.elapsed() > Duration::from_millis(1_000),
            "the upload was slow"
        );
    }

    #[tokio::test]
    async fn a_gateway_error_does_not_make_a_path_current() {
        let (port, _) = upstream_server().await;
        let gateway = raw_server(|s| {
            answer(
                s,
                Some(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                Duration::ZERO,
            )
        })
        .await;
        let proxy = start(policy(vec![mirror(gateway), mirror(port)]))
            .await
            .unwrap();
        let (status, via, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::BAD_GATEWAY, "passed on as it is");
        assert_eq!(via.as_deref(), Some("mirror"));
        assert_eq!(proxy.policy().await.current, None);
        let (status, _, body) = get(&proxy, &proxy.token, "keys", "/b").await;
        assert_eq!(status, StatusCode::OK);
        assert!(body.contains("path=/k/b"), "{body}");
    }

    #[tokio::test]
    async fn a_server_error_still_counts_as_a_working_path() {
        let unavailable = raw_server(|s| {
            answer(
                s,
                Some(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"),
                Duration::ZERO,
            )
        })
        .await;
        let proxy = start(policy(vec![mirror(unavailable)])).await.unwrap();
        let (status, _, _) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
        assert_eq!(proxy.policy().await.current, Some(0));
    }

    #[tokio::test]
    async fn a_client_breaking_off_its_upload_does_not_fail_the_path() {
        // Reads everything and never answers.
        let sink = raw_server(|mut s| async move {
            let mut buf = [0u8; 4096];
            while matches!(s.read(&mut buf).await, Ok(n) if n > 0) {}
        })
        .await;
        let proxy = start(policy(vec![mirror(sink)])).await.unwrap();
        let mut client = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let head = format!(
            "POST /up HTTP/1.1\r\nHost: 127.0.0.1\r\n{HEADER_TOKEN}: {}\r\n{HEADER_UPSTREAM}: keys\r\nContent-Length: 100000\r\n\r\n",
            proxy.token
        );
        client.write_all(head.as_bytes()).await.unwrap();
        client.write_all(&[b'x'; 1_000]).await.unwrap();
        tokio::time::sleep(Duration::from_millis(200)).await;
        drop(client);
        tokio::time::sleep(Duration::from_millis(500)).await;
        let memory = proxy.policy().await.memory;
        assert!(
            memory
                .networks
                .get("test")
                .is_none_or(|m| m.failed_at_ms.is_empty()),
            "{memory:?}"
        );
    }

    #[tokio::test]
    async fn an_outcome_is_not_recorded_after_the_policy_changed() {
        let slow = raw_server(|s| answer(s, Some(OK_REPLY), Duration::from_millis(400))).await;
        let proxy = Arc::new(start(policy(vec![mirror(slow)])).await.unwrap());
        let request = {
            let proxy = proxy.clone();
            tokio::spawn(async move { get(&proxy, &proxy.token, "keys", "/a").await })
        };
        tokio::time::sleep(Duration::from_millis(100)).await;
        proxy.update_policy(|p| p.network_id = "cell".into()).await;
        assert_eq!(request.await.unwrap().0, StatusCode::OK);
        let p = proxy.policy().await;
        assert_eq!(p.current, None, "the success belongs to the old network");
        assert!(p.memory.networks.is_empty(), "{:?}", p.memory);
    }

    #[tokio::test]
    async fn stopping_closes_open_connections() {
        let (port, _) = upstream_server().await;
        let mut proxy = start(policy(vec![mirror(port)])).await.unwrap();
        let stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let (mut sender, conn) = hyper::client::conn::http1::handshake(TokioIo::new(stream))
            .await
            .unwrap();
        tokio::spawn(conn);
        let request = |path: &str| {
            Request::builder()
                .uri(path)
                .header(HOST, "127.0.0.1")
                .header(HEADER_TOKEN, proxy.token.as_str())
                .header(HEADER_UPSTREAM, "keys")
                .body(Empty::<Bytes>::new())
                .unwrap()
        };
        let first = sender.send_request(request("/a")).await.unwrap();
        assert_eq!(first.status(), StatusCode::OK);
        let _ = first.into_body().collect().await;
        let second = request("/b");
        proxy.stop();
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            sender.send_request(second).await.is_err(),
            "a kept-alive connection must not outlive the proxy"
        );
    }

    #[tokio::test]
    async fn responses_vary_on_the_service() {
        let (port, _) = upstream_server().await;
        let proxy = start(policy(vec![mirror(port)])).await.unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let req = format!(
            "GET /a HTTP/1.1\r\nHost: 127.0.0.1\r\n{HEADER_TRANSPORT_TOKEN}: {}\r\n{HEADER_SERVICE}: keys\r\nConnection: close\r\n\r\n",
            proxy.token
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut response = String::new();
        stream.read_to_string(&mut response).await.unwrap();
        let response = response.to_lowercase();
        assert!(
            response.contains(&format!("vary: {HEADER_SERVICE}")),
            "{response}"
        );
        assert!(
            response.contains(&format!("vary: {HEADER_UPSTREAM}")),
            "{response}"
        );
    }

    #[tokio::test]
    async fn ipv6_literal_base_urls_work() {
        let Ok(listener) = TcpListener::bind((std::net::Ipv6Addr::LOCALHOST, 0)).await else {
            return; // No IPv6 loopback on this machine.
        };
        let port = listener.local_addr().unwrap().port();
        tokio::spawn(async move {
            while let Ok((mut s, _)) = listener.accept().await {
                tokio::spawn(async move {
                    let mut buf = [0u8; 4096];
                    let n = s.read(&mut buf).await.unwrap_or(0);
                    let head = String::from_utf8_lossy(&buf[..n]).to_lowercase();
                    let host = head
                        .lines()
                        .find_map(|l| l.strip_prefix("host: "))
                        .unwrap_or("")
                        .to_string();
                    let reply = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{host}",
                        host.len()
                    );
                    let _ = s.write_all(reply.as_bytes()).await;
                });
            }
        });
        let v6 = PathSpec::Mirror {
            keys: Some(format!("http://[::1]:{port}/k")),
            relay: Some(format!("http://[::1]:{port}/r")),
            targets: Default::default(),
            ip: None,
        };
        let proxy = start(policy(vec![v6])).await.unwrap();
        let (status, _, body) = get(&proxy, &proxy.token, "keys", "/a").await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body, format!("[::1]:{port}"));
    }
}
