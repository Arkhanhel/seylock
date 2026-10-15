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
//! WebSocket: a request with `Upgrade: websocket` becomes, after a 101
//! response, two raw streams copied in opposite directions.
//!
//! Paths race at the connection stage, in the manner of Happy Eyeballs
//! (RFC 8305): the next path starts if the previous one has not connected
//! within [`Race::delay_ms`], or at once if it failed. The first connection to
//! complete (TCP and, for `https`, the TLS handshake with certificate
//! verification) carries the request; the others are dropped. Only
//! connections race, never requests: a request body is sent exactly once.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http::header::{HOST, HeaderName, HeaderValue};
use http::{Request, Response, StatusCode, Uri};
use http_body_util::{BodyExt, Empty, Full, combinators::BoxBody};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, oneshot};
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

/// Bounds applied to [`Race`] values, so a bad setting cannot turn the proxy
/// into a connection flood or make it wait for minutes.
const RACE_DELAY_MIN_MS: u64 = 10;
const RACE_DELAY_MAX_MS: u64 = 5_000;
const RACE_PARALLEL_MAX: usize = 8;

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
#[derive(Clone, Debug)]
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
}

impl Policy {
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
pub struct ProxyHandle {
    /// TCP port on `127.0.0.1` the proxy listens on.
    pub port: u16,
    /// Random token that requests must present in `x-transport-token` (or the
    /// format 1 `x-secretly-proxy-token`).
    pub token: String,
    policy: Arc<Mutex<Policy>>,
    shutdown: Option<oneshot::Sender<()>>,
}

impl ProxyHandle {
    /// Modifies the policy in place. The change applies to requests that start
    /// afterwards.
    pub async fn update_policy(&self, f: impl FnOnce(&mut Policy)) {
        let mut p = self.policy.lock().await;
        f(&mut p);
    }

    /// Returns a snapshot of the current policy.
    pub async fn policy(&self) -> Policy {
        self.policy.lock().await.clone()
    }

    /// Stops accepting connections. Repeated calls have no effect.
    pub fn stop(&mut self) {
        if let Some(tx) = self.shutdown.take() {
            let _ = tx.send(());
        }
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
    tls: TlsConnector,
    now_ms: Arc<dyn Fn() -> i64 + Send + Sync>,
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
    let policy = Arc::new(Mutex::new(policy));
    let shared = Shared {
        token: token.clone(),
        policy: policy.clone(),
        tls: tls_connector(),
        now_ms,
    };
    let (tx, mut rx) = oneshot::channel::<()>();
    tokio::spawn(async move {
        loop {
            tokio::select! {
                _ = &mut rx => break,
                accepted = listener.accept() => {
                    let Ok((stream, peer)) = accepted else { continue };
                    if !peer.ip().is_loopback() {
                        continue;
                    }
                    let shared = shared.clone();
                    tokio::spawn(async move {
                        let io = TokioIo::new(stream);
                        let service = hyper::service::service_fn(move |req| {
                            let shared = shared.clone();
                            async move { Ok::<_, hyper::Error>(handle(shared, req).await) }
                        });
                        let conn = hyper::server::conn::http1::Builder::new()
                            .serve_connection(io, service)
                            .with_upgrades();
                        if let Err(e) = conn.await {
                            tracing::debug!(target: "seylock", "client conn: {e}");
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
        shutdown: Some(tx),
    })
}

fn tls_connector() -> TlsConnector {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    let config = ClientConfig::builder()
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

    let policy = shared.policy.lock().await.clone();
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
    match race_connect(&shared, candidates, policy.race, now).await {
        Ok((winner, stream)) => {
            let served = Served {
                path_index: winner.idx,
                kind: winner.spec.kind(),
            };
            // A path counts as working only once a request through it has
            // actually succeeded. Counting the connection alone let a mirror
            // that drops every request right after TLS stay current forever,
            // and the proxy never moved on.
            let (response, outcome) = forward(req, stream, &winner.target, served).await;
            if let Some(ok) = outcome {
                shared.policy.lock().await.note(winner.idx, ok, now);
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
                    shared.policy.lock().await.note(candidate.idx, false, now_ms);
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
        let host = uri.host()?.to_string();
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
            self.connect_ip.as_deref().unwrap_or(&self.host),
            self.port
        )
    }
}

/// A stream to the server: any `AsyncRead + AsyncWrite`.
type Upstream_ = Box<dyn AsyncReadWrite>;

trait AsyncReadWrite: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> AsyncReadWrite for T {}

async fn connect(shared: &Shared, spec: &PathSpec, target: &Target) -> Result<Upstream_, String> {
    let timeout = match spec.kind() {
        PathKind::Direct | PathKind::Ip => CONNECT_TIMEOUT_CHEAP,
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
        PathSpec::Tor => Err("tor: not built in this version".to_string()),
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
    mut req: Request<Incoming>,
    stream: Upstream_,
    target: &Target,
    served: Served,
) -> (Response<OutBody>, Option<bool>) {
    // Re-address the request to the target: the path gets the mirror's
    // prefix and `Host` becomes the target's name. Request signatures that
    // applications add must not cover the host for this to be safe; the
    // Secretly protocol's do not.
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
        target.host.clone()
    } else {
        format!("{}:{}", target.host, target.port)
    };
    match HeaderValue::from_str(&host_value) {
        Ok(v) => {
            req.headers_mut().insert(HOST, v);
        }
        Err(_) => return (reply(StatusCode::BAD_REQUEST, "host"), None),
    }

    let is_upgrade = req
        .headers()
        .get(http::header::UPGRADE)
        .map(|v| v.to_str().unwrap_or("").eq_ignore_ascii_case("websocket"))
        .unwrap_or(false);

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

    let mut response = match sender.send_request(req).await {
        Ok(r) => r,
        Err(e) => {
            tracing::debug!(target: "seylock", "upstream request: {e}");
            return (
                reply(StatusCode::BAD_GATEWAY, "upstream request"),
                Some(false),
            );
        }
    };
    if let Ok(v) = HeaderValue::from_str(served.kind.as_str()) {
        let headers = response.headers_mut();
        headers.insert(HeaderName::from_static(HEADER_TRANSPORT_PATH), v.clone());
        headers.insert(HeaderName::from_static(HEADER_PATH), v);
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
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
        let (parts, _) = response.into_parts();
        return (
            Response::from_parts(parts, Empty::<Bytes>::new().map_err(|e| match e {}).boxed()),
            Some(true),
        );
    }

    let (parts, body) = response.into_parts();
    (Response::from_parts(parts, body.boxed()), Some(true))
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
            },
            memory: PathMemory::default(),
            network_id: "test".into(),
            allow_tor: false,
            allow_socks: false,
            current: None,
            race: Race::default(),
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

    #[tokio::test]
    async fn websocket_upgrade_is_tunnelled() {
        let (port, _) = upstream_server().await;
        let proxy = start(policy(vec![mirror(port)])).await.unwrap();
        let mut stream = TcpStream::connect(("127.0.0.1", proxy.port)).await.unwrap();
        let req = format!(
            "GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\n{HEADER_TOKEN}: {}\r\n{HEADER_UPSTREAM}: relay\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
            proxy.token
        );
        stream.write_all(req.as_bytes()).await.unwrap();
        let mut buf = vec![0u8; 1024];
        let n = stream.read(&mut buf).await.unwrap();
        let head = String::from_utf8_lossy(&buf[..n]).to_string();
        assert!(head.starts_with("HTTP/1.1 101"), "{head}");
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
        assert_eq!(&echo, b"ping-through");
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

    #[tokio::test]
    async fn stop_closes_the_listener() {
        let (port, _) = upstream_server().await;
        let mut proxy = start(policy(vec![mirror(port)])).await.unwrap();
        let p = proxy.port;
        proxy.stop();
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(TcpStream::connect(("127.0.0.1", p)).await.is_err());
    }
}
