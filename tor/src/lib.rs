// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Tor for SeyLock's `tor` path, built on the Tor Project's
//! [arti](https://gitlab.torproject.org/tpo/core/arti).
//!
//! The core `seylock` crate has no Tor client: this crate supplies one by
//! implementing [`seylock::tor::TorConnector`]. Install it once and the `tor`
//! path starts working for every request the application allows to use it:
//!
//! ```no_run
//! # async fn demo() -> Result<(), String> {
//! let settings = seylock_tor::TorSettings {
//!     state_dir: "/app/data/tor/state".into(),
//!     cache_dir: "/app/data/tor/cache".into(),
//!     bridges: vec![],
//!     transports: vec![],
//! };
//! let connector = seylock_tor::ArtiConnector::start(&settings)?;
//! seylock::tor::install(connector);
//! # Ok(()) }
//! ```
//!
//! Tor bootstraps in the background from the moment the connector starts; a
//! first request waits for it. A cold start downloads the directory (about
//! 40 MB on disk) and takes 10 to 20 seconds; later starts reuse the cache
//! and take about a second.
//!
//! **Bridges.** Censored networks often block the public Tor relays. Bridge
//! lines (`obfs4 ...`, `webtunnel ...`, `snowflake ...`) go into
//! [`TorSettings::bridges`]. Their pluggable transports must already be
//! running and listening on a local SOCKS port, as IPtProxy provides on
//! Android and iOS (where an app cannot start other processes); each is
//! listed in [`TorSettings::transports`].

#![deny(missing_docs)]
#![warn(rust_2018_idioms)]

use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use arti_client::config::pt::TransportConfigBuilder;
use arti_client::config::{BridgeConfigBuilder, Reconfigure, TorClientConfigBuilder};
use arti_client::{HasKind as _, TorClient, TorClientConfig};
use futures::StreamExt as _;
use serde::{Deserialize, Serialize};
use seylock::tor::{ConnectFuture, TorConnector, TorState, TorStream};
use tor_rtcompat::PreferredRuntime;

pub mod ffi;

// Compiles the Rust example in README.md as a doctest.
#[cfg(doctest)]
#[doc = include_str!("../README.md")]
struct ReadmeDoctests;

/// Where Tor keeps its files, and how it reaches the network.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TorSettings {
    /// Directory for Tor's persistent state (guards, timeouts). Created if
    /// missing. Must be private to the application.
    pub state_dir: String,
    /// Directory for the Tor directory cache, about 40 MB. Created if missing.
    pub cache_dir: String,
    /// Bridge lines, as published by the Tor Project or a bridge operator.
    /// Empty means connecting to the public Tor network directly.
    #[serde(default)]
    pub bridges: Vec<String>,
    /// Pluggable transports already listening locally, which the bridges use.
    #[serde(default)]
    pub transports: Vec<LocalTransport>,
}

/// A pluggable transport running outside this library, listening as a SOCKS
/// proxy on a local port (for example one started by IPtProxy).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalTransport {
    /// Transport names it provides, matching the first word of the bridge
    /// lines: `obfs4`, `webtunnel`, `snowflake`, ...
    pub protocols: Vec<String>,
    /// Where it listens, for example `127.0.0.1:47351`.
    pub socks_addr: SocketAddr,
}

impl TorSettings {
    /// Builds arti's configuration. Fails on a malformed bridge line or
    /// transport name, before anything touches the network.
    pub fn to_config(&self) -> Result<TorClientConfig, String> {
        let mut b = TorClientConfigBuilder::from_directories(&self.state_dir, &self.cache_dir);
        for line in &self.bridges {
            let bridge: BridgeConfigBuilder = line
                .parse()
                .map_err(|e| format!("bridge line {line:?}: {e}"))?;
            b.bridges().bridges().push(bridge);
        }
        for t in &self.transports {
            let mut tb = TransportConfigBuilder::default();
            let protocols = t
                .protocols
                .iter()
                .map(|p| p.parse().map_err(|e| format!("transport {p:?}: {e:?}")))
                .collect::<Result<Vec<_>, String>>()?;
            tb.protocols(protocols);
            tb.proxy_addr(t.socks_addr);
            b.bridges().transports().push(tb);
        }
        b.build().map_err(|e| format!("tor configuration: {e}"))
    }
}

/// A Tor client for the `tor` path.
pub struct ArtiConnector {
    client: Arc<TorClient<PreferredRuntime>>,
    state: Arc<Mutex<TorState>>,
    /// The application's own settings; bridges from the signed list are
    /// added to these, never replace them.
    base: TorSettings,
}

impl ArtiConnector {
    /// Creates the client and starts bootstrapping in the background, on the
    /// same runtime as the SeyLock proxy. Returns at once.
    pub fn start(settings: &TorSettings) -> Result<Arc<Self>, String> {
        Self::start_on(settings, &seylock::runtime::handle())
    }

    /// Like [`ArtiConnector::start`], on a runtime of the caller's choosing.
    pub fn start_on(
        settings: &TorSettings,
        runtime: &tokio::runtime::Handle,
    ) -> Result<Arc<Self>, String> {
        let connector = Self::create(settings, runtime)?;
        let client = connector.client.clone();
        let state = connector.state.clone();

        // Progress, for the runtime status.
        let mut events = client.bootstrap_events();
        let progress = state.clone();
        runtime.spawn(async move {
            while let Some(status) = events.next().await {
                let percent = (status.as_frac().clamp(0.0, 1.0) * 100.0) as u8;
                let mut s = progress.lock().unwrap_or_else(|e| e.into_inner());
                if matches!(*s, TorState::Bootstrapping { .. }) {
                    *s = if status.ready_for_traffic() {
                        TorState::Ready
                    } else {
                        TorState::Bootstrapping { percent }
                    };
                }
            }
        });

        // Bootstrap now rather than on the first request.
        let boot_client = client.clone();
        let outcome = state.clone();
        runtime.spawn(async move {
            let result = boot_client.bootstrap().await;
            let mut s = outcome.lock().unwrap_or_else(|e| e.into_inner());
            *s = match result {
                Ok(()) => TorState::Ready,
                Err(e) => {
                    tracing::info!(target: "seylock_tor", "bootstrap failed: {e}");
                    TorState::Failed {
                        reason: e.kind().to_string(),
                    }
                }
            };
        });

        Ok(Arc::new(connector))
    }

    /// Creates the client without starting it. Nothing touches the network
    /// until a stream is opened.
    ///
    /// The bridges of SeyLock's current list are included from the start: if
    /// the list says to use bridges, Tor must never first reach the public
    /// relays directly, which a censor can see.
    fn create(settings: &TorSettings, runtime: &tokio::runtime::Handle) -> Result<Self, String> {
        // arti uses rustls and needs a process-wide crypto provider. SeyLock
        // already uses `ring`; installing it again is harmless.
        let _ = rustls::crypto::ring::default_provider().install_default();
        tighten_lock_files(&settings.state_dir, &settings.cache_dir);
        let config = with_list_bridges(settings, &seylock::tor::list_bridges()).to_config()?;
        let _guard = runtime.enter();
        let client = TorClient::builder()
            .config(config)
            .create_unbootstrapped()
            .map_err(|e| format!("tor: {e}"))?;
        Ok(ArtiConnector {
            client,
            state: Arc::new(Mutex::new(TorState::Bootstrapping { percent: 0 })),
            base: settings.clone(),
        })
    }

    /// Reconfigures the running client with the application's own bridges
    /// plus `list_bridges`. Bridges whose transport the application has not
    /// started are left out: one unusable line must not cost the others.
    fn apply_bridges(&self, list_bridges: &[String]) -> Result<usize, String> {
        let settings = with_list_bridges(&self.base, list_bridges);
        let added = settings.bridges.len() - self.base.bridges.len();
        let config = settings.to_config()?;
        self.client
            .reconfigure(&config, Reconfigure::WarnOnFailures)
            .map_err(|e| format!("tor reconfigure: {e}"))?;
        Ok(added)
    }
}

/// arti creates its lock files (`state/state.lock`, `dir.lock` in the cache)
/// with the process's default permissions. Under a permissive umask
/// (`adb shell` uses 0000) they are writable by everyone, and on the next
/// start arti's permission check refuses the directory. The lock files are
/// empty and only serve as locks, so narrowing them to the owner is safe;
/// arti's checks on everything else stay in force.
#[cfg(unix)]
fn tighten_lock_files(state_dir: &str, cache_dir: &str) {
    use std::os::unix::fs::PermissionsExt as _;
    let state = std::path::Path::new(state_dir);
    for dir in [state.to_path_buf(), state.join("state"), cache_dir.into()] {
        let Ok(entries) = std::fs::read_dir(&dir) else {
            continue;
        };
        for entry in entries.flatten() {
            let path = entry.path();
            if path.extension().is_some_and(|e| e == "lock")
                && let Ok(meta) = std::fs::symlink_metadata(&path)
                && meta.file_type().is_file()
                && meta.permissions().mode() & 0o077 != 0
            {
                let _ = std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600));
            }
        }
    }
}

#[cfg(not(unix))]
fn tighten_lock_files(_state_dir: &str, _cache_dir: &str) {}

/// The application's settings plus the list's bridges that can be used with
/// the transports the application runs.
fn with_list_bridges(base: &TorSettings, list_bridges: &[String]) -> TorSettings {
    let available: Vec<&str> = base
        .transports
        .iter()
        .flat_map(|t| t.protocols.iter().map(String::as_str))
        .collect();
    let mut settings = base.clone();
    for line in list_bridges {
        if !settings.bridges.contains(line) && transport_available(line, &available) {
            settings.bridges.push(line.clone());
        }
    }
    settings
}

/// Whether a bridge line can be used with the transports at hand. A line
/// starting with an address is a plain bridge and needs no transport; any
/// other first word names one.
fn transport_available(line: &str, available: &[&str]) -> bool {
    let first = line.split_whitespace().next().unwrap_or("");
    first.parse::<SocketAddr>().is_ok() || available.contains(&first)
}

impl TorConnector for ArtiConnector {
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> ConnectFuture<'a> {
        Box::pin(async move {
            // The name is resolved by the exit relay, not locally, so a
            // censored DNS resolver never sees it.
            let stream = self
                .client
                .connect((host, port))
                .await
                .map_err(|e| format!("tor: {}", e.kind()))?;
            Ok(Box::new(stream) as Box<dyn TorStream>)
        })
    }

    fn state(&self) -> TorState {
        self.state.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    fn set_bridges(&self, bridges: &[String]) {
        match self.apply_bridges(bridges) {
            Ok(added) => {
                tracing::info!(target: "seylock_tor", "bridges from the list in use: {added}")
            }
            // The previous configuration stays in force.
            Err(e) => tracing::info!(target: "seylock_tor", "list bridges not applied: {e}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> TorSettings {
        TorSettings {
            state_dir: "/tmp/seylock-tor-test/state".into(),
            cache_dir: "/tmp/seylock-tor-test/cache".into(),
            bridges: vec![],
            transports: vec![],
        }
    }

    #[test]
    fn plain_settings_build_a_config() {
        settings().to_config().unwrap();
    }

    #[test]
    fn bridges_with_a_local_transport_build_a_config() {
        let mut s = settings();
        s.bridges = vec![
            "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0"
                .into(),
        ];
        s.transports = vec![LocalTransport {
            protocols: vec!["obfs4".into()],
            socks_addr: "127.0.0.1:47351".parse().unwrap(),
        }];
        s.to_config().unwrap();
    }

    #[test]
    fn a_malformed_bridge_line_is_refused_before_any_network_use() {
        let mut s = settings();
        s.bridges = vec!["obfs4 not-an-address".into()];
        let err = s.to_config().unwrap_err();
        assert!(err.contains("bridge line"), "{err}");
    }

    const OBFS4: &str =
        "obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0";
    const WEBTUNNEL: &str = "webtunnel [2001:db8::1]:443 0123456789ABCDEF0123456789ABCDEF01234567 url=https://example.org/path";
    const PLAIN: &str = "192.0.2.7:9001 0123456789ABCDEF0123456789ABCDEF01234567";

    #[test]
    fn only_bridges_with_a_running_transport_are_used() {
        let available = ["obfs4"];
        assert!(transport_available(OBFS4, &available));
        assert!(!transport_available(WEBTUNNEL, &available));
        assert!(
            transport_available(PLAIN, &available),
            "plain bridges need no transport"
        );
        assert!(!transport_available("", &available));
    }

    #[test]
    fn list_bridges_reconfigure_a_client_without_touching_the_network() {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let dir = std::env::temp_dir().join(format!("seylock-tor-unit-{}", std::process::id()));
        let mut s = settings();
        s.state_dir = dir.join("state").display().to_string();
        s.cache_dir = dir.join("cache").display().to_string();
        s.transports = vec![LocalTransport {
            protocols: vec!["obfs4".into()],
            socks_addr: "127.0.0.1:47351".parse().unwrap(),
        }];
        let c = ArtiConnector::create(&s, rt.handle()).unwrap();
        // The obfs4 and the plain bridge are used; webtunnel has no transport.
        let lines = [OBFS4.to_string(), WEBTUNNEL.to_string(), PLAIN.to_string()];
        assert_eq!(c.apply_bridges(&lines), Ok(2));
        // A list without bridges goes back to the application's own.
        assert_eq!(c.apply_bridges(&[]), Ok(0));
        // A malformed line is refused and the previous configuration stays.
        assert!(c.apply_bridges(&["obfs4 not-an-address".into()]).is_err());
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(unix)]
    #[test]
    fn world_writable_lock_files_are_narrowed_to_the_owner() {
        use std::os::unix::fs::PermissionsExt as _;
        let dir = std::env::temp_dir().join(format!("seylock-tor-lock-{}", std::process::id()));
        let state = dir.join("state");
        let cache = dir.join("cache");
        std::fs::create_dir_all(state.join("state")).unwrap();
        std::fs::create_dir_all(&cache).unwrap();
        let state_lock = state.join("state").join("state.lock");
        let dir_lock = cache.join("dir.lock");
        let other = cache.join("dir.sqlite3");
        for f in [&state_lock, &dir_lock, &other] {
            std::fs::write(f, b"").unwrap();
            std::fs::set_permissions(f, std::fs::Permissions::from_mode(0o666)).unwrap();
        }
        tighten_lock_files(state.to_str().unwrap(), cache.to_str().unwrap());
        let mode = |p: &std::path::Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&state_lock), 0o600);
        assert_eq!(mode(&dir_lock), 0o600);
        assert_eq!(mode(&other), 0o666, "only lock files are touched");
        // Missing directories are fine.
        tighten_lock_files("/nonexistent/a", "/nonexistent/b");
        let _ = std::fs::remove_dir_all(dir);
    }

    #[test]
    fn settings_json_shape() {
        let json = r#"{"state_dir":"/s","cache_dir":"/c",
            "bridges":["obfs4 192.0.2.1:443 0123456789ABCDEF0123456789ABCDEF01234567 cert=AAAA iat-mode=0"],
            "transports":[{"protocols":["obfs4"],"socks_addr":"127.0.0.1:47351"}]}"#;
        let s: TorSettings = serde_json::from_str(json).unwrap();
        assert_eq!(s.transports[0].socks_addr.port(), 47351);
        // Bridges and transports may be left out.
        let s: TorSettings =
            serde_json::from_str(r#"{"state_dir":"/s","cache_dir":"/c"}"#).unwrap();
        assert!(s.bridges.is_empty() && s.transports.is_empty());
    }
}
