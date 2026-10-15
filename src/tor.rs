// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! The hook for the `tor` path.
//!
//! The core library has no Tor client of its own: a Tor implementation brings
//! hundreds of dependencies, and most applications do not want them. A
//! separate crate (`seylock-tor`, built on the Tor Project's `arti`) supplies
//! one by implementing [`TorConnector`] and installing it with [`install`].
//! Until one is installed, the `tor` path fails at once and the next path is
//! tried.
//!
//! The connector only opens a byte stream to a host and port through Tor. TLS
//! to the real server name runs inside that stream, as on the `socks` path,
//! so the exit relay sees neither the requests nor the responses.
//!
//! The `tor` path is still tried only when the application allows it
//! (`allow_tor` in the policy).
//!
//! Bridge lines from the signed list (`tor_bridges`, format 2) reach the
//! connector through [`TorConnector::set_bridges`]: when the proxy starts or
//! its list changes, and when a connector is installed after that.

use std::future::Future;
use std::pin::Pin;
use std::sync::{Arc, RwLock};

use serde::{Deserialize, Serialize};
use tokio::io::{AsyncRead, AsyncWrite};

/// A byte stream opened through Tor.
pub trait TorStream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> TorStream for T {}

/// The future returned by [`TorConnector::connect`].
pub type ConnectFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Box<dyn TorStream>, String>> + Send + 'a>>;

/// What the connector is doing, reported in the runtime status.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TorState {
    /// Fetching the Tor directory and building circuits.
    Bootstrapping {
        /// Progress, 0 to 100.
        percent: u8,
    },
    /// Ready to open streams.
    Ready,
    /// Bootstrapping failed; the connector may retry on its own.
    Failed {
        /// A short reason, safe to show and to log.
        reason: String,
    },
}

/// A Tor client the `tor` path can use.
pub trait TorConnector: Send + Sync + 'static {
    /// Opens a stream to `host:port` through Tor. Waits for bootstrapping if
    /// it has not finished; the proxy bounds the whole attempt with a timeout.
    fn connect<'a>(&'a self, host: &'a str, port: u16) -> ConnectFuture<'a>;

    /// The connector's current state.
    fn state(&self) -> TorState;

    /// Bridge lines from the signed list, replacing those from an earlier
    /// list. An empty slice means the list has none. The connector combines
    /// them with any bridges the application configured itself. The default
    /// ignores them.
    fn set_bridges(&self, bridges: &[String]) {
        let _ = bridges;
    }
}

static CONNECTOR: RwLock<Option<Arc<dyn TorConnector>>> = RwLock::new(None);
static LIST_BRIDGES: RwLock<Vec<String>> = RwLock::new(Vec::new());

/// Installs `connector` for the whole process, replacing any earlier one.
/// Requests that start afterwards use it. It receives the bridges of the
/// current list at once.
pub fn install(connector: Arc<dyn TorConnector>) {
    let bridges = LIST_BRIDGES
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone();
    if !bridges.is_empty() {
        connector.set_bridges(&bridges);
    }
    *CONNECTOR.write().unwrap_or_else(|e| e.into_inner()) = Some(connector);
}

/// Records the bridge lines of the list in use and passes them to the
/// installed connector if they changed. The proxy calls this on start and
/// whenever its list is replaced.
pub fn set_list_bridges(bridges: &[String]) {
    {
        let mut current = LIST_BRIDGES.write().unwrap_or_else(|e| e.into_inner());
        if current.as_slice() == bridges {
            return;
        }
        *current = bridges.to_vec();
    }
    if let Some(connector) = installed() {
        connector.set_bridges(bridges);
    }
}

/// The bridge lines of the list in use. A connector reads them when it is
/// created, so that it never bootstraps directly when the list says to use
/// bridges.
pub fn list_bridges() -> Vec<String> {
    LIST_BRIDGES
        .read()
        .unwrap_or_else(|e| e.into_inner())
        .clone()
}

/// Removes the installed connector. Returns whether one was installed.
pub fn uninstall() -> bool {
    CONNECTOR
        .write()
        .unwrap_or_else(|e| e.into_inner())
        .take()
        .is_some()
}

/// The installed connector, if any.
pub fn installed() -> Option<Arc<dyn TorConnector>> {
    CONNECTOR.read().unwrap_or_else(|e| e.into_inner()).clone()
}

/// The installed connector's state, or `None` if there is none.
pub fn state() -> Option<TorState> {
    installed().map(|c| c.state())
}
