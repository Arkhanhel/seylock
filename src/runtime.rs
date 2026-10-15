// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Background runtime for embedding in an application.
//!
//! A Dart application has no tokio of its own, so the library keeps one runtime
//! per process (two worker threads: a proxy waits on the network rather than
//! computing) and one running proxy. Every call from [`crate::ffi`] is a short
//! `block_on` on that runtime.

use std::sync::{Mutex, OnceLock};

use serde::{Deserialize, Serialize};

use crate::endpoints::EndpointList;
use crate::paths::PathMemory;
use crate::proxy::{self, Policy, ProxyHandle, Race};

static RUNTIME: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
static PROXY: Mutex<Option<ProxyHandle>> = Mutex::new(None);

fn runtime() -> &'static tokio::runtime::Runtime {
    RUNTIME.get_or_init(|| {
        tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .thread_name("seylock")
            .enable_all()
            .build()
            .expect("tokio runtime")
    })
}

/// What the application passes at start-up and on update.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct PolicyInput {
    /// The accepted endpoint list to use.
    pub list: EndpointList,
    /// Path memory saved from an earlier run. Used by [`start`]; [`update`]
    /// ignores it and keeps the memory the running proxy has built up.
    #[serde(default)]
    pub memory: PathMemory,
    /// Opaque identifier of the current network, chosen by the application.
    /// Empty if unknown.
    #[serde(default)]
    pub network_id: String,
    /// Allow `tor` paths. Off by default.
    #[serde(default)]
    pub allow_tor: bool,
    /// Allow `socks` paths. Off by default.
    #[serde(default)]
    pub allow_socks: bool,
    /// How paths race. When the field is absent the proxy tries one path at a
    /// time, as version 0.1 did, so an application built against 0.1 behaves
    /// exactly as before; pass `"race": {}` for the racing defaults.
    #[serde(default = "sequential_race")]
    pub race: Race,
}

fn sequential_race() -> Race {
    Race::SEQUENTIAL
}

impl From<PolicyInput> for Policy {
    fn from(p: PolicyInput) -> Self {
        Policy {
            list: p.list,
            memory: p.memory,
            network_id: p.network_id,
            allow_tor: p.allow_tor,
            allow_socks: p.allow_socks,
            current: None,
            race: p.race,
        }
    }
}

/// A state snapshot for the application: the port, the current path, and the
/// memory the application keeps between runs.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Status {
    /// TCP port on `127.0.0.1` the proxy listens on.
    pub port: u16,
    /// Index into the list's `paths` of the path in use, or `None` if none has
    /// worked yet or the last one failed.
    pub current: Option<usize>,
    /// Kind of the current path (`direct`, `ip`, ...), or `None` if there is no
    /// current path.
    pub current_kind: Option<String>,
    /// Identifier of the current network, as last passed by the application.
    pub network_id: String,
    /// Path memory to persist between runs and pass back at the next start.
    pub memory: PathMemory,
    /// `issued_at_ms` of the list in use, in Unix milliseconds.
    pub issued_at_ms: i64,
}

/// Failure of a runtime call, each with a numeric [`code`](RuntimeError::code)
/// for the C ABI.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RuntimeError {
    /// Code 101. [`start`] was called while a proxy is already running.
    AlreadyStarted,
    /// Code 102. The call needs a running proxy and there is none.
    NotStarted,
    /// Code 103. The loopback listener could not be bound.
    Bind,
}

impl RuntimeError {
    /// Numeric code for the C ABI: 101, 102 or 103.
    pub fn code(self) -> i32 {
        match self {
            RuntimeError::AlreadyStarted => 101,
            RuntimeError::NotStarted => 102,
            RuntimeError::Bind => 103,
        }
    }
}

/// Result of a successful [`start`].
pub struct Started {
    /// TCP port on `127.0.0.1` the proxy listens on.
    pub port: u16,
    /// Token the application must send in `x-transport-token` (or the format
    /// 1 `x-secretly-proxy-token`).
    pub token: String,
}

/// Starts the process-wide proxy. Fails with [`RuntimeError::AlreadyStarted`]
/// if one is running, or [`RuntimeError::Bind`] if the loopback port cannot be
/// bound.
pub fn start(input: PolicyInput) -> Result<Started, RuntimeError> {
    let mut slot = PROXY.lock().unwrap_or_else(|e| e.into_inner());
    if slot.is_some() {
        return Err(RuntimeError::AlreadyStarted);
    }
    let handle = runtime()
        .block_on(proxy::start(input.into()))
        .map_err(|_| RuntimeError::Bind)?;
    let started = Started {
        port: handle.port,
        token: handle.token.clone(),
    };
    *slot = Some(handle);
    Ok(started)
}

/// Stops the proxy. Returns `true` if one was running, `false` otherwise.
pub fn stop() -> bool {
    let mut slot = PROXY.lock().unwrap_or_else(|e| e.into_inner());
    match slot.take() {
        Some(mut h) => {
            h.stop();
            true
        }
        None => false,
    }
}

/// Replaces the list, network and permissions of the running proxy. If the
/// list's `issued_at_ms` differs from the current one, the path memory and
/// current path are reset, because path indices refer to the old list. Fails
/// with [`RuntimeError::NotStarted`] if no proxy is running.
pub fn update(input: PolicyInput) -> Result<(), RuntimeError> {
    let slot = PROXY.lock().unwrap_or_else(|e| e.into_inner());
    let handle = slot.as_ref().ok_or(RuntimeError::NotStarted)?;
    runtime().block_on(handle.update_policy(|p| {
        let same_list = p.list.issued_at_ms == input.list.issued_at_ms;
        p.list = input.list;
        p.network_id = input.network_id;
        p.allow_tor = input.allow_tor;
        p.allow_socks = input.allow_socks;
        p.race = input.race;
        if !same_list {
            // Path indices refer to the old list.
            p.memory = PathMemory::default();
            p.current = None;
        }
    }));
    Ok(())
}

/// Network change: the current path is forgotten, the per-network memory is
/// kept.
pub fn set_network(network_id: &str) -> Result<(), RuntimeError> {
    let slot = PROXY.lock().unwrap_or_else(|e| e.into_inner());
    let handle = slot.as_ref().ok_or(RuntimeError::NotStarted)?;
    let id = network_id.to_string();
    runtime().block_on(handle.update_policy(|p| {
        if p.network_id != id {
            p.network_id = id;
            p.current = None;
        }
    }));
    Ok(())
}

/// Returns a snapshot of the running proxy's state, or
/// [`RuntimeError::NotStarted`] if no proxy is running.
pub fn status() -> Result<Status, RuntimeError> {
    let slot = PROXY.lock().unwrap_or_else(|e| e.into_inner());
    let handle = slot.as_ref().ok_or(RuntimeError::NotStarted)?;
    let port = handle.port;
    let p = runtime().block_on(handle.policy());
    Ok(Status {
        port,
        current: p.current,
        current_kind: p
            .current
            .and_then(|i| p.list.paths.get(i))
            .map(|s| s.kind().as_str().to_string()),
        network_id: p.network_id,
        memory: p.memory,
        issued_at_ms: p.list.issued_at_ms,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::endpoints::{Logical, PathSpec};

    fn input() -> PolicyInput {
        PolicyInput {
            list: EndpointList {
                v: 1,
                issued_at_ms: 5,
                expires_at_ms: i64::MAX / 2,
                logical: Some(Logical {
                    keys: "https://k.invalid".into(),
                    relay: "https://r.invalid".into(),
                }),
                services: Default::default(),
                paths: vec![PathSpec::Direct],
            },
            memory: PathMemory::default(),
            network_id: "wifi:test".into(),
            allow_tor: false,
            allow_socks: false,
            race: Race::SEQUENTIAL,
        }
    }

    #[test]
    fn race_defaults_keep_0_1_behaviour_for_existing_callers() {
        // Applications built against 0.1 do not know the `race` field; for
        // them the proxy must behave as before, one path at a time.
        let json = r#"{"list":{"v":1,"issued_at_ms":1,"expires_at_ms":9,
            "logical":{"keys":"https://k","relay":"https://r"},"paths":[{"kind":"direct"}]}}"#;
        let p: PolicyInput = serde_json::from_str(json).unwrap();
        assert_eq!(p.race, Race::SEQUENTIAL);
        // An empty object turns on the racing defaults; fields may be set.
        let with_race = json.replacen('{', r#"{"race":{},"#, 1);
        let p: PolicyInput = serde_json::from_str(&with_race).unwrap();
        assert_eq!(p.race, Race::default());
        assert_eq!(p.race.max_parallel, 3);
        let tuned = json.replacen('{', r#"{"race":{"delay_ms":400},"#, 1);
        let p: PolicyInput = serde_json::from_str(&tuned).unwrap();
        assert_eq!((p.race.delay_ms, p.race.max_parallel), (400, 3));
    }

    #[test]
    fn start_update_status_stop_lifecycle() {
        // One proxy per process: the test holds global state, so it runs the
        // whole life cycle itself.
        assert!(!stop());
        assert_eq!(status().err(), Some(RuntimeError::NotStarted));
        let s = start(input()).unwrap();
        assert!(s.port > 0);
        assert!(!s.token.is_empty());
        assert_eq!(start(input()).err(), Some(RuntimeError::AlreadyStarted));
        let st = status().unwrap();
        assert_eq!(st.port, s.port);
        assert_eq!(st.network_id, "wifi:test");
        set_network("cell:x").unwrap();
        assert_eq!(status().unwrap().network_id, "cell:x");
        let mut newer = input();
        newer.list.issued_at_ms = 6;
        update(newer).unwrap();
        assert_eq!(status().unwrap().issued_at_ms, 6);
        assert!(stop());
        assert_eq!(status().err(), Some(RuntimeError::NotStarted));
    }
}
