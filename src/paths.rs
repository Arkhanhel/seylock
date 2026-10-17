// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! Probe order of paths and a memory of what worked on this network.
//!
//! A network is not "the internet" in general but a specific point of
//! attachment: home Wi-Fi, a mobile carrier, a café hotspot. On one of them
//! names are blocked, on another addresses, on a third everything is open. So
//! memory is kept per network identifier, which the client obtains from the
//! system (type plus fingerprint), and records which path succeeded last and
//! which paths failed.
//!
//! Ordering rules:
//! 1. the last successful path on this network goes first;
//! 2. then the rest in the default order [`PathKind::DEFAULT_ORDER`], except
//!    that paths which failed recently on this network are moved to the end;
//! 3. paths the user has forbidden (Tor without consent) are never tried.

use std::collections::HashMap;

use serde::{Deserialize, Serialize};

use crate::endpoints::{PathKind, PathSpec};

/// Memory for a single network.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct NetworkMemory {
    /// Index into the list of the path that succeeded last.
    pub last_ok: Option<usize>,
    /// When the last success was recorded, in Unix milliseconds. Used to pick
    /// the network to evict when the memory is full.
    pub last_ok_at_ms: i64,
    /// Path index to the time it last failed.
    #[serde(default)]
    pub failed_at_ms: HashMap<usize, i64>,
}

/// Memory for all networks. Serialised to JSON and stored by the client.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PathMemory {
    /// Per-network memory, keyed by the opaque network identifier the
    /// application chooses. Holds at most [`MAX_NETWORKS`] entries.
    #[serde(default)]
    pub networks: HashMap<String, NetworkMemory>,
}

/// How long a failure is remembered: until it expires, the path goes to the end
/// of the queue.
pub const FAILURE_MEMORY_MS: i64 = 6 * 60 * 60 * 1000;

/// How many networks to remember; the oldest are evicted so the memory does not
/// grow without bound.
pub const MAX_NETWORKS: usize = 32;

impl PathMemory {
    /// Parses memory saved by [`to_json`](Self::to_json). Malformed input
    /// yields an empty memory rather than an error.
    pub fn from_json(raw: &str) -> Self {
        serde_json::from_str(raw).unwrap_or_default()
    }

    /// Serialises the memory to JSON for the application to persist between
    /// runs.
    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_else(|_| "{}".to_string())
    }

    /// Records the outcome of a request on `path_index` for `network_id` at
    /// `now_ms` (Unix milliseconds). A success makes the path the first choice
    /// and clears its failure mark; a failure marks the path and drops it as
    /// the first choice. May evict the oldest network.
    pub fn report(&mut self, network_id: &str, path_index: usize, ok: bool, now_ms: i64) {
        self.trim(network_id);
        let entry = self.networks.entry(network_id.to_string()).or_default();
        if ok {
            entry.last_ok = Some(path_index);
            entry.last_ok_at_ms = now_ms;
            entry.failed_at_ms.remove(&path_index);
        } else {
            entry.failed_at_ms.insert(path_index, now_ms);
            if entry.last_ok == Some(path_index) {
                entry.last_ok = None;
            }
        }
    }

    /// Path indices in the order to probe them.
    pub fn order(
        &self,
        network_id: &str,
        paths: &[PathSpec],
        allowed: &dyn Fn(PathKind) -> bool,
        now_ms: i64,
    ) -> Vec<usize> {
        let memory = self.networks.get(network_id);
        let mut out: Vec<usize> = Vec::with_capacity(paths.len());
        if let Some(idx) = memory.and_then(|m| m.last_ok)
            && idx < paths.len()
            && allowed(paths[idx].kind())
        {
            out.push(idx);
        }
        let mut recently_failed: Vec<usize> = Vec::new();
        for kind in PathKind::DEFAULT_ORDER {
            if !allowed(kind) {
                continue;
            }
            for (idx, path) in paths.iter().enumerate() {
                if path.kind() != kind || out.contains(&idx) {
                    continue;
                }
                let failed_recently = memory
                    .and_then(|m| m.failed_at_ms.get(&idx))
                    // Saturating: the time comes from storage the
                    // application keeps, which may be damaged.
                    // A failure dated in the future (the clock was ahead
                    // and has been corrected) is not trusted: otherwise the
                    // path would stay demoted until the clock caught up.
                    .map(|at| (0..FAILURE_MEMORY_MS).contains(&now_ms.saturating_sub(*at)))
                    .unwrap_or(false);
                if failed_recently {
                    recently_failed.push(idx);
                } else {
                    out.push(idx);
                }
            }
        }
        out.extend(recently_failed);
        out
    }

    /// Makes room so that, with `keep` in it, the memory holds at most
    /// [`MAX_NETWORKS`] networks, evicting those whose last success is the
    /// oldest. A loop, not one eviction: memory passed in by the application
    /// may already hold more than the limit.
    fn trim(&mut self, keep: &str) {
        let room = if self.networks.contains_key(keep) {
            MAX_NETWORKS
        } else {
            MAX_NETWORKS - 1
        };
        while self.networks.len() > room {
            let Some(oldest) = self
                .networks
                .iter()
                .filter(|(k, _)| k.as_str() != keep)
                .min_by_key(|(_, m)| m.last_ok_at_ms)
                .map(|(k, _)| k.clone())
            else {
                break;
            };
            self.networks.remove(&oldest);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn paths() -> Vec<PathSpec> {
        vec![
            PathSpec::Direct,
            PathSpec::Ip {
                ip: "203.0.113.5".into(),
            },
            PathSpec::Mirror {
                keys: Some("https://m/k".into()),
                relay: Some("https://m/r".into()),
                targets: Default::default(),
                ip: None,
            },
            PathSpec::Tor,
        ]
    }

    fn all(_: PathKind) -> bool {
        true
    }

    #[test]
    fn default_order_without_memory() {
        let m = PathMemory::default();
        assert_eq!(m.order("wifi:a", &paths(), &all, 1_000), vec![0, 1, 2, 3]);
    }

    #[test]
    fn last_ok_path_goes_first_and_failures_last() {
        let mut m = PathMemory::default();
        m.report("cell:x", 0, false, 1_000);
        m.report("cell:x", 2, true, 1_100);
        assert_eq!(m.order("cell:x", &paths(), &all, 1_200), vec![2, 1, 3, 0]);
        // The memory of one network does not apply to another.
        assert_eq!(m.order("wifi:a", &paths(), &all, 1_200), vec![0, 1, 2, 3]);
    }

    #[test]
    fn failures_are_forgotten_after_the_window() {
        let mut m = PathMemory::default();
        m.report("cell:x", 0, false, 1_000);
        let later = 1_000 + FAILURE_MEMORY_MS + 1;
        assert_eq!(m.order("cell:x", &paths(), &all, later), vec![0, 1, 2, 3]);
    }

    #[test]
    fn forbidden_kinds_are_never_tried() {
        let mut m = PathMemory::default();
        m.report("cell:x", 3, true, 1_000);
        let no_tor = |k: PathKind| k != PathKind::Tor;
        assert_eq!(m.order("cell:x", &paths(), &no_tor, 1_100), vec![0, 1, 2]);
    }

    #[test]
    fn memory_survives_json_round_trip_and_stays_bounded() {
        let mut m = PathMemory::default();
        for i in 0..(MAX_NETWORKS + 5) {
            m.report(&format!("net:{i}"), 1, true, i as i64);
        }
        assert!(m.networks.len() <= MAX_NETWORKS);
        assert!(
            m.networks
                .contains_key(&format!("net:{}", MAX_NETWORKS + 4))
        );
        let back = PathMemory::from_json(&m.to_json());
        assert_eq!(back, m);
        assert_eq!(PathMemory::from_json("garbage"), PathMemory::default());
    }

    #[test]
    fn a_failure_dated_in_the_future_is_not_trusted() {
        // The clock was a year ahead when the path failed, then corrected.
        let mut m = PathMemory::default();
        let year = 365 * 24 * 60 * 60 * 1000;
        m.report("cell:x", 0, false, 1_000 + year);
        assert_eq!(m.order("cell:x", &paths(), &all, 1_000), vec![0, 1, 2, 3]);
    }

    #[test]
    fn memory_passed_in_over_the_limit_is_trimmed_to_it() {
        let mut m = PathMemory::default();
        for n in 0..MAX_NETWORKS + 10 {
            m.networks
                .insert(format!("net:{n}"), NetworkMemory::default());
        }
        m.report("net:new", 0, true, 1_000);
        assert_eq!(m.networks.len(), MAX_NETWORKS);
        assert!(m.networks.contains_key("net:new"));
        // Reporting on a network already present keeps it at the limit.
        m.report("net:new", 1, true, 2_000);
        assert_eq!(m.networks.len(), MAX_NETWORKS);
    }
}
