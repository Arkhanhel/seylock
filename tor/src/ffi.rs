// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! C ABI, for applications that use SeyLock from another language.
//!
//! Link this crate's library instead of `seylock`'s: it contains the whole of
//! SeyLock's C ABI (`seylock_*`) plus the two functions below. Like the rest
//! of SeyLock's C ABI, they never unwind across the boundary.
//!
//! | Function | Returns |
//! |---|---|
//! | `seylock_tor_enable(settings_json)` | 0, 100 (NULL or non-UTF-8), 104 (bad JSON) or 105 (Tor could not be set up) |
//! | `seylock_tor_disable()` | 0, or 102 if Tor was not enabled |
//!
//! `settings_json` is a [`crate::TorSettings`] as JSON. Enabling starts Tor in
//! the background; its progress appears under `tor` in
//! `seylock_status_json()`. The `tor` path is still used only when the
//! policy allows it (`allow_tor`).

use std::ffi::{CStr, c_char};
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::{ArtiConnector, TorSettings};

const OK: i32 = 0;
const ERR_INTERNAL: i32 = 100;
const ERR_NOT_ENABLED: i32 = 102;
const ERR_BAD_JSON: i32 = 104;
const ERR_TOR_SETUP: i32 = 105;

/// Starts Tor with the given settings and installs it for the `tor` path,
/// replacing an earlier one.
///
/// # Safety
///
/// `settings_json` must be NULL or a NUL-terminated string that stays valid
/// for the duration of the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seylock_tor_enable(settings_json: *const c_char) -> i32 {
    catch_unwind(AssertUnwindSafe(|| {
        if settings_json.is_null() {
            return ERR_INTERNAL;
        }
        // SAFETY: checked for NULL above; the caller promises a valid,
        // NUL-terminated string for the duration of the call.
        let Ok(text) = unsafe { CStr::from_ptr(settings_json) }.to_str() else {
            return ERR_INTERNAL;
        };
        let Ok(settings) = serde_json::from_str::<TorSettings>(text) else {
            return ERR_BAD_JSON;
        };
        match ArtiConnector::start(&settings) {
            Ok(connector) => {
                seylock::tor::install(connector);
                OK
            }
            Err(e) => {
                tracing::info!(target: "seylock_tor", "enable failed: {e}");
                ERR_TOR_SETUP
            }
        }
    }))
    .unwrap_or(ERR_INTERNAL)
}

/// Removes Tor from the `tor` path. Circuits close as their streams end.
#[unsafe(no_mangle)]
pub extern "C" fn seylock_tor_disable() -> i32 {
    catch_unwind(|| {
        if seylock::tor::uninstall() {
            OK
        } else {
            ERR_NOT_ENABLED
        }
    })
    .unwrap_or(ERR_INTERNAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::ffi::CString;

    #[test]
    fn bad_input_is_reported_as_codes() {
        // SAFETY: NULL is allowed and reported as an error.
        assert_eq!(
            unsafe { seylock_tor_enable(std::ptr::null()) },
            ERR_INTERNAL
        );
        let bad = CString::new("not json").unwrap();
        // SAFETY: a valid NUL-terminated string.
        assert_eq!(unsafe { seylock_tor_enable(bad.as_ptr()) }, ERR_BAD_JSON);
        let bad_bridge = CString::new(
            r#"{"state_dir":"/tmp/s","cache_dir":"/tmp/c","bridges":["obfs4 nonsense"]}"#,
        )
        .unwrap();
        // SAFETY: a valid NUL-terminated string.
        assert_eq!(
            unsafe { seylock_tor_enable(bad_bridge.as_ptr()) },
            ERR_TOR_SETUP
        );
        assert_eq!(seylock_tor_disable(), ERR_NOT_ENABLED);
    }
}
