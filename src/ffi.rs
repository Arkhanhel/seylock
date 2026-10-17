// SPDX-License-Identifier: MPL-2.0
// SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
//! C ABI for the client.
//!
//! Rules: strings are NUL-terminated UTF-8; anything the library returns must
//! be freed only with [`seylock_string_free`]; errors are reported
//! as codes, not panics (a panic across the FFI boundary is undefined
//! behaviour, so every function that does real work is wrapped in
//! `catch_unwind`; `seylock_version` and `seylock_string_free` cannot
//! panic).
//!
//! Codes: 0 is success; 1-11 are endpoint-list errors
//! ([`crate::endpoints::EndpointError::code`]); 101-103 are runtime errors
//! ([`crate::runtime::RuntimeError::code`]); 104 is invalid policy JSON; 100
//! is an internal error or an invalid pointer.
//!
//! The C declarations, with these rules spelled out, are in
//! `include/seylock.h`; `tools/check_c_abi.sh` compiles a C program against
//! that header and the static library to keep the two in step.

use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use std::panic::{AssertUnwindSafe, catch_unwind};

use crate::endpoints;
use crate::runtime::{self, PolicyInput};

/// Code for an internal error: a panic or an invalid pointer.
pub const ERR_INTERNAL: i32 = 100;
/// Code for JSON that cannot be parsed.
pub const ERR_JSON: i32 = 104;

/// # Safety
///
/// `ptr` is null or a NUL-terminated string that stays alive and unchanged
/// for `'a`.
unsafe fn cstr<'a>(ptr: *const c_char) -> Option<&'a str> {
    if ptr.is_null() {
        return None;
    }
    // SAFETY: guaranteed by the caller.
    unsafe { CStr::from_ptr(ptr) }.to_str().ok()
}

fn to_c(s: String) -> *mut c_char {
    CString::new(s)
        .map(CString::into_raw)
        .unwrap_or(std::ptr::null_mut())
}

fn guarded(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(ERR_INTERNAL)
}

/// Library version. Free it with [`seylock_string_free`].
#[unsafe(no_mangle)]
pub extern "C" fn seylock_version() -> *mut c_char {
    to_c(crate::version().to_string())
}

/// Verifies a signed endpoint list. 0 means accepted (and `out_doc`, if not
/// null, receives the list's JSON); otherwise a code from
/// [`endpoints::EndpointError::code`].
///
/// # Safety
/// `signed_json` and `verifying_key_b64` are NUL-terminated strings; `out_doc`
/// is null or the address of a caller variable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seylock_endpoints_verify(
    signed_json: *const c_char,
    verifying_key_b64: *const c_char,
    now_ms: i64,
    current_issued_at_ms: i64,
    out_doc: *mut *mut c_char,
) -> i32 {
    guarded(|| {
        // SAFETY: guaranteed by the caller of this function.
        let (Some(signed), Some(key)) = (unsafe { cstr(signed_json) }, unsafe {
            cstr(verifying_key_b64)
        }) else {
            return ERR_INTERNAL;
        };
        match endpoints::verify_and_parse(signed, key, now_ms, current_issued_at_ms) {
            Ok(list) => {
                if !out_doc.is_null() {
                    let json = serde_json::to_string(&list).unwrap_or_default();
                    // SAFETY: the caller passed the address of its own variable.
                    unsafe { *out_doc = to_c(json) };
                }
                0
            }
            Err(e) => e.code(),
        }
    })
}

/// Starts the local proxy. `policy_json` is a [`PolicyInput`]. On success
/// `out_port` and `out_token` are filled in; free the token with
/// [`seylock_string_free`].
///
/// # Safety
/// `policy_json` is a NUL-terminated string; `out_port` and `out_token` are
/// addresses of caller variables.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seylock_start(
    policy_json: *const c_char,
    out_port: *mut u16,
    out_token: *mut *mut c_char,
) -> i32 {
    guarded(|| {
        // SAFETY: guaranteed by the caller of this function.
        let Some(raw) = (unsafe { cstr(policy_json) }) else {
            return ERR_INTERNAL;
        };
        if out_port.is_null() || out_token.is_null() {
            return ERR_INTERNAL;
        }
        let Ok(input) = serde_json::from_str::<PolicyInput>(raw) else {
            return ERR_JSON;
        };
        match runtime::start(input) {
            Ok(started) => {
                // SAFETY: addresses of the caller's variables, checked for null
                // above.
                unsafe {
                    *out_port = started.port;
                    *out_token = to_c(started.token);
                }
                0
            }
            Err(e) => e.code(),
        }
    })
}

/// Replaces the list, network and permissions of the running proxy.
///
/// # Safety
///
/// `policy_json` is null or a NUL-terminated string valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seylock_update(policy_json: *const c_char) -> i32 {
    guarded(|| {
        // SAFETY: guaranteed by the caller.
        let Some(raw) = (unsafe { cstr(policy_json) }) else {
            return ERR_INTERNAL;
        };
        let Ok(input) = serde_json::from_str::<PolicyInput>(raw) else {
            return ERR_JSON;
        };
        runtime::update(input)
            .map(|_| 0)
            .unwrap_or_else(|e| e.code())
    })
}

/// Reports a network change (type + fingerprint, as the platform provides
/// them).
///
/// # Safety
///
/// `network_id` is null or a NUL-terminated string valid for the call.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seylock_set_network(network_id: *const c_char) -> i32 {
    guarded(|| {
        // SAFETY: guaranteed by the caller.
        let Some(id) = (unsafe { cstr(network_id) }) else {
            return ERR_INTERNAL;
        };
        runtime::set_network(id)
            .map(|_| 0)
            .unwrap_or_else(|e| e.code())
    })
}

/// JSON of [`runtime::Status`], or null if the proxy is not running.
#[unsafe(no_mangle)]
pub extern "C" fn seylock_status_json() -> *mut c_char {
    catch_unwind(|| match runtime::status() {
        Ok(s) => to_c(serde_json::to_string(&s).unwrap_or_default()),
        Err(_) => std::ptr::null_mut(),
    })
    .unwrap_or(std::ptr::null_mut())
}

/// Stops the proxy. 0 means stopped, 102 means it was not running.
#[unsafe(no_mangle)]
pub extern "C" fn seylock_stop() -> i32 {
    guarded(|| {
        if runtime::stop() {
            0
        } else {
            runtime::RuntimeError::NotStarted.code()
        }
    })
}

/// Frees a string obtained from the library. `null` is allowed.
///
/// # Safety
/// `ptr` is null or a pointer returned by this library that has not been freed
/// yet.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn seylock_string_free(ptr: *mut c_char) {
    if ptr.is_null() {
        return;
    }
    // SAFETY: the pointer came from CString::into_raw in this library.
    unsafe { drop(CString::from_raw(ptr)) };
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn version_round_trips_through_c_strings() {
        let p = seylock_version();
        assert!(!p.is_null());
        let s = unsafe { CStr::from_ptr(p) }.to_str().unwrap().to_string();
        assert_eq!(s, crate::version());
        unsafe {
            seylock_string_free(p);
            seylock_string_free(std::ptr::null_mut());
        }
    }

    #[test]
    fn verify_reports_errors_as_codes_not_panics() {
        let bad = CString::new("not json").unwrap();
        let key = CString::new("AAAA").unwrap();
        let mut out: *mut c_char = std::ptr::null_mut();
        let code = unsafe { seylock_endpoints_verify(bad.as_ptr(), key.as_ptr(), 1, 0, &mut out) };
        assert_eq!(code, endpoints::EndpointError::Envelope.code());
        assert!(out.is_null());
        assert_eq!(
            unsafe { seylock_endpoints_verify(std::ptr::null(), key.as_ptr(), 1, 0, &mut out) },
            ERR_INTERNAL
        );
    }

    #[test]
    fn start_rejects_bad_json_and_null_outputs() {
        let bad = CString::new("{").unwrap();
        let mut port: u16 = 0;
        let mut token: *mut c_char = std::ptr::null_mut();
        assert_eq!(
            unsafe { seylock_start(bad.as_ptr(), &mut port, &mut token) },
            ERR_JSON
        );
        assert_eq!(
            unsafe { seylock_start(bad.as_ptr(), std::ptr::null_mut(), &mut token) },
            ERR_INTERNAL
        );
        assert!(seylock_status_json().is_null());
    }
}
