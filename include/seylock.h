/*
 * SPDX-License-Identifier: MPL-2.0
 * SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
 *
 * SeyLock C ABI: reach your own servers from networks that block them.
 *
 * Rules for every function:
 *  - Strings passed in are NUL-terminated UTF-8 and only need to stay valid
 *    for the duration of the call.
 *  - Strings returned are owned by the caller and must be released with
 *    seylock_string_free(), and with nothing else.
 *  - Functions never unwind or abort across this boundary: failures are
 *    returned as codes. All functions may be called from any thread.
 *
 * Codes:
 *    0        success
 *    1 .. 11  the endpoint list was rejected (PROTOCOL.md, "Acceptance")
 *    100      internal error, NULL pointer or non-UTF-8 string
 *    101      seylock_start: a proxy is already running
 *    102      no proxy is running
 *    103      seylock_start: the loopback port could not be bound
 *    104      the policy JSON is invalid
 *
 * The proxy listens on 127.0.0.1:<port>. Send the application's ordinary
 * HTTP and WebSocket requests there with two headers:
 *    x-transport-token:   the token from seylock_start()
 *    x-transport-service: a service name from the list ("keys"/"relay" in
 *                         format 1 lists)
 * See README.md and PROTOCOL.md.
 */
#ifndef SEYLOCK_H
#define SEYLOCK_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Library version, for example "0.2.0". Free with seylock_string_free(). */
char *seylock_version(void);

/*
 * Verifies a signed endpoint list against the pinned Ed25519 public key.
 *
 *   signed_json           the signed envelope {"doc": ..., "sig_b64": ...}
 *   verifying_key_b64     standard base64 of the 32-byte public key
 *   now_ms                the device clock, Unix milliseconds
 *   current_issued_at_ms  issued_at_ms of the list already accepted, or 0
 *   out_doc               NULL, or receives the accepted list as JSON on
 *                         success (free with seylock_string_free())
 *
 * Returns 0 if the list is accepted, otherwise its rejection code (1..11),
 * or 100.
 */
int32_t seylock_endpoints_verify(const char *signed_json,
                                 const char *verifying_key_b64,
                                 int64_t now_ms,
                                 int64_t current_issued_at_ms,
                                 char **out_doc);

/*
 * Starts the process-wide proxy.
 *
 *   policy_json  {"list": <accepted list JSON>, "memory": {...},
 *                 "network_id": "...", "allow_tor": false,
 *                 "allow_socks": false, "race": {}}
 *                Only "list" is required. Without "race" paths are tried one
 *                at a time; "race": {} turns on racing (PROTOCOL.md).
 *   out_port     receives the loopback port
 *   out_token    receives the token for x-transport-token
 *                (free with seylock_string_free())
 *
 * Returns 0, 101, 103, 104 or 100.
 */
int32_t seylock_start(const char *policy_json, uint16_t *out_port, char **out_token);

/* Replaces the list, network and permissions of the running proxy.
 * Returns 0, 102, 104 or 100. */
int32_t seylock_update(const char *policy_json);

/* Tells the proxy the device changed networks (an opaque id the application
 * chooses, for example a salted hash of the Wi-Fi name). Returns 0, 102 or 100. */
int32_t seylock_set_network(const char *network_id);

/* The running proxy's state as JSON: port, current path, network, path memory
 * to persist, issued_at_ms, and "tor" when a Tor connector is installed.
 * NULL if no proxy is running. Free with seylock_string_free(). */
char *seylock_status_json(void);

/* Stops the proxy. Returns 0, or 102 if none was running. */
int32_t seylock_stop(void);

/* Frees a string returned by this library. NULL is ignored. */
void seylock_string_free(char *s);

#ifdef __cplusplus
}
#endif

#endif /* SEYLOCK_H */
