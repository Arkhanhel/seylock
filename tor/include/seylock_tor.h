/*
 * SPDX-License-Identifier: MPL-2.0
 * SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
 *
 * seylock-tor C ABI: Tor for SeyLock's `tor` path.
 *
 * Link the seylock-tor library instead of seylock's: it carries the whole
 * SeyLock C ABI (include seylock.h for it) plus the two functions below. The
 * rules of seylock.h apply: strings passed in are NUL-terminated UTF-8 valid
 * for the duration of the call, and nothing unwinds across this boundary.
 *
 * Codes:
 *    0    success
 *    100  internal error, NULL pointer or non-UTF-8 string
 *    102  seylock_tor_disable: Tor was not enabled
 *    104  the settings JSON is invalid
 *    105  Tor could not be set up (see the log)
 */
#ifndef SEYLOCK_TOR_H
#define SEYLOCK_TOR_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Starts Tor in the background with `settings_json`, TorSettings as JSON:
 *    {"state_dir": "...", "cache_dir": "...",
 *     "bridges": ["obfs4 ..."],                                 (optional)
 *     "transports": [{"protocols": ["obfs4"],
 *                     "socks_addr": "127.0.0.1:47351"}]}          (optional)
 * Both directories must be private to the application. It installs Tor for
 * the `tor` path, replacing an earlier one. Progress appears under "tor" in
 * seylock_status_json(). The path is used only when the policy allows it
 * ("allow_tor": true).
 */
int32_t seylock_tor_enable(const char *settings_json);

/* Removes Tor from the `tor` path. Circuits close as their streams end. */
int32_t seylock_tor_disable(void);

#ifdef __cplusplus
}
#endif

#endif /* SEYLOCK_TOR_H */
