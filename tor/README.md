# seylock-tor

[![crates.io](https://img.shields.io/crates/v/seylock-tor.svg)](https://crates.io/crates/seylock-tor)
[![docs.rs](https://img.shields.io/docsrs/seylock-tor)](https://docs.rs/seylock-tor)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

**Tor for [SeyLock](https://github.com/Arkhanhel/seylock)'s `tor` path**, built on
the Tor Project's [arti](https://gitlab.torproject.org/tpo/core/arti).

SeyLock itself has no Tor client: a Tor implementation brings several hundred
dependencies, and most applications do not want them. This crate supplies one.
Install it, allow the `tor` path in the policy, and requests that no other
path can carry go through Tor, with TLS to the real server running inside the
Tor stream.

## Using it

From Rust:

```rust,no_run
# fn demo() -> Result<(), String> {
let settings = seylock_tor::TorSettings {
    state_dir: "/app/data/tor/state".into(),
    cache_dir: "/app/data/tor/cache".into(),
    bridges: vec![],
    transports: vec![],
};
seylock::tor::install(seylock_tor::ArtiConnector::start(&settings)?);
# Ok(()) }
```

From other languages, link this crate's library instead of `seylock`'s: it
carries SeyLock's whole C ABI plus two functions, declared in
[`include/seylock_tor.h`](include/seylock_tor.h).

| Function | Returns |
|---|---|
| `seylock_tor_enable(settings_json)` | 0, 100 (NULL or non-UTF-8), 104 (bad JSON), 105 (Tor could not be set up) |
| `seylock_tor_disable()` | 0, or 102 if Tor was not enabled |

```json
{
  "state_dir": "/app/data/tor/state",
  "cache_dir": "/app/data/tor/cache",
  "bridges": ["obfs4 192.0.2.1:443 0123...4567 cert=... iat-mode=0"],
  "transports": [{ "protocols": ["obfs4"], "socks_addr": "127.0.0.1:47351" }]
}
```

Tor starts bootstrapping at once, in the background. Its progress appears
under `tor` in `seylock_status_json()`:

- `{"state":"bootstrapping","percent":40}`
- `{"state":"ready"}`
- `{"state":"failed","reason":"..."}`

## Bridges

Censored networks often block the public Tor relays. Put bridge lines
(`obfs4`, `webtunnel`, `snowflake`, ...) in `bridges`.

Bridges also arrive from SeyLock's signed list (`tor_bridges`, format 2):
whenever the list changes, the connector adds them to the application's own
and reconfigures Tor in place, without a restart. A bridge whose transport is
not running is left out rather than making the whole configuration fail.

Pluggable transports must already be running and listening on a local SOCKS
port, listed in `transports`. On Android and iOS an application cannot
start other programs, so the transports run inside it, for example through
[IPtProxy](https://github.com/tladesignz/IPtProxy) (the approach of Orbot and
OnionShare).

## What it costs

Android arm64, release build with Rust 1.93.1, symbols stripped as APK
packaging does:

| Library | Size | Compressed (the download) |
|---|---:|---:|
| `libseylock.so`, SeyLock alone | 2.36 MB | 1.19 MB |
| `libseylock_tor.so`, SeyLock with Tor and bundled SQLite | 9.53 MB | 4.44 MB |
| **Tor adds** | **+7.17 MB** | **+3.24 MB** |

| Other costs | |
|---|---|
| New dependencies | about 370 packages, almost all from arti |
| Disk, directory cache | about 40 MB |
| First start, empty cache | 10–20 s to the first circuit |
| Later starts | about 1 s |

Live checks, one request through SeyLock's proxy to an HTTPS site, 16
October 2026:

| Where | How | Result |
|---|---|---|
| Android 16 phone (arm64, Wi-Fi), `tor_probe` over `adb` | direct to Tor, cold start | `200 OK` by the `tor` path, 8–17 s |
| same | warm start | `200 OK`, 3.2–5.2 s |
| same | plain bridge from the signed list only, fresh state | `200 OK`, 5.6 s |
| macOS | direct to Tor, cold start | `200 OK`, 12–15 s |
| macOS | 7 obfs4 bridges (Tor Browser's built-in ones) from the list, through lyrebird 0.8.1 already running | `200 OK`, 25 s |

**After every bridge run, Tor had only used bridges.** Its guard state held
the bridges and nothing else: the public guard samples were empty. The list's
bridges are applied before the first bootstrap, so a bridge-only setup never
reaches the public relays directly.

**The first bridge start can outlast one request.** Through obfs4 the
directory is fetched over the bridges, and some built-in bridges refused
connections. The first request hit SeyLock's 60 s limit at 44 % bootstrap;
bootstrapping went on in the background, and the next request succeeded. An
application should show the `tor` state from the status while it
bootstraps.

## Platforms

arti keeps its directory cache in SQLite. Whether to compile SQLite into the
library depends on how the library is linked:

- **Dynamic library** (`.so`, `.dll`, `.dylib`): use `bundled-sqlite`. The
  copy stays private, because the library exports only its own functions,
  and it cannot clash with the application's SQLite or SQLCipher.
  - Android needs it anyway: the NDK has no public SQLite.
  - On Windows it is always on: there is no system SQLite to link against.
- **Static library linked into an app that also has SQLite or SQLCipher**
  (typical on iOS, and on macOS when the app links `.a`): do **not** use
  `bundled-sqlite`, and do not link the system `libsqlite3` either. arti
  then uses the application's own engine, which provides the same
  `sqlite3_*` functions. Two copies in one statically linked binary can
  silently replace the encrypted database engine with the plain one.
- **iOS, at the time of writing.** arti 0.47 does not build for iOS with
  `libc` 0.2.190.
  - That libc release gated `mach_*` functions to macOS. This is fixed in
    [rust-lang/libc#5612](https://github.com/rust-lang/libc/pull/5612),
    which is not yet released.
  - arti's `tor-memquota` also uses `sysinfo` 0.38, which calls the
    non-public `proc_pidinfo` on iOS.
  - Until both are resolved upstream, pin `libc` to 0.2.189. We have
    proposed a small `tor-memquota` change to arti that removes `sysinfo` on
    iOS without raising its minimum Rust version.

**Dependency audit.** `cargo audit` reports RUSTSEC-2023-0071 (the "Marvin"
timing attack on private-key RSA) through arti's `rsa` dependency. A Tor
client makes no private-key RSA operations. arti tracks the switch it needs
before it makes RSA signatures (relays, directory authorities) in
[tpo/core/arti#2447](https://gitlab.torproject.org/tpo/core/arti/-/issues/2447).
CI ignores that advisory, and only that one.

## Privacy

- **What the exit relay sees:** the server name and port you connect to,
  and the volume and timing of the traffic.
- **What it does not see:** requests and responses. TLS to the real server
  runs inside the Tor stream, so the exit relay cannot read or alter them.
- **DNS:** names are resolved by the exit relay, so a censoring DNS resolver
  never sees them.
- **When Tor is used:** only when the application allows it (`allow_tor` in
  SeyLock's policy), and in SeyLock's path order it is the last resort.

## License

MPL-2.0, like SeyLock. arti and its dependencies are MIT or Apache-2.0.
