# SeyLock

[![crates.io](https://img.shields.io/crates/v/seylock.svg)](https://crates.io/crates/seylock)
[![docs.rs](https://img.shields.io/docsrs/seylock)](https://docs.rs/seylock)
[![CI](https://github.com/Arkhanhel/seylock/actions/workflows/ci.yml/badge.svg)](https://github.com/Arkhanhel/seylock/actions/workflows/ci.yml)
[![License: MPL-2.0](https://img.shields.io/badge/license-MPL--2.0-blue.svg)](LICENSE)

**Reach your own servers from networks that block them.**

SeyLock is a small Rust library for applications whose users live behind
censorship. The application keeps sending ordinary HTTP and WebSocket
requests; SeyLock finds a way through and carries them.

## Who it is for

- **Apps under censorship.** Messengers, newsrooms' apps, human-rights tools,
  anything with its own servers and users in countries that block them.
- **Teams without a networking specialist.** One signed list of ways in, one
  local port, and the library does the rest.
- **Any language.** A C ABI, used from Dart in production, callable from C,
  C++, Swift and Go directly and from Kotlin or Java through JNI or JNA.

## How it works

SeyLock runs a reverse proxy on `127.0.0.1` inside the app and decides how to
reach the real server: directly, by a pinned IP address, through a mirror
domain, through a CDN-hosted name, through a volunteer TLS proxy, or through
a SOCKS5 proxy such as a local Tor client.

- **Paths race at the connection stage.** A silently blocked path does not
  hold up a working one: on a network that drops `direct` and `ip`, the first
  request takes half a second instead of twelve
  ([measurements](RACE_LAB.md)). Requests themselves never race, so nothing is
  sent twice.
- **It remembers each network.** The path that worked at home, on mobile data
  or at a café is tried first the next time.
- **The list of ways in is signed** with an offline Ed25519 key, and only a
  newer list replaces the current one. A censor who can tamper with traffic
  cannot point the app at a server they control, nor roll it back to
  addresses that are already blocked.
- **It never needs to see content.** SeyLock moves bytes and picks the road;
  it sits under the application's own encryption. A list names whatever
  services the application has (`api`, `media`, ...), so nothing in it is
  tied to one product.

SeyLock was built for, and is used by, [Secretly](https://github.com/Arkhanhel/Secretly),
an end-to-end encrypted messenger, where messages are encrypted before they
reach SeyLock and every request is signed by the device key. It does not
depend on Secretly's servers: the addresses come from the signed list you give
it.

## Status

Version 0.1. Tested in CI on Linux, macOS and Windows; built into Secretly's
development builds for Android, iOS and macOS, not yet in a store release.

| Path | What it does | Status |
|---|---|---|
| `direct` | Normal TLS connection to the server's own name | done |
| `ip` | Same TLS name (SNI), but connects to a pinned IP, skipping DNS | done |
| `mirror` | Another domain that serves the same API | done |
| `cdn` | A name hosted behind a CDN that forwards to the server | done |
| `proxy` | TLS to a volunteer proxy, then TLS to the server inside it, as in Signal's proxy design | done |
| `socks` | SOCKS5, for example a local Tor or a user's own proxy | done |
| `tor` | Tor, from the separate [`seylock-tor`](https://github.com/Arkhanhel/seylock/tree/main/tor) crate (arti), only when the app allows it | done |

## What it does not do

- **It does not make traffic invisible.** A censor who studies the TLS
  fingerprint, packet timing or volume can still tell that something is
  going on. The goal is to make blocking cost more than a DNS entry or one
  IP address.
- **No domain fronting.** Major CDNs have closed it. The `cdn` path is an
  ordinary name that the CDN serves, not a hidden one.
- **The TLS fingerprint is rustls's own.** It is not disguised as a
  browser.
- **It does not hide that you use the app** from someone holding the
  phone.

## Quick start

The example tool covers the operator's side and lets you try the proxy:

```sh
# 1. A signing key. Keep the secret file offline; ship the public key in the app.
cargo run --example endpoints_tool -- keygen list-signing.key

# 2. Describe your ways in (see examples/list.example.json) and sign the list.
cargo run --example endpoints_tool -- sign list-signing.key list.json list.signed.json

# 3. Check it the way a client will.
cargo run --example endpoints_tool -- verify <PUBLIC_KEY_B64> list.signed.json

# 4. Run the local proxy with that list and send a request through it.
cargo run --example endpoints_tool -- serve <PUBLIC_KEY_B64> list.signed.json
```

`serve` prints a `curl` line. The response carries an `x-transport-path`
header that names the path which worked.

`examples/list.v2.example.json` shows format 2, where a list names its own
services (`api`, `media`, …) instead of the fixed pair `keys` and `relay`.

## Using it from Rust

```rust,no_run
use seylock::endpoints;
use seylock::paths::PathMemory;
use seylock::proxy::{self, Policy, Race};

# async fn demo(signed_json: &str, pinned_key_b64: &str, now_ms: i64) {
let list = endpoints::verify_and_parse(signed_json, pinned_key_b64, now_ms, 0)
    .expect("list rejected");
let handle = proxy::start(Policy {
    list,
    memory: PathMemory::default(), // persist `memory` between runs
    network_id: "wifi:home".into(),
    allow_tor: false,
    allow_socks: false,
    current: None,
    race: Race::default(), // paths race at the connection stage
})
.await
.expect("bind loopback");
// Send requests to http://127.0.0.1:{handle.port} with the headers
// x-transport-token: {handle.token}
// x-transport-service: <a service name from the list>
# }
```

## Using it from other languages

The `ffi` module exposes a C ABI: verify a list, start, update the policy,
report a network change, read status as JSON, stop. Strings returned by the
library are freed with `seylock_string_free`. The Secretly app
calls it from Dart through `dart:ffi`. The crate builds as `staticlib` and
`cdylib` for Android, iOS, macOS, Windows and Linux.

See [PROTOCOL.md](PROTOCOL.md) for the list format, the proxy's request
rules and the error codes.

## Running a volunteer proxy

The `proxy` path expects a plain TLS proxy that forwards by SNI, the same
shape as a Signal TLS proxy. A ready Docker Compose setup with two nginx
containers and setup notes in English and Russian lives in the Secretly
repository under `server/proxy/tlsproxy/`.

## How it is checked

| Check | What it shows |
|---|---|
| `cargo test` | Unit and integration tests, including racing, and the README example compiled as a doctest. |
| `test-vectors/endpoints.json` | 55 signed lists with the result each must give, written by hand from PROTOCOL.md. |
| `tools/verify_vectors.py` | A second implementation in plain Python, with its own Ed25519 from RFC 8032 and no third-party code, agreeing on every vector. |
| `tests/robustness.rs`, `fuzz/` | Damaged and extreme input never panics; four fuzz targets run nightly in CI. |
| `tools/check_reproducible.sh` | Two builds from different directories give byte-identical libraries. |
| `examples/race_lab.rs` | The racing measurements in [RACE_LAB.md](RACE_LAB.md). |

## Security notes

- **List signatures.** The signed bytes are a context string —
  `transport-endpoints-v2\n` for format 2, `secretly-endpoints-v1\n` for
  format 1 — followed by the exact UTF-8 bytes of the list document. The
  context prevents a signature made for another purpose, or for the other
  format, from being replayed as a list.
- **Freshness.** A list is accepted only if `issued_at_ms` is newer than
  the current one. An old list cannot be replayed to roll back to addresses
  that are already blocked or compromised.
- **Who can use the proxy.** It listens on `127.0.0.1` only, drops
  connections from other addresses, and requires a random token that only
  the app knows. Other apps on the device cannot use it as an open proxy.
- **Certificates.** Outbound TLS verifies the server certificate against
  the Mozilla root store (`webpki-roots`). The `ip` path keeps the real
  server name for SNI and certificate checks, so a pinned IP cannot be
  hijacked into a different identity.
- **Private headers.** The proxy strips its own control headers before
  forwarding, so the server never sees the token.

Who can do what to whom, and the scope for an independent audit, are in
[THREAT_MODEL.md](THREAT_MODEL.md). Report vulnerabilities privately as
described in [SECURITY.md](SECURITY.md).

## Roadmap

- **Packages for mobile developers:** Kotlin and Swift bindings, an Android
  AAR on Maven Central and a Swift package.
- **Bridges in the signed list:** Tor bridge lines distributed and rotated
  like the other ways in. Today `seylock-tor` takes them from the
  application.
- **Less recognisable TLS:** Encrypted Client Hello where the CDN supports
  it, and a measured look at browser-like ClientHellos.
- **Open blocking statistics:** which ways in work on which networks,
  aggregated, opt-in, and published only after review of the privacy risks.
- **An independent security audit.**

## License

MPL-2.0. You can use the library in closed or open apps. Changes to the
library's own files must be shared under the same license. The Secretly
app itself is AGPL-3.0.
