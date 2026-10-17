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

**Start here:** [INTEGRATING.md](INTEGRATING.md) walks an operator and an
application developer through putting SeyLock under an existing app, in about
an hour.

## Status

Version 0.2.0 (October 2026). Published on
[crates.io](https://crates.io/crates/seylock) (with
[`seylock-tor`](https://crates.io/crates/seylock-tor)), as a Swift package
and an Android library attached to the
[release](https://github.com/Arkhanhel/seylock/releases/tag/v0.2.0).

It is tested in CI on Linux, macOS and Windows, with the Swift package
tests on macOS, the Android library tests on the JVM, and an iOS simulator
build. The Android device tests run on an emulator before each release. It is built into Secretly's development builds for Android,
iOS and macOS, not yet in a store release. There has been no external audit
yet; [AUDIT.md](AUDIT.md) is the guide for one.

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
use seylock::proxy::{self, Policy};

# async fn demo(signed_json: &str, pinned_key_b64: &str, now_ms: i64) {
let list = endpoints::verify_and_parse(signed_json, pinned_key_b64, now_ms, 0)
    .expect("list rejected");
// Paths race at the connection stage by default.
let mut policy = Policy::new(list);
policy.network_id = "wifi:home".into(); // an opaque id, never the Wi-Fi name
policy.response_timeout_ms = Some(20_000); // fail over from a silent path
// Restore `policy.memory` saved from `handle.policy().await.memory` last run.
let handle = proxy::start(policy).await.expect("bind loopback");
// Send requests to http://127.0.0.1:{handle.port} with the headers
// x-transport-token: {handle.token}
// x-transport-service: <a service name from the list>
# }
```

## Using it from Swift (iOS, macOS)

Add the package `https://github.com/Arkhanhel/seylock` in Xcode or in
`Package.swift`. It brings a prebuilt XCFramework (iOS devices, the iOS
simulator on Apple silicon, macOS) and a small Swift API:

```swift
import SeyLock

let list = try SeyLock.verifyList(signedJSON: signed, publicKeyBase64: pinnedKey)
let proxy = try SeyLock.start(policyJSON: #"{"list":\#(list),"race":{},"response_timeout_ms":20000}"#)

// Any URLRequest to your server, sent through SeyLock:
let request = proxy.request(for: URLRequest(url: apiURL), service: "api")
let (data, response) = try await URLSession.shared.data(for: request)
```

Errors arrive as `SeyLockError` (`listRejected(code:)`, `notRunning`, ...),
and memory returned by the library is freed for you. The package's tests
send a real `URLSession` request through the proxy.

## Using it from Kotlin (Android)

The Android library `io.github.arkhanhel:seylock` carries `libseylock.so`
for arm64-v8a, armeabi-v7a and x86_64 and a Kotlin API over it (through JNA,
as UniFFI's Kotlin bindings do). Until it is on Maven Central, take
`seylock-<version>.aar` from the GitHub release and add it with JNA:

```kotlin
dependencies {
    implementation(files("libs/seylock-0.2.0.aar"))
    implementation("net.java.dev.jna:jna:5.17.0@aar")
}
```

The proxy speaks plain HTTP on `127.0.0.1`, which Android 9 and later refuse
by default. The AAR ships a configuration that allows it for `127.0.0.1` and
nothing else; point the manifest at it:

```xml
<application android:networkSecurityConfig="@xml/seylock_network_security_config">
```

[`bindings/android/sample`](bindings/android/sample) is a complete minimal
application doing exactly this, minified by R8 as a release build would be.

```kotlin
import io.github.arkhanhel.seylock.SeyLock

val list = SeyLock.verifyList(signedJson, pinnedKeyBase64)
val proxy = SeyLock.start("""{"list":$list,"race":{},"response_timeout_ms":20000}""")

// With OkHttp, one interceptor sends every request through SeyLock:
val client = OkHttpClient.Builder().addInterceptor { chain ->
    val request = chain.request()
    val url = proxy.url(request.url.toUrl()).toString().toHttpUrl()
    chain.proceed(request.newBuilder().url(url).apply {
        proxy.headers("api").forEach { (k, v) -> header(k, v) }
    }.build())
}.build()
```

Errors arrive as `SeyLockException` subclasses. The library's tests run on
the JVM and on an Android emulator, each sending a real request through the
proxy. `tools/build_android_libs.sh` builds the native libraries;
`bindings/android` builds the AAR.

## Using it from C and other languages

[`include/seylock.h`](include/seylock.h) declares the C ABI with its rules
(who frees what, every return code): verify a list, start, update the
policy, report a network change, read status as JSON, stop. Strings
returned by the library are freed with `seylock_string_free`.
`tools/check_c_abi.sh` compiles a C program against that header and the
static library in CI, so the two cannot drift apart.

The Secretly app calls the same ABI from Dart through `dart:ffi`. The crate
builds as `staticlib` and `cdylib` for Android, iOS, macOS, Windows and
Linux.

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
| `cargo test` | Unit and integration tests, including racing, failover from silent and broken paths, and the README example compiled as a doctest. |
| `cargo test --features lab-roots` | Real TLS end to end with a test authority: trusted, foreign, wrong name, TLS inside TLS. |
| `test-vectors/endpoints.json` | 63 signed lists with the result each must give, written by hand from PROTOCOL.md, including repeated keys and non-canonical base64. |
| `tools/verify_vectors.py` | A second implementation in plain Python, with its own Ed25519 from RFC 8032 and no third-party code, agreeing on every vector. |
| `tests/robustness.rs`, `fuzz/` | Damaged and extreme input never panics; four fuzz targets run nightly in CI. |
| `tools/check_reproducible.sh` | Two builds from different directories, with the release settings, give byte-identical libraries with no path of the build machine in them. |
| Release builds | Made with Rust 1.93.1 (`tools/release_env.sh`); `SeyLockFFI.xcframework.zip` and the Android libraries come out byte-identical from any directory, so anyone can check them against the source. |
| `tools/netem_lab.sh` | The Linux network lab: real TLS, `iptables` blocking, `tc netem` latency and loss. |
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

- **Stream mode:** raw TCP and TLS through the same signed paths, for
  protocols that are not HTTP (IMAP and SMTP, XMPP, messenger protocols).
- **Proxyless and less recognisable TLS:**
  - ClientHello fragmentation against filtering by server name;
  - Encrypted Client Hello where the CDN supports it;
  - a published JA4 fingerprint report.
- **A racing delay derived from measured handshakes**, so slow networks stop
  paying for racing in extra connections ([RACE_LAB.md](RACE_LAB.md)).
- **Integrations in existing open-source apps**, and a Dart/Flutter package.
- **Open blocking statistics:** which ways in work on which networks,
  aggregated, opt-in, and published only after review of the privacy risks.
- **The AAR on Maven Central** (today it is a release asset, as the
  XCFramework is for the Swift package).
- **An external security audit** ([AUDIT.md](AUDIT.md)).

Contributions are welcome: see [CONTRIBUTING.md](CONTRIBUTING.md).

## License

MPL-2.0. You can use the library in closed or open apps. Changes to the
library's own files must be shared under the same license. The Secretly
app itself is AGPL-3.0.
