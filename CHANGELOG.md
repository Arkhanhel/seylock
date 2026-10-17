# Changelog

## 0.2.0 — 17 October 2026

0.2.0 rather than 0.1.2: public structs gained fields since 0.1.1, which
breaks Rust code that builds them field by field.

### Breaking for Rust code

- `Policy`, `PolicyInput`, `EndpointList` and `runtime::Status` are
  `#[non_exhaustive]`, so later fields will not break callers again. Build
  them with `Policy::new(list)`, `PolicyInput::new(list)`,
  `EndpointList::v2(...)` or `EndpointList::v1(...)` and set the fields you
  need.
- `seylock_update` and `seylock_set_network` are `unsafe extern "C"`, like
  the other functions that take pointers. Nothing changes for C callers.

### Fixed

- A path that accepts a request and then stays silent no longer holds the
  application forever: the new `response_timeout_ms` (policy JSON and
  `Policy`) answers `504` and records the path as failed, so the next request
  tries another. Off by default, so long polling keeps working; it applies to
  requests with a body of at most 64 KiB, as larger uploads may still be in
  transit.
- A `502` or `504` from a mirror, CDN name or proxy no longer makes that path
  the current one; the response still reaches the client unchanged.
- A client breaking off its own upload no longer marks the path as failed.
- An outcome is no longer recorded against a network or list that changed
  while the request was in flight.
- Stopping the proxy, or dropping its handle, now closes every open
  connection and tunnel, not only the listener.
- The TLS client names the `ring` provider instead of relying on the
  process default, which panicked when another dependency enabled a second
  rustls provider.
- A local client must send its request head within 30 seconds, and a failing
  `accept` backs off instead of spinning.
- IPv6 literal base URLs (`https://[2001:db8::1]`) work.
- Any `Upgrade` protocol is tunnelled after a `101`, not only WebSocket.
- Responses carry `Vary: x-transport-service` (and the format 1 name), so an
  HTTP cache cannot answer one service with another's response.
- `update` compares whole lists, not only `issued_at_ms`, before keeping the
  path memory.
- A failure dated in the future no longer demotes a path; memory passed in
  with more than 32 networks is trimmed to the limit.
- Installing a Tor connector and replacing the list's bridges can no longer
  interleave so that the new connector misses the new bridges.
- Repeated JSON keys are refused everywhere, the `services` and `targets`
  maps included (code 4; code 1 in the envelope), and the Python verifier
  now refuses them and non-canonical base64 as Rust does. Test vectors: 63.
- `endpoints_tool keygen` creates the signing key readable by its owner only.
- Release builds: no path of the build machine is left in the libraries
  (it was, hundreds of times), Android libraries are explicitly aligned to
  16 KB pages whatever the NDK, and the XCFramework zip is deterministic.
  With the pinned toolchain (Rust 1.93.1) the zip and the Android libraries
  are byte-identical from any directory. The module map sits in
  `Headers/SeyLockFFI/`, so it cannot collide with another XCFramework's.

### Added

- Android: the AAR ships `seylock_network_security_config`, which allows
  plain HTTP to the proxy on `127.0.0.1` and nowhere else. Without it a
  current Android application refuses the first request ("Cleartext HTTP
  traffic to 127.0.0.1 not permitted"). Found by building a minified
  application against the release AAR; the device test now uses the shipped
  configuration instead of allowing plain HTTP everywhere.
- Install instructions: the AAR is a release asset until it is on Maven
  Central. No App Transport Security exception is needed on Apple platforms.
- Network lab on Linux (`tools/netem_lab.sh`, `examples/netem_lab.rs`): two
  network namespaces, blocking by `iptables` (silent drop, reset on the TLS
  server name), latency and loss by `tc netem`, real TCP and TLS 1.3. It
  measures the first request one path at a time and racing, and counts the
  connections the server receives, so the cost of racing on a slow open
  network is measured, not estimated. Runs in CI on every push (short) and
  on demand (100 runs per row).
- Real TLS tested end to end (`tests/lab_tls.rs`): a trusted certificate is
  accepted, one from another authority or for another name is refused, and
  the volunteer `proxy` path carries TLS inside TLS.
- `lab-roots` feature, off by default and never for applications: lets the
  lab and the TLS tests trust their own test authority.
- INTEGRATING.md: the operator's and the developer's steps, and the things
  that are easy to get wrong.
- Swift package: a prebuilt XCFramework (iOS, iOS simulator, macOS) built by
  `tools/build_xcframework.sh`, and a Swift API with typed errors and a
  `URLRequest` helper. Tests include a real request through the proxy.
- Android library `io.github.arkhanhel:seylock`: libseylock.so for three ABIs
  and a Kotlin API through JNA, with typed exceptions and URL and header
  helpers. Tested on the JVM and on an Android 15 emulator with a real
  request through the proxy.
- `include/seylock.h`: the C ABI with its ownership rules and every return
  code, checked against the library in CI (`tools/check_c_abi.sh`).
  `tor/include/seylock_tor.h` for the two functions of `seylock-tor`.
- The `tor` path works when a Tor client is installed: a new `tor` module
  with a `TorConnector` hook, which the separate `seylock-tor` crate
  implements with arti. The core gains no dependencies.
- Runtime status reports the Tor state (`tor`), absent without a connector.
- `runtime::handle()` gives companion crates the proxy's runtime.
- Connect timeout for `tor` is 60 s, enough for a cold Tor start.
- Format 2 lists may carry Tor bridge lines (`tor_bridges`), checked for count,
  length and printable ASCII (new rejection code 11) and handed to the
  installed Tor connector whenever the list changes.
- `tor::list_bridges()`, so a connector can include the list's bridges from
  its first bootstrap.

- README: who the library is for, how it works, badges, an up-to-date status
  and roadmap.

## 0.1.1 — 15 October 2026

First release on crates.io.

- rustls 0.23.46, for RUSTSEC-2026-0346, -0347, -0348 and -0349 (published
  14 October 2026). None of them reaches SeyLock as built: it does not use
  ECH (0347), does not enable the `brotli` feature (0348), uses the `ring`
  provider, which offers no post-quantum group to downgrade from (0349), and
  never formats session values (0346). The update keeps the dependency audit
  clean.
- CI: the dependency audit job has the permission it needs to report.

## 0.1.0 — 15 October 2026 (GitHub only, not published to crates.io)

First public version, under the name SeyLock (crate `seylock`). It was
developed inside the Secretly messenger as `secretly_transport`; the C ABI
functions are now `seylock_*`.

- Signed endpoint lists: Ed25519 over a context string and the exact
  document bytes; only newer lists are accepted.
- Paths: `direct`, `ip`, `mirror`, `cdn`, `proxy` (TLS in TLS through a
  volunteer proxy), `socks` (SOCKS5). `tor` is reserved.
- Per-network memory of the path that worked, with failed paths pushed back
  for six hours.
- A path counts as working only after a request through it succeeded.
- Local reverse proxy on loopback with a random token, WebSocket tunnelling
  and an `x-secretly-path` response header.
- C ABI for clients in other languages.
- Example tool: generate a key, sign and verify a list, run the proxy.
- List format 2: any named services (`services`, and `targets` on `mirror`
  and `cdn` paths) instead of the fixed pair `keys` and `relay`, with its own
  signing context and two new rejection codes (9, 10). Format 1 lists, headers
  and C ABI behave exactly as before.
- Neutral header names: `x-transport-token`, `x-transport-service`,
  `x-transport-path`. The format 1 names keep working.
- The proxy token is compared in constant time.
- Paths race at the connection stage (Happy Eyeballs, RFC 8305): the next path
  starts after 250 ms or as soon as the previous one fails, with at most three
  attempts in flight. Requests never race. On a network that silently drops
  `direct` and `ip`, the first request takes 0.5 s instead of 12 s
  (`RACE_LAB.md`, `examples/race_lab.rs`). Callers of the C ABI that do not
  pass `race` keep the one-at-a-time behaviour of earlier builds.
- Live tests take their server from environment variables.
- README examples are compiled as doctests.
- Test vectors (`test-vectors/endpoints.json`, 47 cases) and a second,
  independent implementation in plain Python (`tools/verify_vectors.py`).
- Robustness tests and four cargo-fuzz targets.
- Times from the caller and from saved path memory are handled with
  saturating arithmetic; extreme values used to overflow.
- Reproducible builds: on macOS and iOS the dynamic library's install name is
  `@rpath/...` instead of the absolute build path, so two builds from
  different directories are byte-identical (`tools/check_reproducible.sh`).
- `THREAT_MODEL.md`: adversaries, guarantees, limits and the scope for an
  independent audit.
