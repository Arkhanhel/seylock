# Guide for auditors

Where things are, how to run them, and what we would like a review to look
at first. The adversaries and the formal audit scope are in
[THREAT_MODEL.md](THREAT_MODEL.md); the wire format and acceptance rules are
in [PROTOCOL.md](PROTOCOL.md). Report findings privately as described in
[SECURITY.md](SECURITY.md).

## The code

The core crate is about 4,100 lines of Rust, tests included:

| File | Lines | What it holds |
|---|---:|---|
| `src/proxy.rs` | 1,911 | The loopback reverse proxy: token check, header handling, connection racing, TLS for every path kind, forwarding, upgrades, response timeout, shutdown |
| `src/endpoints.rs` | 1,047 | Signed lists: envelope, signature contexts, version binding, freshness and expiry, shape checks of both formats |
| `src/runtime.rs` | 378 | The process-wide runtime and proxy used by the C ABI; policy input and status |
| `src/ffi.rs` | 257 | The C ABI (`include/seylock.h`) |
| `src/paths.rs` | 251 | Per-network path memory and probe order |
| `src/tor.rs` | 141 | The hook through which a companion crate supplies Tor |
| `src/lib.rs` | 52 | Module list, version |
| `src/lab.rs` | 28 | Test roots, compiled only with the `lab-roots` feature |

There are 16 direct dependencies, 73 crates in all. The ones that matter
most for security:
- `rustls` with the `ring` provider, and `webpki-roots`;
- `ed25519-dalek` for list signatures;
- `hyper` and `hyper-util` for HTTP/1.1;
- `tokio` and `tokio-rustls`;
- `serde_json`;
- `tokio-socks`.

The full list is in `Cargo.lock`.

The bindings are thin and contain no logic of their own:
- Swift: `bindings/swift/Sources/SeyLock/SeyLock.swift`;
- Kotlin: `bindings/android/seylock/src/main/kotlin/.../SeyLock.kt`, through
  JNA.

`tor/` is the separate `seylock-tor` crate, built on arti. It is out of the
core scope, except for the `TorConnector` interface it implements.

## Running everything

```sh
cargo test                                   # unit and integration tests
cargo test --features lab-roots              # adds real TLS end to end
cargo run --example make_vectors && git diff --exit-code test-vectors/
python3 -I tools/verify_vectors.py test-vectors/endpoints.json   # second implementation
tools/check_c_abi.sh                         # a C program against include/seylock.h
tools/check_reproducible.sh                  # two builds, compared byte for byte
cargo +nightly fuzz run list_envelope        # also: list_document, path_memory, policy_json
tools/netem_lab.sh 3 1                       # Linux, root: namespaces, iptables, tc netem
```

CI runs all of these (`.github/workflows/ci.yml`). Fuzzing runs nightly, and
the full lab runs on demand.

## Trust boundaries

```
 signer (offline Ed25519 key)
        │ signed list, over any channel
        ▼
 application ──C ABI / Swift / Kotlin──▶ runtime ──▶ proxy on 127.0.0.1
        ▲                                                 │  ▲
        │ responses                     other local apps ─┘  │ token
        │                                                    │
        └──────────── paths: direct, ip, mirror, cdn, proxy (TLS in TLS),
                      socks, tor ──▶ censor, mirror and CDN operators,
                      volunteer proxies, SOCKS, Tor ──▶ the service
```

- **Inputs that are untrusted:**
  - the signed list until verified;
  - every byte from the network;
  - local connections without the token;
  - path memory and policy JSON passed back by the application (possibly
    damaged storage).
- **Trusted:** the holder of the signing key. Such a holder can redirect all
  traffic; see THREAT_MODEL.md.

## What we would like reviewed first

1. **List verification** (`endpoints.rs`). Signature contexts and the rule
   that the context matches `v`; rollback through `issued_at_ms`; expiry and
   clock tolerance; the refusal of repeated JSON keys and of non-canonical
   base64; any way a list could be read differently by this code and by
   PROTOCOL.md (63 vectors in `test-vectors/` are the starting point).
2. **The local proxy's access control** (`proxy.rs`).
   - The constant-time token check, and the removal of the control headers.
   - Loopback-only accept.
   - The 30-second request-head timeout, and what another application on the
     device can still do without the token.
3. **TLS on every path** (`proxy.rs`, `connect_inner`, `maybe_tls`).
   - The name used for SNI and verification for each path kind, including
     `ip`, `mirror` with an `ip`, IPv6 literals, and TLS inside TLS on
     `proxy`.
   - That the explicit `ring` provider and `webpki-roots` are the only trust.
   - That `lab-roots` cannot reach a release build.
4. **The failover logic**, for ways a censor could pin the client to a bad
   path or make it give up on a good one.
   - `race_connect` and its slot accounting.
   - What counts as success, and 502/504.
   - `response_timeout_ms` and the 64 KiB body rule.
   - The policy generation that keeps stale outcomes from being recorded.
   - Path memory and the 32-network limit.
5. **The C ABI** (`ffi.rs`, `runtime.rs`).
   - Pointer contracts and ownership of returned strings.
   - Panics never crossing the boundary.
   - Calls racing each other on the process-wide proxy.

## Known limitations (accepted, documented)

- **The TLS fingerprint is rustls's own, and traffic shape is not
  disguised.** Proxyless techniques (ClientHello fragmentation, ECH) are
  planned, not present.
- **A signed list may name `http` base URLs.** They exist for loopback
  testing and carry no certificate check. The signer is trusted and is told
  not to publish them.
- **Upstream connections are not reused.** Each request races and connects
  anew, so many concurrent requests open many connections.
- **On a slow open network the fixed 250 ms racing delay costs extra
  connections.** About 2.7 per request at an 800 ms round trip
  (`RACE_LAB.md`); a delay derived from measured handshakes is planned.
- **`response_timeout_ms` is off by default and skips bodies over 64 KiB**,
  so that long polling and large uploads keep working.

## Earlier review

A full code review before 0.2.0 led to the fixes listed under "Fixed" in
[CHANGELOG.md](CHANGELOG.md). Each fix has a test. There has been no
external audit yet.
