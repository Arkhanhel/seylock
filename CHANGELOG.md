# Changelog

## 0.1.1 (unreleased)

- rustls 0.23.46, for RUSTSEC-2026-0346, -0347, -0348 and -0349 (published
  14 October 2026). None of them reaches SeyLock as built: it does not use
  ECH (0347), does not enable the `brotli` feature (0348), uses the `ring`
  provider, which offers no post-quantum group to downgrade from (0349), and
  never formats session values (0346). The update keeps the dependency audit
  clean.
- CI: the dependency audit job has the permission it needs to report.

## 0.1.0

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
