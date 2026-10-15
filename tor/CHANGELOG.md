# Changelog

## 0.1.0 (unreleased)

First version.

- `ArtiConnector`: a Tor client for SeyLock's `tor` path, built on arti 0.47.
  It bootstraps in the background and reports its progress to SeyLock's
  status.
- Bridges through pluggable transports that are already running
  (`TorSettings::bridges`, `TorSettings::transports`).
- C ABI: `seylock_tor_enable`, `seylock_tor_disable`. The library also
  carries SeyLock's whole C ABI.
- `bundled-sqlite` feature for Android.
- Bridges from SeyLock's signed list are applied in place. Bridges whose
  transport is not running are skipped.
- Bridges from the list in force when the connector is created are part of
  the first bootstrap, so a bridge-only setup never contacts the public relays
  directly.
- Lock files that arti creates (`state.lock`, `dir.lock`) are narrowed to the
  owner before start. Under a permissive umask they were writable by everyone,
  and arti then refused its own directory on the next start; this was found on
  an Android phone.
- Example `tor_probe`: one request through SeyLock and Tor, for checking a
  device without an application. It accepts bridges and a running transport.
