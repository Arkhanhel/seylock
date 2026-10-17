# SeyLock protocol, formats 1 and 2

SeyLock grew out of the Secretly messenger. Format 1 was designed for it,
which is why its signing context and its header names keep a `secretly`
prefix; they stay as they are so that lists already signed, and applications
already released, keep working. Format 2 and the `x-transport-*` headers name
no product.

This document is enough to write a compatible list signer, a compatible
client, or a server that publishes lists. The Rust code in this crate is the
reference implementation.

## 1. Endpoint list

A list is a JSON document:

```json
{
  "v": 1,
  "issued_at_ms": 1791590400000,
  "expires_at_ms": 1823126400000,
  "logical": {
    "keys": "https://keys.example.org",
    "relay": "https://relay.example.org"
  },
  "paths": [ { "kind": "direct" }, ... ]
}
```

| Field | Meaning |
|---|---|
| `v` | Format version. Must be `1`. |
| `issued_at_ms` | When the list was made, Unix milliseconds. Orders lists. |
| `expires_at_ms` | After this moment the list is refused. |
| `logical.keys`, `logical.relay` | The canonical base URLs of the two services. The app addresses requests to these. |
| `paths` | Ways to reach the services, in any order. Each has a `kind`. |

`logical` URLs use `https` (or `http` for local testing). A path prefix in
the URL is allowed and is prepended to every forwarded request path.

### Format 2: any services

Format 1 knows exactly two services, `keys` and `relay`. Format 2 lets a list
name its own, so the library serves any application:

```json
{
  "v": 2,
  "issued_at_ms": 1791590400000,
  "expires_at_ms": 1823126400000,
  "services": {
    "api": "https://api.example.org",
    "media": "https://media.example.org"
  },
  "paths": [
    { "kind": "direct" },
    { "kind": "mirror", "targets": { "api": "https://a.mirror.example.net" } }
  ]
}
```

| Field | Meaning |
|---|---|
| `services` | Canonical base URL of each service, by name. At least 1, at most 16. Replaces `logical`, which must be absent. |
| service name | 1 to 32 bytes of lowercase ASCII letters, digits and `-`, not starting with `-`. |
| `targets` (in `mirror` and `cdn`) | Base URL of that mirror or CDN name for each service it serves. Replaces `keys` and `relay`, which must be absent. Every name must be in `services`. |
| `tor_bridges` | Optional. Tor bridge lines (`obfs4 ...`, `webtunnel ...`, or a plain `address fingerprint`), at most 32, each 1 to 2048 bytes of printable ASCII. The library does not interpret them: it hands them to the installed Tor connector, so bridges are distributed and rotated like the other ways in. |

A mirror or CDN name that has no target for a service is not used for that
service: a request for it skips the path without recording a failure.
Other path kinds reach the service's own base URL, as in format 1.

A format 1 list is still accepted and keeps its meaning. A format 1 list is
equivalent to a format 2 list with `services` `{"keys": …, "relay": …}`.

### Parsing

The document is JSON. Fields not described here are ignored, so a newer
signer may add fields that older clients skip. A path whose `kind` is not in
the table below, a required field that is missing or has the wrong type, and a
number outside its range (`v` is an unsigned 32-bit integer, times are signed
64-bit, `port` is 0 to 65535) make the document invalid (code 4).

A key repeated in any object, the envelope included, is refused: code 1 in
the envelope, code 4 in the document. JSON parsers disagree on which copy of
a repeated key wins, and a signed list must read the same in every
implementation. Fields of the other format may be present when they are
empty or `null` (`"services": {}` in format 1, `"logical": null` in format 2);
with content they make the document invalid.

`test-vectors/endpoints.json` holds signed lists with the result each must
give, from acceptance to every rejection code. `tools/verify_vectors.py` is a
second implementation of this section in plain Python, written from this
document alone; CI checks that it agrees with every vector.

### Path kinds

| `kind` | Fields | Connects to | TLS name (SNI) and `Host` |
|---|---|---|---|
| `direct` | none | the `logical` host | the `logical` host |
| `ip` | `ip` | the given IP, `logical` port | the `logical` host |
| `mirror` | `keys`, `relay`, optional `ip` | the mirror URL's host, or `ip` if set | the mirror URL's host |
| `cdn` | `keys`, `relay` | the CDN URL's host | the CDN URL's host |
| `proxy` | `host`, `port` (default 443) | `host:port`, TLS to it, then TLS to the `logical` host inside | outer: `host`; inner: the `logical` host |
| `socks` | `addr` (`ip:port`) | a SOCKS5 proxy, which connects to the `logical` host by name | the `logical` host |
| `tor` | none | a Tor client the application installs (see below); without one the path fails at once | the `logical` host, inside the Tor stream |

`mirror` and `cdn` are different only in intent and default order: a mirror
is a server or reverse proxy you run, a CDN name is served by a third party.

### Signing

The signed envelope is:

```json
{ "doc": "<the list document as a JSON string>", "sig_b64": "<base64>" }
```

`sig_b64` is a standard base64 Ed25519 signature (64 bytes) over the
signing context of the format followed by the UTF-8 bytes of `doc`. Base64
is strict, for the signature and the public key alike: with `=` padding and
no stray bits in the last character, so only one text encodes given bytes
(code 2 otherwise).

```
format 1:  "secretly-endpoints-v1\n"  || doc
format 2:  "transport-endpoints-v2\n" || doc
```

The format 2 context names no product, so renaming the library or the
application never invalidates signed lists. A client tries both contexts; the
one that verifies must match the `v` inside the document, so a signature made
for one format never vouches for a document of the other.

The signature covers the exact `doc` string, so the signer must not
re-serialize after signing and the client must parse `doc` only after the
signature has been verified. The public key is a standard base64 encoding of
the 32-byte Ed25519 key, pinned in the client.

### Acceptance

A client accepts a signed list only if all of these hold, checked in this
order. The numbers are the error codes returned by `verify_and_parse` and
the C ABI.

| Code | Check |
|---|---|
| 1 | The envelope is valid JSON with `doc` and `sig_b64`. |
| 2 | The key and the signature decode as base64 to 32 and 64 bytes, and the key is a valid Ed25519 point. |
| 3 | The signature verifies with the pinned key, under the context of the document's own format. |
| 4 | `doc` is a valid list document. |
| 5 | `v` is `1` or `2`. |
| 6 | `expires_at_ms` is in the future, and `issued_at_ms` is not more than seven days in the future (clock skew allowance). |
| 7 | `issued_at_ms` is strictly greater than that of the list the client already has. |
| 8 | `paths` is not empty; format 1: both `logical` URLs are set; format 2: `services` is not empty and no base URL in it is empty. |
| 9 | Format 2: every service name is valid, and there are at most 16. |
| 10 | Format 2: every `targets` name is in `services`, with a non-empty URL. |
| 11 | Format 2: `tor_bridges` has at most 32 lines, each 1 to 2048 bytes of printable ASCII. |

A document that mixes the formats — `services`, `targets` or `tor_bridges` in format 1,
`logical`, `keys` or `relay` in format 2 — or a format 1 `mirror` or `cdn`
without both `keys` and `relay`, is rejected with code 4.

Rule 7 is what stops replay of old lists. A server that publishes lists
must give every new list a larger `issued_at_ms`.

A client ships with a built-in list and replaces it only with an accepted
signed list. Lists may arrive from the server itself, from a link a user
shares, or from any other channel: the signature makes the channel
irrelevant.

## 2. Choosing a path

The client keeps a small memory per network. A network is identified by
an opaque `network_id` that the app chooses, for example a hash of the
Wi-Fi name or the mobile carrier code. The memory stores, for each network,
the index of the last path that worked and when each path last failed.

The order for a request on network N is:

1. The path that last worked on N, if it is still allowed.
2. All other allowed paths in the default kind order: `direct`, `ip`,
   `mirror`, `cdn`, `proxy`, `socks`, `tor`. Within a kind, the list order
   is kept. Paths that failed on N within the last six hours go to the end.

While the proxy is running it keeps the path currently in use and moves that
one to the very front, ahead of both the remembered one and the demotion
above. So a path that is working right now is not abandoned because the
memory, which is only written to storage occasionally, still names another.

`socks` and `tor` are allowed only when the app enables them. The memory
keeps at most 32 networks and forgets those with the oldest success, also
when memory passed in at start holds more. A failure dated in the future (the
clock was ahead and has been corrected) does not demote a path.

A path counts as working only after a request through it got an HTTP
response from the server. It is recorded as failed, so the next request
moves on, when:

- it does not connect within its timeout;
- it connects but then drops the request;
- the response is `502` or `504`: a mirror, CDN name or proxy answered but
  could not reach the server (the response still goes to the client as it
  is; any other status, server errors included, comes from the server and
  counts as working);
- the policy sets `response_timeout_ms` and no response head arrives within
  that time after a request with a body of at most 64 KiB has been sent. The
  client then gets `504`. Larger uploads are not timed: their last bytes may
  still be in transit, and on a slow link that can take longer than any
  sensible timeout.

Nothing is recorded when the client breaks off its own request, and nothing
for a request that started before the list, the network or the permissions
changed: its path index or network would be wrong.

### Racing

Paths are tried in that order, but they race at the connection stage, in the
manner of Happy Eyeballs (RFC 8305):

1. The first path starts at once.
2. The next one starts when the previous has not connected within
   `delay_ms`, or at once when it failed, as long as fewer than
   `max_parallel` attempts are in flight.
3. The first attempt to connect wins. Connecting means TCP and, for `https`,
   the TLS handshake with certificate verification. The others are dropped.
4. The request is sent once, over the winner. **Requests never race**, so a
   request body is never sent twice.

A failed attempt is recorded as failed. An attempt dropped because another
won is not recorded, since nothing was learned about it.

| Setting | Default | Bounds |
|---|---|---|
| `delay_ms` | 250 | 10 to 5000 |
| `max_parallel` | 3 | 1 to 8; `1` tries one path at a time |

Measurements are in [RACE_LAB.md](RACE_LAB.md).

Connect timeouts are 6 seconds for `direct` and `ip`, 60 seconds for `tor`
(a cold Tor start takes 10 to 20 seconds before the first circuit), and 12
seconds for the others.

### The `tor` path

The core library contains no Tor client. An application that wants one
installs a connector through the `tor` module (Rust) or, from other
languages, links `seylock-tor` and calls `seylock_tor_enable`. The connector
opens a stream to the `logical` host and port through Tor; TLS to that host
runs inside it, as on the `socks` path. Without a connector the path fails at
once and is recorded as failed like any other.

A path whose target cannot be resolved at all — a `mirror` or `cdn` entry
whose URL is not a valid `http`/`https` address — is skipped without being
recorded as failed. It is a fault in the list, not in the network, and
remembering it per network would be meaningless.

## 3. The local proxy

The library listens on `127.0.0.1` on a random port and accepts
connections only from loopback addresses. Each request must carry:

| Header | Value |
|---|---|
| `x-transport-token` | the random token returned at start |
| `x-transport-service` | a service name from the list; for a format 1 list, `keys` or `relay` |

The format 1 spellings `x-secretly-proxy-token` and `x-secretly-upstream` are
accepted in their place. Service names are compared in lowercase.

The request line keeps the original path and query. The proxy:

- removes all four control headers, whichever spelling was used;
- prepends the target's path prefix to the path;
- sets `Host` to the target's host, with the port if it is not the default;
- forwards the request over HTTP/1.1, and tunnels upgrades (WebSocket or
  any other `Upgrade` protocol) in both directions after a `101`;
- adds `x-transport-path: <kind>` and, for format 1 clients,
  `x-secretly-path: <kind>` to the response, naming the path used;
- adds `Vary: x-transport-service` and `Vary: x-secretly-upstream`: every
  service is reached at the same local URL, and this keeps an HTTP cache from
  answering a request for one service with another's response. Cookies are
  not separated this way; an application whose services set cookies should
  keep one cookie store per service.

A client must send the request head within 30 seconds; a connection that
does not is closed, so no other program on the device can hold connections
open without the token. Stopping the proxy closes the listener and every open
connection, tunnels included.

Proxy-generated errors:

| Status | Meaning |
|---|---|
| 403 | Missing or wrong token. Nothing was sent anywhere. |
| 400 | Missing service, a service the list does not name, or a request the proxy cannot rewrite. Nothing was sent anywhere. |
| 503 | No path is allowed by the policy. |
| 502 | Every path failed, none of the allowed paths serves the service, or the chosen path dropped the request. |
| 504 | `response_timeout_ms` passed with no response. |

The app should trust a server `Date` header for clock correction only when
`x-transport-path` is `direct` or `ip`, because other paths pass through
third-party machines.

## 4. C ABI

All functions are safe to call from any thread. They never unwind across
the boundary: a panic becomes error code 100, and so does a NULL or non-UTF-8
argument. Strings passed in are NUL-terminated UTF-8. Strings returned must be freed with
`seylock_string_free`.

| Function | Returns |
|---|---|
| `seylock_version()` | library version string |
| `seylock_endpoints_verify(signed_json, key_b64, now_ms, current_issued_at_ms, out_doc)` | 0 or an acceptance code from §1; on 0, `out_doc` receives the list as JSON |
| `seylock_start(policy_json, out_port, out_token)` | 0, 101 (already started), 103 (cannot bind) or 104 (bad JSON) |
| `seylock_update(policy_json)` | 0, 100, 102 (not started) or 104 |
| `seylock_set_network(network_id)` | 0, 100 or 102 |
| `seylock_status_json()` | status JSON, or NULL if not started |
| `seylock_stop()` | 0 or 102 |

`policy_json`:

```json
{
  "list": { "...": "an accepted list document" },
  "memory": { "networks": { } },
  "network_id": "wifi:3f2a...",
  "allow_tor": false,
  "allow_socks": false,
  "race": { "delay_ms": 250, "max_parallel": 3 },
  "response_timeout_ms": 20000
}
```

When `race` is absent, the proxy tries one path at a time, as version 0.1
did, so an application written for 0.1 behaves exactly as before. `"race": {}`
selects the defaults above. `response_timeout_ms` (clamped to 1 000–600 000)
is absent by default, which never times out and suits long polling; see §2.

`memory` is read only by `start`. `update` ignores it, and it clears the
running memory by itself when the list changes in any way: path indexes
refer to positions in the list, so a new list makes the old notes meaningless.

Status JSON has `port`, `current` (path index or null), `current_kind`,
`network_id`, `memory` (to persist between runs) and `issued_at_ms`. When a
Tor connector is installed it also has `tor`: `{"state":"bootstrapping",
"percent":N}`, `{"state":"ready"}` or `{"state":"failed","reason":"..."}`.
Without a connector the field is absent.
