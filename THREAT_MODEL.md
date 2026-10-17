# Threat model

What this library protects, against whom, and where its protection ends. It
covers the library only: the confidentiality of messages is the job of the
application's own end-to-end encryption, which the library never sees.

## What the library is for

An application on a phone or computer must reach its servers from a network
that blocks them. The library carries the application's HTTP and WebSocket
requests to those servers by whichever path still works, and it must never be
the reason a request goes to the wrong place or to the wrong party.

## Assets

| Asset | Why it matters |
|---|---|
| The list of ways in | Whoever controls it decides where the application's traffic goes. |
| The identity of the server | A request must reach the real server, or a party the operator chose, never one the censor chose. |
| The proxy's token | Whoever has it can use the proxy as the application. |
| Path memory | It records which networks the device used, under opaque names the application chooses. |
| The application process | A crash in the library takes the application down with it. |

## Adversaries and what they can do

### A censor on the network path

**Can:**
- block any address, name or protocol;
- see the server names (SNI) and addresses the client connects to, the TLS
  fingerprint, traffic timing and volume;
- drop connections silently or reset them.

**Cannot:**
- **Feed the client a list of its own.** Lists are signed with an Ed25519 key
  kept offline; the public key is pinned in the application
  (`endpoints::verify_and_parse`).
- **Roll the client back to an older list** whose addresses it has already
  blocked. A list must be strictly newer than the one in use (rule 7).
- **Reuse a signature made for something else.** The signed message starts
  with a context string, a different one for each format.
- **Impersonate the server.** Every `https` target is verified against the
  Mozilla root store, and the `ip` path keeps the real name for SNI and
  verification. The list decides the scheme: a signed list may also name
  `http` base URLs, which exist for loopback testing and carry no
  certificate check. Nothing stops a signer from publishing them; the signer
  is trusted anyway (see below), and should not.

**Out of reach of this library:** hiding the TLS fingerprint, traffic shape or
the fact that the application is in use. The library's aim is to make
blocking cost more than one address or one DNS entry, not to make traffic
invisible.

### Whoever hands out lists

A list can come from the server, a mirror, a QR code or another person. None
of them is trusted; only the signature is. A party without the signing key
can only withhold lists or replay old ones, and old ones are refused.

### The operator of a mirror or a CDN name

On the `mirror` and `cdn` paths, TLS ends at the mirror's or CDN's own name.
Their operator therefore sees the HTTP layer of every request on that path:
the method, path, headers, sizes and timing, and the client's address.

The application must assume this. In Secretly, message contents are
end-to-end encrypted and requests are signed by the device key, so an
operator can observe and delay, but not read or alter, what it carries. An
application without such protection should not list third-party mirrors.

### A volunteer proxy

On the `proxy` path, TLS to the real server runs inside the volunteer's TLS.
The volunteer sees:
- the client's address;
- the server name it forwards to;
- the volume and timing of the traffic.

It cannot see or alter the contents without a certificate for the real name.

### A SOCKS proxy

The same holds for `socks`: the proxy sees the destination name and the
traffic volume. TLS to the server runs end to end inside it.

### Tor

On the `tor` path (with `seylock-tor` installed), TLS to the server runs
inside the Tor stream.

- The exit relay sees the server name, the port and the traffic volume, but
  not the content.
- The network around the device sees a connection to Tor, or to a bridge.
- Names are resolved by the exit relay, not by the local resolver.

The Tor client is a separate crate, with its own dependency tree of about
370 packages. Applications that do not install it carry none of that code.

### Another application on the same device

The proxy listens on `127.0.0.1` only and drops connections from any other
address. Every request must carry a random 192-bit token that only the
embedding application knows, compared in constant time. The proxy strips the
token and its own headers before forwarding, so they never reach a server.

Another application can find the port, but cannot use the proxy without the
token. Nor can it tie the proxy up: a connection must send its request head
within 30 seconds or is closed, and a failing `accept` (for example when file
descriptors run out) backs off instead of spinning.

### Whoever holds the signing key

The signing key is the root of the whole scheme. With it, an attacker can
publish a newer list that changes the services' own base URLs, not only the
mirrors, and so send all of the application's traffic to servers of its
choosing. Certificate checks then only prove the attacker's own names.

What remains is the application's own protection. In Secretly, message
contents are end-to-end encrypted between devices and requests are signed by
device keys, so such an attacker can block, observe metadata and refuse
service, but cannot read messages or impersonate users.

Therefore:
- the key stays offline;
- lists are signed on a machine that is not a server;
- rotating the key means shipping a new public key in the application.

### Certificate authorities

Trust in the server's identity rests on the Web PKI: any authority in the
Mozilla root store can issue a certificate the library will accept. The
library does not pin certificates. Pinning would make a lost or rotated
certificate a total outage in exactly the networks where re-issuing an update
is hardest.

The roots are compiled in, and nothing at run time adds to them: not the
policy, not the C ABI, not the environment. The one exception is the
`lab-roots` Cargo feature, off by default, which lets the network lab trust
its own test authority (`seylock::lab`). An application must never enable it.
Builds of the library for applications, the XCFramework and the Android
libraries among them, are made without it.

## The process itself

- **No panic crosses the C ABI.** Every exported function that does real
  work is wrapped in `catch_unwind`, and a panic becomes error code 100;
  `seylock_version` and `seylock_string_free` cannot panic. Functions that
  take pointers are declared `unsafe` with their contracts, so Rust callers
  cannot use them by mistake. The release profile keeps
  `panic = "unwind"` for this reason.
- **Pointers are checked.** Pointer arguments are checked for null, and
  strings for valid UTF-8. Strings the library returns are freed only by
  `seylock_string_free`.
- **Damaged input is rejected.** Damaged or extreme input from the caller or
  from saved state (lists, policy JSON, path memory, clock values) is
  rejected or clamped without a panic: `tests/robustness.rs` and four fuzz
  targets in `fuzz/`.
- **Settings cannot run away.** Racing settings are clamped (10 ms to 5 s,
  at most 8 attempts per request) and so is the response timeout (1 s to
  10 min). The limit is per request: concurrent requests each race, and
  upstream connections are not reused, so an application that sends many
  requests at once opens as many connections as a browser would.

## Privacy of saved state

Path memory stores, per network, the index of the path that worked and when
paths failed. Networks are named by the application. Raw Wi-Fi names or
carrier identifiers would make this a log of where the device has been, so
the application should pass a salted hash. The memory keeps at most 32
networks.

## Scope for an independent audit

**In scope:**

1. `endpoints.rs` — signature contexts and the rule that the context must
   match the version, the order of the acceptance checks, freshness and clock
   handling, the shape checks of both formats.
2. `proxy.rs`:
   - the token check and header stripping;
   - resolving targets and `Host`/SNI for each path kind;
   - TLS configuration and certificate verification, including TLS inside
     TLS on `proxy`;
   - cancellation in the connection race, and the guarantee that a request
     is sent once;
   - WebSocket tunnelling.
3. `ffi.rs` and `runtime.rs` — memory safety at the C boundary, the
   process-wide state, and behaviour when calls race each other.
4. `paths.rs` — handling of damaged memory.
5. PROTOCOL.md — whether a compatible implementation built from it alone
   could differ from this one in what it accepts. `test-vectors/` and
   `tools/verify_vectors.py` are the starting point.

**Out of scope:**
- the application's protocol and its end-to-end encryption;
- the servers;
- the volunteer proxy configuration in the Secretly repository;
- dependencies, beyond how this library uses them.
