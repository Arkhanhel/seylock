# Integrating SeyLock in an hour

What an operator and an application developer each do to put SeyLock under an
existing app. The protocol is in [PROTOCOL.md](PROTOCOL.md), the security
model in [THREAT_MODEL.md](THREAT_MODEL.md).

## 1. The operator: a signed list of ways in

You need one offline signing key and a list of the ways your servers can be
reached.

```sh
# Once. Keep list-signing.key offline; the public key goes into the app.
cargo run --example endpoints_tool -- keygen list-signing.key
```

Describe your services and the ways to reach them. Start from
[`examples/list.v2.example.json`](examples/list.v2.example.json):

- `services`: your own base URLs, by name (`api`, `media`, ...);
- `paths`, any of:
  - `direct`;
  - `ip` — a pinned address, which helps when DNS is blocked;
  - `mirror` — another domain serving the same API;
  - `cdn` — a name behind a CDN;
  - `proxy` — a volunteer TLS proxy (see `server/proxy/tlsproxy` in the
    Secretly repository);
  - `socks`;
  - `tor`;
- `tor_bridges` (optional): Tor bridge lines, if you offer Tor.

Give every new list a larger `issued_at_ms`: clients refuse older lists.

```sh
cargo run --example endpoints_tool -- sign list-signing.key list.json list.signed.json
cargo run --example endpoints_tool -- verify <PUBLIC_KEY_B64> list.signed.json
```

Publish `list.signed.json` through any channel: your server, a mirror, a
link people share, a QR code. The signature makes the channel irrelevant, so
distribute widely.

## 2. The application

Pin the public key in the app. Ship a built-in signed list, so the very first
start works even when your server is unreachable. Then keep two things
between runs:

- **the signed list you accepted last** (the built-in one at first). At each
  start verify it again with `currentIssuedAtMs = 0`, which checks the
  signature and the expiry. A list that arrives later is verified with
  `currentIssuedAtMs` set to the `issued_at_ms` of the one you hold; only a
  newer one passes. Keep it, and pass it to `update`. Verifying the list you
  already hold against its own timestamp fails by design (code 7);
- **the path memory**: `memory` from the status JSON, saved now and then and
  passed back at the next start (`{}` the first time).

### Android (Kotlin)

Download `seylock-0.2.0.aar` from the
[release](https://github.com/Arkhanhel/seylock/releases/tag/v0.2.0) into
`app/libs/` (Maven Central publication is planned):

```kotlin
// build.gradle.kts
dependencies {
    implementation(files("libs/seylock-0.2.0.aar"))
    implementation("net.java.dev.jna:jna:5.17.0@aar")
}
```

SeyLock listens on `http://127.0.0.1`, and since Android 9 an app may not
send plain HTTP unless it says so. The AAR ships a configuration that allows
it for `127.0.0.1` only. Use it in `AndroidManifest.xml`, or copy its
`domain-config` into your own `network_security_config.xml`:

```xml
<application android:networkSecurityConfig="@xml/seylock_network_security_config">
```

Avoid `android:usesCleartextTraffic="true"`: it allows plain HTTP to every
host, not only to the proxy.

```kotlin
val list = SeyLock.verifyList(storedSignedList, PINNED_KEY)  // checked again at each start
val memory = savedMemory ?: "{}"
val proxy = SeyLock.start(
    """{"list":$list,"memory":$memory,"network_id":"$networkId",
       "race":{},"response_timeout_ms":20000}"""
)
```

Then route your HTTP client through it. The OkHttp interceptor in the
README does it in one place.

The AAR has libraries for `arm64-v8a`, `armeabi-v7a` and `x86_64`. JNA also
brings 32-bit `x86`, so limit the app to the three, or a 32-bit x86 device
would install an app that cannot load SeyLock:

```kotlin
android { defaultConfig { ndk { abiFilters += listOf("arm64-v8a", "armeabi-v7a", "x86_64") } } }
```

### iOS and macOS (Swift)

Add the package `https://github.com/Arkhanhel/seylock`, then:

```swift
let list = try SeyLock.verifyList(signedJSON: storedSignedList, publicKeyBase64: pinnedKey)
let memory = savedMemory ?? "{}"
let proxy = try SeyLock.start(policyJSON: """
    {"list":\(list),"memory":\(memory),"network_id":"\(networkID)",
     "race":{},"response_timeout_ms":20000}
    """)
let request = proxy.request(for: URLRequest(url: apiURL), service: "api")
```

iOS may take back a suspended app's listening socket. When the app returns
to the foreground and requests to the proxy fail, save `memory` from the
status, then `stop()` and `start()` again.

The XCFramework's simulator slice is for Apple silicon Macs.

No App Transport Security exception is needed: ATS does not stop requests
to `127.0.0.1`. This was checked in a macOS application with no ATS keys in
its `Info.plist`.

### Rust, C, C++, Go

Rust: the `seylock` crate (README, "Using it from Rust"). Everything else:
[`include/seylock.h`](include/seylock.h) and the static or dynamic library.

## 3. Things that are easy to get wrong

| | Do |
|---|---|
| Signing key | Keep it offline, never on a server. Anyone holding it can redirect all traffic. |
| First start | Ship a signed list inside the app; do not depend on reaching your server to get one. |
| Freshness | Pass the `issued_at_ms` of the list you hold, so old lists are refused. |
| The list over time | Keep the signed list you accepted and verify it at each start with `currentIssuedAtMs = 0`; use the held list's `issued_at_ms` only for lists that arrive later. |
| Racing | Pass `"race": {}`. Without it paths are tried one at a time, as in 0.1. |
| Silent paths | Pass `"response_timeout_ms"` (for example 20000) unless you long-poll: without it, a path that accepts requests and never answers keeps the app waiting on it. |
| Network id | Pass an opaque value, such as a salted hash of the Wi-Fi name, never the name itself, and call `setNetwork` when the network changes. |
| Path memory | Persist `memory` from the status JSON and pass it back at the next start, so the path that worked is tried first. |
| Requests | Requests go out once; there are no automatic retries of bodies. Keep your own retry logic as it is. |
| Cookies | Every service is reached at the same local address. If your services set cookies, keep one cookie store per service. HTTP caches are kept apart by the `Vary` header the proxy adds. |
| Clock | Trust a server `Date` header only when `x-transport-path` is `direct` or `ip`. |
| Content | SeyLock does not encrypt your content. Mirror and CDN operators see the HTTP layer, so keep your application's own encryption and request signing. |
| Android plain HTTP | Use the shipped `seylock_network_security_config`, never `usesCleartextTraffic="true"`; otherwise the first request fails with "Cleartext HTTP traffic to 127.0.0.1 not permitted". |
| Tor | Allow it (`allow_tor`) only with the user's consent, and show its progress from the status (`tor`), because a first start can take tens of seconds. |

## 4. Checking it works

- `cargo run --release --example race_lab`: what racing changes on a network
  that drops packets.
- `cargo run --example endpoints_tool -- serve <KEY> list.signed.json`: the
  proxy with your own list, and a `curl` line to try. The response header
  `x-transport-path` names the path that worked.
- `tor_probe` in `tor/examples`: one request through Tor from any device,
  including an Android phone over `adb`.
