# Racing paths: measurements

How long the **first request on a new network** takes when some ways to the
server are blocked: trying paths one at a time, as version 0.1 did, against
racing them at the connection stage.

Anyone can repeat this:

```sh
cargo run --release --example race_lab -- 20
```

## Results

14 October 2026, macOS 27.0.1, Rust 1.93.1. Each row is 20 cold runs: a fresh
proxy with no memory of earlier networks, one request.

| Scenario | Mode | OK | Median, s | 95th pct, s | Server connections per request |
|---|---|---:|---:|---:|---:|
| A | one at a time (0.1) | 20/20 | 12.01 | 12.01 | 1.00 |
| A | **racing (default)** | 20/20 | **0.51** | 0.51 | 1.00 |
| A | racing, 5 at once | 20/20 | 0.51 | 0.51 | 1.00 |
| B | one at a time (0.1) | 20/20 | 0.00 | 0.00 | 1.00 |
| B | **racing (default)** | 20/20 | **0.00** | 0.00 | 1.00 |
| C | one at a time (0.1) | 20/20 | 36.02 | 36.02 | 1.00 |
| C | **racing (default)** | 20/20 | **6.26** | 6.26 | 1.00 |
| C | racing, 5 at once | 20/20 | 1.02 | 1.02 | 1.00 |
| D | one at a time (0.1) | 20/20 | 0.00 | 0.00 | 1.00 |
| D | **racing (default)** | 20/20 | **0.00** | 0.00 | 1.00 |

The default is 250 ms between starts and at most 3 attempts at once.

| Scenario | What is blocked | What works |
|---|---|---|
| A | `direct` and `ip` silently dropped | a mirror |
| B | `direct` and `ip` reset | a CDN name |
| C | `direct`, `ip`, the mirror and the CDN name silently dropped | only the proxy |
| D | nothing | everything |

## What the numbers say

- **When packets are silently dropped, racing changes everything.**
  - Scenario A goes from 12 s to half a second, 24 times faster.
  - Scenario C goes from 36 s to 6.3 s with the default, and to 1 s with five
    attempts at once.

  Silent dropping is the common way to block: the client cannot tell a blocked
  server from a slow one, and one at a time it waits out every timeout (6 s
  for `direct` and `ip`, 12 s for the others).
- **When the network refuses at once (B), racing changes nothing.** A refused
  attempt frees its slot immediately in both modes.
- **When nothing is blocked (D), racing costs nothing here:** one connection
  per request, as before.
- **The limit of three at once is what holds C at 6.3 s.** Four silent paths
  stand ahead of the proxy, so the proxy can start only when the first of
  them times out. Five at once removes that wait.

  The default stays at three for a reason this lab cannot show: on a slow but
  open network, a TLS handshake that takes longer than 250 ms lets the next
  attempt start, and each extra attempt is an extra connection to a server.
  An application that expects heavy blocking can raise the limit
  (`"race": {"max_parallel": 5}`).

## What is real and what is simulated

| Part | How |
|---|---|
| Silent drop | **Real.** Connections go to private addresses that nothing answers (`10.255.255.1` and the next three). The operating system waits for a SYN-ACK that never comes. The lab checks first that these addresses stay silent and stops if they do not. |
| Reset | **Real.** A closed port on loopback refuses at once. |
| Working server | An HTTP server on loopback. |
| Working proxy (C) | A SOCKS5 server on loopback, standing in for a volunteer proxy with an open route. The `proxy` path needs TLS to a real certificate and cannot run on loopback. |
| TLS and latency | **Absent.** Everything is plain HTTP on loopback. On a real network each successful path adds one or two round trips for TCP and TLS; the blocked paths cost the same timeouts as here. |

So the times for the successful paths here are lower bounds. The savings are
not: they come from the timeouts of blocked paths, which are the same on any
network.

## The Linux lab: real TLS, latency and loss

The lab above runs on loopback, so it cannot show what racing costs on a slow
network that blocks nothing: when a TLS handshake takes longer than 250 ms,
the next attempt starts, and each extra attempt is an extra connection to a
server. `tools/netem_lab.sh` measures that on Linux:

```sh
tools/netem_lab.sh            # 100 runs per row, 10 one at a time
tools/netem_lab.sh 3 1        # a quick check
```

- Two network namespaces joined by a virtual cable. The server holds one
  address per path (`direct`, `ip`, `mirror`, `cdn`, and a volunteer proxy
  that carries TLS inside TLS); the client resolves the lab names through its
  own hosts file.
- Blocking is done by `iptables` in the client's namespace: silent drop by
  address, and a reset on the server name in the TLS ClientHello, as a
  censor's DPI does. Latency and loss are `tc netem` on both ends.
- Everything is real TCP and TLS 1.3 with certificate checks. The client
  trusts the lab's own certificate authority through the `lab-roots` feature,
  which no application enables.
- After every request the client reads the server's counters, so the table
  shows the connections each request cost the server, by address.
- The script checks that each scenario was answered only by the paths it
  leaves open, so a rule that silently failed to apply cannot pass as a
  result.

| Scenario | Network |
|---|---|
| A | `direct` and `ip` silently dropped; RTT 100 ms |
| B | connections reset on the SNI of `api` and `mirror`; RTT 100 ms |
| C | everything but the volunteer proxy silently dropped; RTT 100 ms |
| D | nothing blocked, slow network: RTT 800 ms, 5 % loss each way |
| E | nothing blocked, ordinary network: RTT 100 ms |

### Results

17 October 2026. GitHub Actions `ubuntu-24.04`, Linux 6.17.0-1022-azure,
Rust 1.99.1. Each racing row is 100 cold runs and each one-at-a-time row is
10, since one path at a time only adds up timeouts. Every request got an
answer.

"Connections" counts the TCP connections the server accepted per request, so
it shows what racing costs the server.

| Scenario | Mode | Median, s | 95th pct, s | Max, s | Connections | Answered by |
|---|---|---:|---:|---:|---:|---|
| A | one at a time (0.1) | 12.31 | 12.40 | 12.40 | 1.00 | mirror |
| A | **racing (default)** | **0.80** | 0.81 | 0.81 | 1.00 | mirror |
| A | racing, 5 at once | 0.80 | 0.81 | 0.81 | 1.00 | mirror |
| A | racing, 1 s apart | 2.31 | 2.31 | 2.31 | 1.00 | mirror |
| B | one at a time (0.1) | 0.60 | 0.80 | 0.80 | 4.00 | cdn |
| B | **racing (default)** | **0.60** | 0.60 | 0.60 | 4.00 | cdn |
| B | racing, 5 at once | 0.60 | 0.60 | 0.75 | 3.99 | cdn |
| B | racing, 1 s apart | 0.60 | 0.60 | 0.61 | 4.00 | cdn |
| C | one at a time (0.1) | 36.41 | 36.51 | 36.51 | 1.00 | proxy |
| C | **racing (default)** | **6.66** | 6.66 | 6.66 | 1.00 | proxy |
| C | racing, 5 at once | 1.41 | 1.41 | 1.41 | 1.00 | proxy |
| C | racing, 1 s apart | 7.41 | 7.41 | 7.41 | 1.00 | proxy |
| D | one at a time (0.1) | 2.40 | 6.91 | 6.91 | 1.00 | direct |
| D | **racing (default)** | **2.40** | 5.04 | 6.08 | **2.73** | direct 89, ip 10, mirror 1 |
| D | racing, 5 at once | 2.40 | 5.02 | 5.88 | 3.93 | direct 81, ip 15, mirror 4 |
| D | racing, 1 s apart | 2.40 | 5.07 | 8.29 | 1.19 | direct 85, ip 15 |
| E | one at a time (0.1) | 0.30 | 0.30 | 0.30 | 1.00 | direct |
| E | **racing (default)** | **0.30** | 0.30 | 0.30 | 1.00 | direct |
| E | racing, 5 at once | 0.30 | 0.30 | 0.30 | 1.00 | direct |
| E | racing, 1 s apart | 0.30 | 0.30 | 0.30 | 1.00 | direct |

### What the Linux numbers say

- **With real TLS and a 100 ms round trip, the loopback results hold.**
  - Scenario A goes from 12.3 s to 0.8 s.
  - Scenario C goes from 36.4 s to 6.7 s with the default, and to 1.4 s with
    five attempts at once.

  The successful paths now pay for TCP and TLS round trips, which loopback
  could not show.
- **A reset by server name costs one connection per blocked path, in any
  mode (B).** The censor lets the TCP handshake through and resets on the
  ClientHello, so the server sees `direct`, `ip` and `mirror` connect before
  the CDN name answers. Racing changes nothing here: resets are fast either
  way.
- **On a slow open network (D) racing costs connections, not time.**
  - The median is the same in every mode, 2.4 s, and racing shortens the tail
    a little (95th percentile 5.0 s against 6.9 s one at a time, from only 10
    runs).
  - The cost: with the default 250 ms, a TLS handshake over an 800 ms round
    trip lets two more attempts start, so the server gets 2.7 connections per
    request instead of 1.
  - With 1 s between starts it gets 1.2, with nearly the same tail.
  - Next step: derive the delay from handshake times measured on the
    network, as RFC 8305 allows, so slow networks stop paying for racing.
- **On an ordinary network (E) racing costs nothing:** 0.3 s and one
  connection, in every mode.

## Still to measure

- Measurements on real censored networks, with the consent of the people
  running them.
