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

The results table goes here from a full run: CI → `lab` job → artifact
`netem-lab`, or a run on any Linux machine.

## Still to measure

- Measurements on real censored networks, with the consent of the people
  running them.
