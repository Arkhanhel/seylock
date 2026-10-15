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

## Still to measure

- A Linux lab with `iptables` and `tc netem`, real TLS and added latency, to
  count extra connections on a slow open network. This is the cost of racing
  that loopback cannot show.
- Measurements on real censored networks, with the consent of the people
  running them.
