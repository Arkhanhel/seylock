#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# SPDX-FileCopyrightText: 2025-2026 Yurii Arkhanhelskyi
#
# The network lab on Linux: real TCP and TLS between two network namespaces,
# blocking by iptables, latency and loss by tc netem. Measures the first
# request on a new network, one path at a time (0.1) against racing, and
# counts the connections the server receives. See RACE_LAB.md.
#
#   tools/netem_lab.sh [runs] [runs-one-at-a-time]     # default: 100 10
#
# Needs root for the namespaces (uses sudo when not root), and ip, iptables
# with the string match, and tc with netem. Writes target/netem_lab/results.md.
set -euo pipefail
cd "$(dirname "$0")/.."

RUNS=${1:-100}
RUNS_SEQUENTIAL=${2:-10}
CL=seylock-lab-client
SV=seylock-lab-server
OUT=target/netem_lab/results.md

if [ "$(uname -s)" != Linux ]; then
  echo "netem_lab: Linux only (network namespaces, iptables, tc netem)" >&2
  exit 2
fi
SUDO=""
[ "$(id -u)" -eq 0 ] || SUDO=sudo
for tool in ip iptables tc; do
  $SUDO sh -c "command -v $tool" >/dev/null || { echo "netem_lab: $tool is missing" >&2; exit 2; }
done

# The netem queue discipline and the iptables string match are modules on
# many kernels; load them if they are not built in.
$SUDO modprobe sch_netem 2>/dev/null || true
$SUDO modprobe xt_string 2>/dev/null || true

cargo build --release --locked --features lab-roots --example netem_lab
BIN=$PWD/target/release/examples/netem_lab
WORK=$(mktemp -d)
chmod 755 "$WORK"
in_cl() { $SUDO ip netns exec "$CL" "$@"; }
in_sv() { $SUDO ip netns exec "$SV" "$@"; }

teardown() {
  $SUDO ip netns pids "$SV" 2>/dev/null | xargs -r $SUDO kill 2>/dev/null || true
  $SUDO ip netns del "$CL" 2>/dev/null || true
  $SUDO ip netns del "$SV" 2>/dev/null || true
  $SUDO rm -rf "/etc/netns/$CL"
}
trap 'teardown; $SUDO rm -rf "$WORK"' EXIT
teardown
mkdir -p "$(dirname "$OUT")"
LOG=$(dirname "$OUT")/server.log

# Two namespaces joined by a veth pair. The server holds one address per
# path; the client resolves the lab names through its own hosts file.
$SUDO ip netns add "$CL"
$SUDO ip netns add "$SV"
$SUDO ip link add cl0 netns "$CL" type veth peer name sv0 netns "$SV"
in_cl ip addr add 10.77.0.1/24 dev cl0
for n in 10 11 12 13 14; do in_sv ip addr add "10.77.0.$n/24" dev sv0; done
for ns in "$CL" "$SV"; do
  $SUDO ip netns exec "$ns" ip link set lo up
done
in_cl ip link set cl0 up
in_sv ip link set sv0 up
$SUDO mkdir -p "/etc/netns/$CL"
printf '%s\n' \
  "127.0.0.1 localhost" \
  "10.77.0.10 api.lab.test" \
  "10.77.0.12 mirror.lab.test" \
  "10.77.0.13 cdn.lab.test" \
  "10.77.0.14 proxy.lab.test" | $SUDO tee "/etc/netns/$CL/hosts" >/dev/null

in_sv "$BIN" serve "$WORK" >"$LOG" 2>&1 &
for _ in $(seq 100); do
  [ -S "$WORK/stats.sock" ] && [ -s "$WORK/ca.der" ] && break
  sleep 0.1
done
[ -S "$WORK/stats.sock" ] || { cat "$LOG" >&2; echo "netem_lab: server did not start" >&2; exit 1; }

# Network conditions: one-way delay in ms and loss in % on both ends, so the
# round trip is twice the delay.
network() {
  in_cl tc qdisc replace dev cl0 root netem delay "${1}ms" loss "${2}%"
  in_sv tc qdisc replace dev sv0 root netem delay "${1}ms" loss "${2}%"
  in_cl iptables -F OUTPUT
}
drop() {
  for ip in "$@"; do in_cl iptables -A OUTPUT -p tcp -d "$ip" -j DROP; done
}
# Reset by the server name in the TLS ClientHello, as a censor's DPI does.
reset_sni() {
  for name in "$@"; do
    in_cl iptables -A OUTPUT -p tcp --dport 443 -m string --string "$name" --algo bm \
      -j REJECT --reject-with tcp-reset
  done
}

# Checks that a scenario's rows were answered only by paths it leaves open,
# so a rule that silently failed to apply cannot pass as a result.
expect_answered_by() {
  local scenario=$1 allowed=$2 rows
  rows=$(grep "^| $scenario |" "$OUT")
  while IFS= read -r row; do
    local by
    by=$(printf '%s' "$row" | awk -F'|' '{print $11}')
    for word in $(printf '%s' "$by" | tr ',' ' ' | tr -d '0-9–'); do
      case " $allowed " in
        *" $word "*) ;;
        *) echo "netem_lab: scenario $scenario answered by '$word', expected only: $allowed" >&2
           exit 1 ;;
      esac
    done
  done <<<"$rows"
}

measure() {
  local scenario=$1 settle_ms=$2
  echo "netem_lab: scenario $scenario" >&2
  in_cl "$BIN" run "$WORK" "$scenario" "$RUNS" "$RUNS_SEQUENTIAL" "$settle_ms" | tee -a "$OUT"
}

{
  echo "# Network lab results"
  echo
  echo "$(date -u +%Y-%m-%d), Linux $(uname -r), $(rustc --version | cut -d' ' -f1-2)," \
    "$RUNS cold runs per row ($RUNS_SEQUENTIAL one at a time). Real TCP and TLS 1.3."
  echo
  in_cl "$BIN" legend
  echo
  in_cl "$BIN" header
} >"$OUT"

network 50 0; drop 10.77.0.10 10.77.0.11;                         measure A 400
network 50 0; reset_sni api.lab.test mirror.lab.test;             measure B 400
network 50 0; drop 10.77.0.10 10.77.0.11 10.77.0.12 10.77.0.13;   measure C 400
network 400 5;                                                    measure D 2000
network 50 0;                                                     measure E 400

# Every row must have answered at least once; partial failures stay in the
# table as they are.
if grep -E '^\| [A-E] \| [^|]+ \| 0/' "$OUT" >&2; then
  echo "netem_lab: the rows above never got an answer" >&2
  exit 1
fi

expect_answered_by A "mirror cdn proxy"
expect_answered_by B "cdn proxy"
expect_answered_by C "proxy"

echo >&2
echo "netem_lab: results in $OUT" >&2
if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
  cat "$OUT" >>"$GITHUB_STEP_SUMMARY"
fi
