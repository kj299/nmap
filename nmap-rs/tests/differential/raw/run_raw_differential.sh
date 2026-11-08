#!/usr/bin/env bash
# Raw-scan differential: each raw scan type, run by C nmap and by nmap-rs as
# root against one target, compared port by port on state and reason.
#
# The target defaults to this host's own non-loopback address, the one an
# outbound packet leaves from. C nmap scans its own address over the loopback
# (`route_dst`: "we need to use a localhost device for these"), since that is
# where the kernel delivers the probe and sends the reply; a port that
# captured on the address's own interface would see no reply and call every
# port filtered, which nmap-rs did until FreeBSD step d. TARGET=127.0.0.1
# runs the same matrix over the loopback.
#
# An IPv6 TARGET runs with -6: the connect scan and every raw scan type (IPv6
# scans step d). nmap-rs's raw IPv6 scans reach this host's own addresses, ::1
# and an address of its own, which go over the loopback as C nmap sends them;
# for any other IPv6 target it still connect-scans (`ipv6-raw-port-scans-unported`,
# step e). A raw scan that fell back to a connect scan fails here rather than
# compare connect rows with raw ones. SCANS overrides the list.
#
# Requires root (raw sockets, BPF) and a --features pcap build; SKIPs without
# them, as run_os_differential.sh does.
#
# Usage: [TARGET=addr] [SCANS="-sS ..."] [NMAP=...] [NMAP_RS=...] run_raw_differential.sh
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_ROOT="$(cd "$HERE/../../.." && pwd)"
OPEN_TCP=18122
OPEN_UDP=18153
CLOSED=18199

NMAP="${NMAP:-$(command -v nmap || true)}"
if [[ -z "$NMAP" || ! -x "$NMAP" ]]; then
  echo "SKIP: C nmap oracle not found (set NMAP=... or install nmap)"; exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "SKIP: raw scans need root"; exit 0
fi
NMAP_RS="${NMAP_RS:-}"
if [[ -z "$NMAP_RS" ]]; then
  for cand in "$RS_ROOT/target/release/nmap-rs" "$RS_ROOT/target/debug/nmap-rs"; do
    if [[ -f "$cand" && -x "$cand" ]]; then NMAP_RS="$cand"; break; fi
  done
fi
if [[ -z "$NMAP_RS" || ! -f "$NMAP_RS" || ! -x "$NMAP_RS" ]]; then
  echo "SKIP: nmap-rs binary not found (build with --features pcap)"; exit 0
fi

TARGET="${TARGET:-$(python3 "$HERE/own_address.py")}"
if [[ "$TARGET" == *:* ]]; then
  FAMILY=6; SIX=(-6); SCANS="${SCANS:--sT -sS -sF -sN -sX -sA -sW -sM -sU}"
else
  FAMILY=4; SIX=(); SCANS="${SCANS:--sS -sF -sN -sX -sA -sW -sM -sU}"
fi
echo "target : $TARGET"
echo "oracle : $NMAP ($("$NMAP" --version | head -1))"
echo "rust   : $NMAP_RS"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [[ -n "${FIXTURE_PID:-}" ]] && kill "$FIXTURE_PID" 2>/dev/null || true' EXIT

# The fixture, on every address: a TCP listener that accepts and drains, a
# UDP socket that never answers (open|filtered), nothing on $CLOSED.
python3 - "$OPEN_TCP" "$OPEN_UDP" "$FAMILY" <<'PY' &
import socket, sys, threading, time
fam, anyaddr = (socket.AF_INET6, "::") if sys.argv[3] == "6" else (socket.AF_INET, "0.0.0.0")
t = socket.socket(fam)
t.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
t.bind((anyaddr, int(sys.argv[1])))
t.listen(64)
u = socket.socket(fam, socket.SOCK_DGRAM)
u.bind((anyaddr, int(sys.argv[2])))
def drain():
    while True:
        try:
            c, _ = t.accept()
        except ConnectionAbortedError:
            continue  # FreeBSD: a connection reset while queued
        c.close()
threading.Thread(target=drain, daemon=True).start()
time.sleep(900)
PY
FIXTURE_PID=$!
sleep 1
# A listener that failed to bind would leave every port closed, and two
# tools agreeing on that would pass vacuously. Check it answers on $TARGET.
python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET6 if $FAMILY == 6 else socket.AF_INET); s.settimeout(2)
sys.exit(0 if s.connect_ex(('$TARGET', $OPEN_TCP)) == 0 else 1)
" || { echo "FAIL: the fixture is not listening on $TARGET:$OPEN_TCP"; exit 1; }

PORTS="$OPEN_TCP,$OPEN_UDP,$CLOSED"
fail=0
for scan in $SCANS; do
  # Three ports take seconds; a run still going after 120 s has hung, and
  # fails on its empty projection rather than stalling the job.
  rm -f "$WORK/c.xml" "$WORK/rs.xml"
  timeout 120 "$NMAP" "${SIX[@]}" "$scan" -Pn -n --reason -p "$PORTS" "$TARGET" -oX "$WORK/c.xml" >/dev/null 2>"$WORK/c.err" || true
  timeout 120 "$NMAP_RS" "${SIX[@]}" "$scan" -Pn -n --reason -p "$PORTS" "$TARGET" -oX "$WORK/rs.xml" >"$WORK/rs.out" 2>&1 || true
  touch "$WORK/c.xml" "$WORK/rs.xml"
  if grep -q "lacks raw-scan support" "$WORK/rs.out"; then
    echo "SKIP: nmap-rs lacks the pcap feature (build with --features pcap)"; exit 0
  fi
  if [[ "$scan" != "-sT" ]] && grep -q "running a connect scan" "$WORK/rs.out"; then
    echo "FAIL [$scan]: nmap-rs fell back to a connect scan:"; grep "connect scan" "$WORK/rs.out"
    fail=1; continue
  fi
  python3 "$HERE/raw_project.py" <"$WORK/c.xml" >"$WORK/c.proj" || true
  python3 "$HERE/raw_project.py" <"$WORK/rs.xml" >"$WORK/rs.proj" || true
  if ! grep -q "/$OPEN_TCP " "$WORK/c.proj"; then
    echo "FAIL [$scan]: C nmap reported no ports"; cat "$WORK/c.err"; fail=1; continue
  fi
  if diff -u "$WORK/c.proj" "$WORK/rs.proj" >"$WORK/diff"; then
    echo "MATCH [$scan]: $(grep -c '/' "$WORK/c.proj") ports"
  else
    echo "DIVERGENCE [$scan] (C nmap -, nmap-rs +):"; cat "$WORK/diff"
    echo "--- nmap-rs output ---"; tail -20 "$WORK/rs.out"
    fail=1
  fi
done
exit "$fail"
