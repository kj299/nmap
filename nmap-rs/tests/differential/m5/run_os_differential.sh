#!/usr/bin/env bash
# M5 OS-detection differential — prove nmap-rs's fingerprint matches C nmap's, on the
# same host, at the same moment.
#
# Every earlier M5 slice was gated by a C oracle over static vectors or by the real
# nmap-os-db. This is the first gate that exercises the whole path on the wire: build the
# 23-probe battery, put it on a real interface, capture and attribute the replies, and
# assemble a fingerprint. A static oracle cannot check any of that.
#
# The fixture is loopback: listeners on fixed ports give a deterministic open/closed set,
# and the target stack is the same kernel for both tools, so the observed fingerprint must
# agree. os_project.py strips the fields that are legitimately run-to-run variable (the
# SCAN metadata line, and SEQ's SP/GCD/ISR, which sample ISN randomness by design).
#
# Requires root (raw sockets) and a --features pcap build. SKIPs cleanly otherwise, the
# same way the M1 harness does when C nmap is absent.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_ROOT="$(cd "$HERE/../../.." && pwd)"
OPEN_PORTS=(8022 8080)
CLOSED_PORT=9999
TARGET=127.0.0.1

NMAP="${NMAP:-$(command -v nmap || true)}"
if [[ -z "$NMAP" || ! -x "$NMAP" ]]; then
  echo "SKIP: C nmap oracle not found (set NMAP=... or install nmap)"; exit 0
fi
if [[ "$(id -u)" != "0" ]]; then
  echo "SKIP: OS detection needs raw sockets (run as root)"; exit 0
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

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [[ -n "${FIXTURE_PID:-}" ]] && kill "$FIXTURE_PID" 2>/dev/null || true' EXIT

# --- Fixture: loopback listeners so the open/closed set is deterministic -----
python3 - "${OPEN_PORTS[@]}" <<'PY' &
import socket, sys, time
socks = []
for p in (int(a) for a in sys.argv[1:]):
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", p))
    s.listen(16)
    socks.append(s)
time.sleep(600)
PY
FIXTURE_PID=$!
sleep 1

# Verify the fixture actually came up. A listener that failed to bind (a stale process
# holding the port, say) would leave every port closed — and two fingerprints of a host
# with no open TCP port agree trivially, turning this gate into a no-op that reports
# success. Check rather than assume.
for p in "${OPEN_PORTS[@]}"; do
  if ! python3 -c "
import socket, sys
s = socket.socket(); s.settimeout(2)
sys.exit(0 if s.connect_ex(('127.0.0.1', $p)) == 0 else 1)
"; then
    echo "FAIL: fixture port $p is not listening (something else may be holding it)"
    exit 1
  fi
done

PORTS="$(IFS=,; echo "${OPEN_PORTS[*]}"),$CLOSED_PORT"

# `-d` on both: each tool prints the raw fingerprint even when it judges the run unfit to
# submit. Without it the comparison is flaky in a way that has nothing to do with
# fidelity — under load either tool may decide its own timing was poor and withhold the
# fingerprint, and two withheld fingerprints would "agree" vacuously.
echo "== running C nmap -O =="
"$NMAP" -O -d -Pn -p "$PORTS" "$TARGET" >"$WORK/c.out" 2>&1 || true
echo "== running nmap-rs -O =="
"$NMAP_RS" -O -d -Pn -p "$PORTS" "$TARGET" >"$WORK/rs.out" 2>&1 || true

python3 "$HERE/os_project.py" <"$WORK/c.out"  >"$WORK/c.proj"
python3 "$HERE/os_project.py" <"$WORK/rs.out" >"$WORK/rs.proj"

# A build without `pcap` cannot do OS detection at all. It says so on stderr; treat that
# as a SKIP rather than letting an empty projection masquerade as a divergence.
if grep -q "requires a --features pcap build" "$WORK/rs.out"; then
  echo "SKIP: nmap-rs binary lacks the pcap feature (build with --features pcap)"
  echo "      note: a later plain \`cargo build\` overwrites the pcap binary at the same path"
  exit 0
fi

# An empty projection means the tool printed no fingerprint at all — a real failure to
# report, not a match. Without this check two empty files would "agree".
if [[ ! -s "$WORK/c.proj" ]]; then
  echo "FAIL: C nmap produced no fingerprint"; sed -n '1,40p' "$WORK/c.out"; exit 1
fi
if [[ ! -s "$WORK/rs.proj" ]]; then
  echo "FAIL: nmap-rs produced no fingerprint (it may have judged the run unsubmittable)"
  sed -n '1,40p' "$WORK/rs.out"; exit 1
fi

# The comparison is not a plain diff: a few IP-ID attributes are present only when the run
# happened to collect enough samples (see PRESENCE_OPTIONAL in os_project.py), so their
# presence is not comparable between the tools while their values still are.
if python3 "$HERE/os_project.py" "$WORK/c.out" "$WORK/rs.out" >"$WORK/diff"; then
  echo "MATCH: $(wc -l <"$WORK/c.proj") fingerprint tests agree with C nmap"
  exit 0
fi

echo "DIVERGENCE between C nmap and nmap-rs fingerprints:"
cat "$WORK/diff"
echo
echo "--- projections ---"
diff -u "$WORK/c.proj" "$WORK/rs.proj" || true
echo
echo "--- C nmap output ---";  sed -n '1,40p' "$WORK/c.out"
echo "--- nmap-rs output ---"; sed -n '1,40p' "$WORK/rs.out"
exit 1
