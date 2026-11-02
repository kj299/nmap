#!/usr/bin/env bash
# IPv6 OS-detection differential (FreeBSD step e): `-6 -O` by C nmap and by nmap-rs,
# both as root, against one target, compared on what the classifier decides.
#
# IPv6 detection is a trained model, not a database, and nmap-rs prints its own report
# (`ipv6-os-detection-is-a-classifier-not-a-database`). Both reach the same three things,
# and those are compared:
#   - the verdict: "OS details: <class>" when a single class is within 90% of the top and
#     below the novelty threshold, else "No OS matches for host" (7.94's
#     printosscanoutput; nmap-rs's "IPv6 verdict" line at -d);
#   - the top-ranked class, verdict or not (7.94: the first row of -ddd's label table;
#     nmap-rs: the first of its guesses);
#   - the distance: 0 for the host itself (`islocalhost`).
# The responses carry sequence numbers and times, so they are not compared.
#
# TARGET (default ::1) is scanned; the host's own address goes over the loopback, as
# route_dst sends it. REQUIRE_IPV6=1 makes a host without IPv6 a failure, not a SKIP
# (CI sets it). Needs root and a --features pcap build; SKIPs without them.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_ROOT="$(cd "$HERE/../../.." && pwd)"
OPEN_PORT=8022
CLOSED_PORT=9999
TARGET="${TARGET:-::1}"

skip() {
  if [[ "${REQUIRE_IPV6:-}" == "1" ]]; then echo "FAIL: $*"; exit 1; fi
  echo "SKIP: $*"; exit 0
}

NMAP="${NMAP:-$(command -v nmap || true)}"
[[ -n "$NMAP" && -x "$NMAP" ]] || skip "C nmap oracle not found (set NMAP=... or install nmap)"
[[ "$(id -u)" == "0" ]] || skip "OS detection needs raw sockets (run as root)"
NMAP_RS="${NMAP_RS:-}"
if [[ -z "$NMAP_RS" ]]; then
  for cand in "$RS_ROOT/target/release/nmap-rs" "$RS_ROOT/target/debug/nmap-rs"; do
    if [[ -f "$cand" && -x "$cand" ]]; then NMAP_RS="$cand"; break; fi
  done
fi
[[ -n "$NMAP_RS" && -x "$NMAP_RS" ]] || skip "nmap-rs binary not found (build with --features pcap)"
python3 -c "import socket; socket.socket(socket.AF_INET6).bind(('$TARGET', 0))" 2>/dev/null \
  || skip "no IPv6 here, or $TARGET is not this host's"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"; [[ -n "${FIXTURE_PID:-}" ]] && kill "$FIXTURE_PID" 2>/dev/null || true' EXIT

# One open TCP port on the target (accepting and closing), one closed.
python3 - "$TARGET" "$OPEN_PORT" <<'PY' &
import socket, sys, threading, time
s = socket.socket(socket.AF_INET6)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind((sys.argv[1], int(sys.argv[2])))
s.listen(64)
def drain():
    while True:
        try:
            c, _ = s.accept()
        except ConnectionAbortedError:
            continue  # FreeBSD: a connection reset while queued
        c.close()
threading.Thread(target=drain, daemon=True).start()
time.sleep(900)
PY
FIXTURE_PID=$!
sleep 1
python3 -c "
import socket, sys
s = socket.socket(socket.AF_INET6); s.settimeout(2)
sys.exit(0 if s.connect_ex(('$TARGET', $OPEN_PORT)) == 0 else 1)
" || { echo "FAIL: the fixture is not listening on [$TARGET]:$OPEN_PORT"; exit 1; }

PORTS="$OPEN_PORT,$CLOSED_PORT"
echo "target : $TARGET"
echo "== running C nmap -6 -O =="
timeout 300 "$NMAP" -6 -O -ddd -Pn -n -p "$PORTS" "$TARGET" >"$WORK/c.out" 2>&1 || true
# nmap-rs reads the data files 7.94 read, which -d names ("Read from DIR: nmap-os-db
# ..."), as run_os_differential.sh does: the FreeBSD VM's oracle is not installed,
# and -O needs nmap-os-db there too.
DATADIR="$(sed -n 's/^Read from \(.*\): .*nmap-os-db.*/\1/p' "$WORK/c.out" | head -1)"
# At -ddd 7.94 also names each file it finds ("Fetchfile found DIR/nmap-services").
[[ -n "$DATADIR" ]] || DATADIR="$(sed -n 's|^Fetchfile found \(.*\)/nmap-services$|\1|p' "$WORK/c.out" | head -1)"
rs_env=()
[[ -n "$DATADIR" ]] && rs_env=("NMAP_RS_DATADIR=$DATADIR")
echo "== running nmap-rs -6 -O (data files from ${DATADIR:-its own search}) =="
env "${rs_env[@]}" timeout 300 "$NMAP_RS" -6 -O -d -Pn -n -p "$PORTS" "$TARGET" >"$WORK/rs.out" 2>&1 || true

# 7.94 follows "No OS matches for host" with a submission invitation, " (If you know
# what OS is running on it, see https://nmap.org/submit/ )."; the verdict is the words
# before it.
c_verdict="$(grep -m1 -E '^(OS details: |No OS matches for host)' "$WORK/c.out" \
  | sed -E 's/^(No OS matches for host).*/\1/' || true)"
c_top="$(sed -n -E 's/^ *[0-9]+\.[0-9]{4} +[0-9]+\.[0-9]{4} +[0-9]+ (.+)$/\1/p' "$WORK/c.out" | head -1)"
c_dist="$(sed -n -E 's/^Network Distance: ([0-9]+) hops?$/\1/p' "$WORK/c.out" | head -1)"
rs_verdict="$(sed -n 's/^IPv6 verdict: //p' "$WORK/rs.out" | head -1)"
rs_top="$(sed -n '/^OS guesses (IPv6):$/{n;p;}' "$WORK/rs.out" | sed -E 's/^ +//; s/ \([0-9]+%\)$//' | head -1)"
rs_dist="$(sed -n -E 's/^IPv6 observation: distance (-?[0-9]+) .*/\1/p' "$WORK/rs.out" | head -1)"

show() {
  echo "--- C nmap (verdict, top, distance) ---"; printf '%s\n%s\n%s\n' "$c_verdict" "$c_top" "$c_dist"
  echo "--- nmap-rs ---"; printf '%s\n%s\n%s\n' "$rs_verdict" "$rs_top" "$rs_dist"
  echo "--- C nmap output (head) ---"; grep -v -E '^ *[0-9]+\.[0-9]{4} ' "$WORK/c.out" | sed -n '1,40p'
  echo "--- nmap-rs output ---"; sed -n '1,40p' "$WORK/rs.out"
}

# An empty side is a failure to report, not agreement.
if [[ -z "$c_verdict" || -z "$c_top" ]]; then echo "FAIL: C nmap gave no IPv6 classification"; show; exit 1; fi
if [[ -z "$rs_verdict" || -z "$rs_top" ]]; then echo "FAIL: nmap-rs gave no IPv6 classification"; show; exit 1; fi

if [[ "$c_verdict" == "$rs_verdict" && "$c_top" == "$rs_top" && "$c_dist" == "$rs_dist" ]]; then
  echo "MATCH: $c_verdict; top class '$c_top'; distance $c_dist"
  exit 0
fi
echo "DIVERGENCE between C nmap and nmap-rs (-6 -O $TARGET):"
show
exit 1
