#!/usr/bin/env bash
# M1 connect-scan differential oracle — prove nmap-rs's port-state fidelity
# against C nmap over a reproducible loopback fixture.
#
# What it does:
#   1. Binds loopback listeners on a fixed set of "open" ports (the fixture),
#      leaving a fixed set of "closed" ports with nothing listening.
#   2. Runs the kit's differential harness (diff_run.py) with two wrapper
#      "binaries" — one shelling out to C nmap, one to nmap-rs — each piping its
#      `-oX` output through project.py to the canonical semantic projection.
#   3. Diffs the projections case-by-case. MATCH means identical host status +
#      open-port state/reason + closed/filtered counts; a divergence is a real
#      fidelity regression (or a ledgered, intentional M1 abbreviation).
#
# Determinism: loopback closed ports return an immediate RST (closed, not
# filtered) and bound ports accept immediately (open), so state is stable without
# depending on timing. project.py strips everything nondeterministic (latency,
# timestamps, durations) by construction.
#
# Usage:
#   run_differential.sh                 # auto-discover nmap and nmap-rs on PATH/target
#   NMAP=/path/to/nmap NMAP_RS=/path/to/nmap-rs run_differential.sh
#   run_differential.sh --self-test     # fixture-free harness sanity (project.py)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RS_ROOT="$(cd "$HERE/../.." && pwd)"                 # nmap-rs/
KIT_DIFF="$(cd "$RS_ROOT/../porting-kit/harnesses/differential" && pwd)"
MATRIX="$HERE/mvp-matrix.toml"
LEDGER="$RS_ROOT/DIVERGENCES.md"

if [[ "${1:-}" == "--self-test" ]]; then
  python3 "$HERE/project.py" --self-test
  exit $?
fi

# --- Locate the two binaries ------------------------------------------------
NMAP="${NMAP:-$(command -v nmap || true)}"
if [[ -z "${NMAP_RS:-}" ]]; then
  for cand in "$RS_ROOT/target/release/nmap-rs" "$RS_ROOT/target/debug/nmap-rs" "$(command -v nmap-rs || true)"; do
    if [[ -x "$cand" ]]; then NMAP_RS="$cand"; break; fi
  done
fi
# Require a regular executable *file*, not just something with the +x bit — a
# directory passes `-x` and would be "run" to empty output, surfacing as a
# confusing XML parse-error downstream instead of a clear "not a binary".
if [[ -z "$NMAP" || ! -f "$NMAP" || ! -x "$NMAP" ]]; then
  echo "SKIP: C nmap oracle not found (set NMAP=... or install nmap)"; exit 0
fi
if [[ -z "${NMAP_RS:-}" || ! -f "$NMAP_RS" || ! -x "$NMAP_RS" ]]; then
  echo "error: nmap-rs binary not found or not a file — run 'cargo build --release' first (got: '${NMAP_RS:-}')" >&2; exit 2
fi
echo "oracle : $NMAP ($("$NMAP" --version | head -1))"
echo "rust   : $NMAP_RS ($("$NMAP_RS" --version 2>/dev/null | head -1))"

# --- Fixture: loopback listeners on the fixed "open" ports -------------------
# Must match the ports the matrix scans. Kept as unusual high ports so a CI
# runner is overwhelmingly unlikely to have them already bound.
OPEN_PORTS="18080 18443"
# Port 18022 additionally emits an SSH identification banner on every connection,
# so `-sV` on both tools must detect service "ssh" (the M3 differential). The
# silent listeners on 18080/18443 stay for the M1 state-fidelity cases.
BANNER_PORT="18022"
python3 - "$OPEN_PORTS" "$BANNER_PORT" <<'PY' &
import socket, sys, threading, time
socks = []
for p in sys.argv[1].split():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", int(p)))
    s.listen(16)
    socks.append(s)

# The banner port: accept in a loop and answer with the OpenSSH banner. `-sV`
# connects several times (NULL probe + retries) across both tools.
bp = int(sys.argv[2])
bs = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
bs.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
bs.bind(("127.0.0.1", bp))
bs.listen(64)

def serve():
    while True:
        try:
            c, _ = bs.accept()
            c.sendall(b"SSH-2.0-OpenSSH_9.6\r\n")
            time.sleep(0.05)
            c.close()
        except OSError:
            break

threading.Thread(target=serve, daemon=True).start()
# Hold the listeners open long enough for both scans; the parent kills us.
time.sleep(120)
PY
FIXTURE_PID=$!
trap 'kill "$FIXTURE_PID" 2>/dev/null || true' EXIT
sleep 1   # let the binds settle

# --- Wrapper "binaries" the harness invokes with the matrix args ------------
WRAP_DIR="$(mktemp -d)"
trap 'kill "$FIXTURE_PID" 2>/dev/null || true; rm -rf "$WRAP_DIR"' EXIT
cat > "$WRAP_DIR/oracle" <<EOF
#!/usr/bin/env bash
"$NMAP" "\$@" -oX - 2>/dev/null | python3 "$HERE/project.py"
EOF
cat > "$WRAP_DIR/rust" <<EOF
#!/usr/bin/env bash
# NMAP_RS_DATADIR lets nmap-rs -sV find nmap-service-probes at the repo root.
NMAP_RS_DATADIR="$RS_ROOT/.." "$NMAP_RS" "\$@" -oX - 2>/dev/null | python3 "$HERE/project.py"
EOF
chmod +x "$WRAP_DIR/oracle" "$WRAP_DIR/rust"

# --- Run the differential ---------------------------------------------------
# --ignore-exit: the projection is the fidelity contract; process exit codes are
# a separate concern tracked in DIVERGENCES.md (nmap-rs exit-code parity is M2).
python3 "$KIT_DIFF/diff_run.py" \
  --oracle "$WRAP_DIR/oracle" \
  --rust "$WRAP_DIR/rust" \
  --matrix "$MATRIX" \
  --ledger "$LEDGER" \
  --ignore-exit
