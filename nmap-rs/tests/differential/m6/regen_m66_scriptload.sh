#!/usr/bin/env bash
# Re-derive the M6.6 per-script load golden from nmap itself, and compare it
# with what is committed.
#
#   ./regen_m66_scriptload.sh           regenerate the golden in place
#   ./regen_m66_scriptload.sh --check   FAIL if it differs
#
# The oracle is the installed nmap 7.94 loading each shipped script alone
# (--script-help) from a scratch data directory whose nse_main.lua removes the
# C modules the port does not have (oracle/gen_m66_scriptload.py, PORT_MISSING).
# --check compares everything, the `# missing:` header included, so a golden
# regenerated with another missing set, or gone stale after a change to
# scripts/, nselib/ or nse_main.lua, fails here rather than passing a test
# that reads it (M6.6 review, sabotages S24 and S27). Needs nmap; CI runs
# --check in the differential job.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

NAME=m66_scriptload_golden.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m66_scriptload.py "$WORK"

rows=$(grep -cv '^#' "$WORK/$NAME")
if (( CHECK )); then
  if ! cmp -s "$NAME" "$WORK/$NAME"; then
    echo "FAIL: $NAME is stale — run ./regen_m66_scriptload.sh" >&2
    diff -u "$NAME" "$WORK/$NAME" | head -40 >&2 || true
    exit 1
  fi
  echo "m6.6 scriptload: golden is current ($rows scripts)"
  exit 0
fi
cp "$WORK/$NAME" "$NAME"
echo "m6.6 scriptload: regenerated ($rows scripts)"
