#!/usr/bin/env bash
# Re-derive the M6.6 exit-criterion golden from nmap itself, and compare it
# with what is committed.
#
#   ./regen_m66_exit.sh           regenerate the golden in place
#   ./regen_m66_exit.sh --check   FAIL if it differs
#
# The oracle is the installed nmap 7.94 on this repository's data directory:
# the scripts -sC, --script default, --script version and -sC -sV select and
# load, the same with the C modules the port does not have removed
# (gen_m66_scriptload.py's emulation), the categories that stop at start-up
# without them, and the executed scripts against loopback listeners on 8098,
# 8332 and 8180 (oracle/gen_m66_exit.py). Generation fails if 7.94 disagrees
# with the harness's two tolerances (OPENSSL_QUIET, SV_VERSION_ONLY). --check
# compares everything, so a golden gone stale after a change to scripts/,
# nselib/ or nse_main.lua fails here rather than passing a test that reads it.
# Needs nmap; CI runs --check in the differential job.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

NAME=m66_exit_golden.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 -B oracle/gen_m66_exit.py "$WORK"

blocks=$(grep -cE '^(load|abort|run) ' "$WORK/$NAME")
if (( CHECK )); then
  if ! cmp -s "$NAME" "$WORK/$NAME"; then
    echo "FAIL: $NAME is stale — run ./regen_m66_exit.sh" >&2
    diff -u "$NAME" "$WORK/$NAME" | head -40 >&2 || true
    exit 1
  fi
  echo "m6.6 exit: golden is current ($blocks blocks)"
  exit 0
fi
cp "$WORK/$NAME" "$NAME"
echo "m6.6 exit: regenerated ($blocks blocks)"
