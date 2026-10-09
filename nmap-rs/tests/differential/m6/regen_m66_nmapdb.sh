#!/usr/bin/env bash
# Re-derive the M6.6 `nmapdb` golden from nmap itself, and compare it with
# what is committed.
#
#   ./regen_m66_nmapdb.sh           regenerate the golden and quarantine list in place
#   ./regen_m66_nmapdb.sh --check   FAIL if either differs
#
# The oracle is the installed nmap 7.94 with --datadir set to this repository,
# running oracle/m66_probe_nmapdb.nse as a prerule (oracle/gen_m66_nmapdb.py,
# which also checks that the probe read this tree's data files). Needs nmap; CI
# runs --check in the differential job, where nmap is installed. A change to
# nmap-mac-prefixes, nmap-services or nmap-protocols changes the golden, and
# --check says so.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

NAMES=(m66_nmapdb_golden.txt m66_nmapdb_quarantine.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/second"

python3 oracle/gen_m66_nmapdb.py "$WORK"

# Determinism is asserted, not assumed: a golden that differs run to run turns
# the gate into noise.
python3 oracle/gen_m66_nmapdb.py "$WORK/second"
for n in "${NAMES[@]}"; do
  if ! cmp -s "$WORK/$n" "$WORK/second/$n"; then
    echo "FAIL: the oracle is not deterministic across two runs ($n)" >&2
    diff -u "$WORK/$n" "$WORK/second/$n" | head -40 >&2 || true
    exit 1
  fi
done

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! cmp -s "$n" "$WORK/$n"; then
      echo "FAIL: $n is stale — run ./regen_m66_nmapdb.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

lines=$(grep -cv '^#' m66_nmapdb_golden.txt)
held=$(grep -cv '^#' m66_nmapdb_quarantine.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6.6 nmapdb: golden and quarantine list are current ($lines lines, $held quarantined calls)"
  exit $rc
fi
echo "m6.6 nmapdb: regenerated ($lines lines, $held quarantined calls)"
