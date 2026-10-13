#!/usr/bin/env bash
# Re-derive the base-library golden from nmap itself, and compare it with what
# is committed.
#
#   ./regen_m6_base.sh           regenerate m6_base_golden.txt in place
#   ./regen_m6_base.sh --check   FAIL if it differs
#
# The oracle is the installed nmap 7.94 with --datadir set to this repository,
# running oracle/m6_base_probe.nse as a prerule (oracle/gen_m6_base.py): the
# base and coroutine libraries, string.char, the string metatable's arithmetic
# and the table functions' checks, as an NSE script meets them, and `warn`'s
# output. crates/core/tests/base_differential.rs runs the same probe through
# the port's engine. Needs nmap; CI runs --check in the differential job.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

N=m6_base_golden.txt
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
mkdir "$WORK/second"

python3 -B oracle/gen_m6_base.py "$WORK"

# Determinism is asserted, not assumed.
python3 -B oracle/gen_m6_base.py "$WORK/second"
if ! cmp -s "$WORK/$N" "$WORK/second/$N"; then
  echo "FAIL: the oracle is not deterministic across two runs ($N)" >&2
  diff -u "$WORK/$N" "$WORK/second/$N" | head -40 >&2 || true
  exit 1
fi

rows=$(grep -c '^row|' "$WORK/$N")
if (( CHECK )); then
  if ! cmp -s "$N" "$WORK/$N"; then
    echo "FAIL: $N is stale — run ./regen_m6_base.sh" >&2
    diff -u "$N" "$WORK/$N" | head -40 >&2 || true
    exit 1
  fi
  echo "m6 base: golden is current ($rows rows)"
  exit 0
fi
cp "$WORK/$N" "$N"
echo "m6 base: regenerated ($rows rows)"
