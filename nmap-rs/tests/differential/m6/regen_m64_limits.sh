#!/usr/bin/env bash
# Re-derive the M6.4b limits corpus -- C-call depth, Lua stack depth,
# metamethod chains, results a call may push -- with nmap's OWN Lua, and
# compare it with what is committed.
#
#   ./regen_m64_limits.sh           regenerate cases and golden in place
#   ./regen_m64_limits.sh --check   FAIL if either differs
#
# Gates the vendored VM's LUAI_MAXCCALLS, LUAI_MAXSTACK and MAXTAGLOOP, the
# depth at which each is reached from every kind of caller, and the errors
# raised there. The oracle is `liblua/` from this repository, built by
# oracle/build_lua_oracle.sh; the driver is oracle/m6_pattern_driver.lua.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m64_limits_cases.txt m64_limits_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m64_limits.py > "$WORK/m64_limits_cases.txt"
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m64_limits_cases.txt" \
  > "$WORK/m64_limits_golden.txt"

# Determinism is asserted, not assumed: a golden that differs run to run turns
# the gate into noise.
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m64_limits_cases.txt" \
  > "$WORK/second_run.txt"
if ! diff -q "$WORK/m64_limits_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m64_limits_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m64_limits.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m64_limits_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6.4 limits: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m6.4 limits: regenerated ($total cases)"
