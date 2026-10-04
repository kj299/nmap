#!/usr/bin/env bash
# Re-derive the M6.4c stdlib corpus -- utf8, os (the clock), io (files) and
# debug.getinfo -- with nmap's OWN Lua, and
# compare it with what is committed.
#
#   ./regen_m64_stdlib.sh           regenerate cases and golden in place
#   ./regen_m64_stdlib.sh --check   FAIL if either differs
#
# Gates core::nse::stdlib's utf8lib, oslib/osdate, iolib and debuglib. The
# oracle is `liblua/` from this repository, built by oracle/build_lua_oracle.sh;
# the driver is oracle/m6_pattern_driver.lua. It runs with TZ=UTC, the time
# zone the port's `os` uses, from this directory so that `fixtures/io/` is
# where the cases look, with /tmp/m64io/ as the directory cases write in.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m64_stdlib_cases.txt m64_stdlib_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m64_stdlib.py > "$WORK/m64_stdlib_cases.txt"
rm -rf /tmp/m64io && mkdir -p /tmp/m64io
export TZ=UTC
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m64_stdlib_cases.txt" \
  > "$WORK/m64_stdlib_golden.txt"

# Determinism is asserted, not assumed: a golden that differs run to run turns
# the gate into noise.
./oracle/lua oracle/m6_pattern_driver.lua "$WORK/m64_stdlib_cases.txt" \
  > "$WORK/second_run.txt"
if ! diff -q "$WORK/m64_stdlib_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m64_stdlib_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m64_stdlib.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m64_stdlib_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6.4 stdlib: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m6.4 stdlib: regenerated ($total cases)"
