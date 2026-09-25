#!/usr/bin/env bash
# Re-derive the `string.pack` / `unpack` / `packsize` corpus with nmap's OWN Lua
# and compare it with what is committed.
#
#   ./regen_m6_strpack.sh           regenerate cases and golden in place
#   ./regen_m6_strpack.sh --check   FAIL if either differs
#
# Gates `core::nse::stdlib::strpack`, the first-party port of
# `liblua/lstrlib.c:1385-1830`. The oracle is `liblua/` from this repository,
# built by oracle/build_lua_oracle.sh, and each case is a Lua chunk it evaluates.
#
# The driver is oracle/m60_coerce_driver.lua, shared with the coercion corpus
# rather than copied, because the rendering both need is the same: every
# returned value as `subtype:text` (strings as hex), and an error as the bare
# word "error". The message is left out on purpose — PUC-Lua's carries the
# caller's position, which the vendored VM does not add (DIVERGENCES.md,
# `error_string_gets_position`), and for a missing argument it carries
# artefacts of the C's stack layout that are not Lua semantics at all.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m6_strpack_cases.txt m6_strpack_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m6_strpack.py > "$WORK/m6_strpack_cases.txt"
./oracle/lua oracle/m60_coerce_driver.lua "$WORK/m6_strpack_cases.txt" \
  > "$WORK/m6_strpack_golden.txt"

# Determinism is asserted, not assumed: a golden that differs run to run turns
# the gate into noise.
./oracle/lua oracle/m60_coerce_driver.lua "$WORK/m6_strpack_cases.txt" \
  > "$WORK/second_run.txt"
if ! diff -q "$WORK/m6_strpack_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m6_strpack_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m6_strpack.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m6_strpack_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6 strpack: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m6 strpack: regenerated ($total cases)"
