#!/usr/bin/env bash
# Re-derive the M6.4b memory corpus -- what a script sees when memory runs
# out -- with nmap's OWN Lua, and compare it with what is committed.
#
#   ./regen_m64_memory.sh           regenerate cases and golden in place
#   ./regen_m64_memory.sh --check   FAIL if either differs
#
# Each case runs in a process of its own (oracle/m64_memory_one.lua) under
# `ulimit -v`, so that PUC-Lua's allocator is refused as the port's budget
# refuses. The cases are built so that the outcome does not depend on where
# exactly memory runs out (see oracle/gen_m64_memory.py).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

# The address space the oracle may use, in KiB: a few times the port's
# budget (32 MiB, in crates/core/tests/memory_differential.rs), as PUC-Lua's
# process also maps its code, its C stack and the C library.
ORACLE_KB=131072

"$HERE/oracle/build_lua_oracle.sh"

NAMES=(m64_memory_cases.txt m64_memory_golden.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

python3 oracle/gen_m64_memory.py > "$WORK/m64_memory_cases.txt"

run_all() {
  echo "# name	oracle_status	oracle_value"
  echo "# The verdict of nmap's OWN Lua 5.4, one process per case under"
  echo "# ulimit -v $ORACLE_KB. Regenerate with ./regen_m64_memory.sh."
  grep -v '^#' "$WORK/m64_memory_cases.txt" | while IFS=$'\t' read -r name chunk _; do
    ( ulimit -v "$ORACLE_KB"; ./oracle/lua oracle/m64_memory_one.lua "$name" "$chunk" ) \
      || { echo "FAIL: the oracle died on $name" >&2; exit 1; }
  done
}

run_all > "$WORK/m64_memory_golden.txt"
run_all > "$WORK/second_run.txt"
if ! diff -q "$WORK/m64_memory_golden.txt" "$WORK/second_run.txt" >/dev/null; then
  echo "FAIL: the oracle is not deterministic across two runs" >&2
  diff -u "$WORK/m64_memory_golden.txt" "$WORK/second_run.txt" >&2 || true
  exit 1
fi

rc=0
for n in "${NAMES[@]}"; do
  if (( CHECK )); then
    if ! diff -q "$n" "$WORK/$n" >/dev/null; then
      echo "FAIL: $n is stale — run ./regen_m64_memory.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

total=$(grep -cv '^#' m64_memory_cases.txt)
if (( CHECK )); then
  (( rc == 0 )) && echo "m6.4 memory: cases and golden are current ($total cases)"
  exit $rc
fi
echo "m6.4 memory: regenerated ($total cases)"
