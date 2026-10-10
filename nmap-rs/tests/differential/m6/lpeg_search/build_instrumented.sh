#!/usr/bin/env bash
# Build `lua-instr`: the M6 oracle interpreter with an instrumented COPY of
# lpeg.c that exposes `lpeg.__steps()` (patch_lpeg.py). The tree's lpeg.c is
# only read.
#
#   build_instrumented.sh WORKDIR      -> WORKDIR/lua-instr
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../../.." && pwd -P)"
[[ $# -eq 1 ]] || { echo "usage: $0 WORKDIR" >&2; exit 2; }
WORK="$(realpath -m "$1")"
mkdir -p "$WORK/src" "$WORK/tmp"

python3 -I -B "$HERE/patch_lpeg.py" "$REPO/lpeg.c" "$WORK/src/lpeg.instrumented.c"
bash "$HERE/build_patched_lua.sh" "$WORK/src/lpeg.instrumented.c" "$WORK/lua-instr" "$WORK/tmp"

# The counters must exist, count, and reset on read.
"$WORK/lua-instr" -e '
  local l = require "lpeg"
  assert(type(l.__steps) == "function", "lpeg.__steps missing")
  l.__steps()
  assert(l.match(l.C(l.P"a"^1), "aaa") == "aaa")
  local vm, cap = l.__steps()
  assert(vm > 0 and cap > 0, "counters did not move")
  local vm2, cap2 = l.__steps()
  assert(vm2 == 0 and cap2 == 0, "counters did not reset")
  print(string.format("lpeg.__steps ok: vm=%d cap=%d for C(P\"a\"^1) on \"aaa\"", vm, cap))'
