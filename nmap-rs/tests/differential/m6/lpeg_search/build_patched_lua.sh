#!/usr/bin/env bash
# Build the M6 oracle interpreter (liblua/ + LPeg, oracle/build_lua_oracle.sh)
# around a PATCHED COPY of lpeg.c, without touching the tree.
#
#   build_patched_lua.sh PATCHED_LPEG_C OUT_BINARY [SCRATCH_PARENT]
#
# The recipe is not repeated here. The committed oracle/build_lua_oracle.sh is
# copied into a throw-away tree of the same shape, next to the patched lpeg.c
# and the tree's own liblua/ (a symlink, only ever read), nse_lpeg.cc,
# nse_lpeg.h and nse_lua.h, and run there. So the patched interpreter is built
# exactly as the oracle is, and a change to the recipe reaches it.
#
# Used by lpeg_search/build_instrumented.sh and lpeg_sabotage/build_variants.py.
# LOCAL ONLY: CI never runs it.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../../.." && pwd -P)"
ORACLE_SH="$REPO/nmap-rs/tests/differential/m6/oracle/build_lua_oracle.sh"

if [[ $# -lt 2 || $# -gt 3 ]]; then
  echo "usage: $0 PATCHED_LPEG_C OUT_BINARY [SCRATCH_PARENT]" >&2
  exit 2
fi
SRC="$(realpath -e "$1")"
OUT="$(realpath -m "$2")"
PARENT="$(realpath -m "${3:-${TMPDIR:-/tmp}}")"

inside_repo() { case "$1/" in "$REPO"/*) return 0 ;; *) return 1 ;; esac; }
for p in "$OUT" "$PARENT"; do
  if inside_repo "$p"; then
    echo "refusing to build inside the repository: $p" >&2
    exit 2
  fi
done
if [[ "$SRC" == "$REPO/lpeg.c" ]]; then
  echo "pass a patched COPY of lpeg.c, not the tree's file" >&2
  exit 2
fi
[[ -f "$ORACLE_SH" ]] || { echo "missing $ORACLE_SH" >&2; exit 1; }

mkdir -p "$PARENT" "$(dirname "$OUT")"
FAKE="$(mktemp -d "$PARENT/fake-tree.XXXXXX")"
trap 'rm -rf "$FAKE"' EXIT
ORACLE_DIR="$FAKE/nmap-rs/tests/differential/m6/oracle"
mkdir -p "$ORACLE_DIR"
cp "$ORACLE_SH" "$ORACLE_DIR/"
ln -s "$REPO/liblua" "$FAKE/liblua"
cp "$SRC" "$FAKE/lpeg.c"
cp "$REPO/nse_lpeg.cc" "$REPO/nse_lpeg.h" "$REPO/nse_lua.h" "$FAKE/"

# The oracle script's own `mktemp -d` (its object files) lands under $FAKE too.
TMPDIR="$FAKE" bash "$ORACLE_DIR/build_lua_oracle.sh" >&2
mv "$ORACLE_DIR/lua" "$OUT"
