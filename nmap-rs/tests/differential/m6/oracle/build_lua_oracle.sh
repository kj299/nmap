#!/usr/bin/env bash
# Build the M6 differential oracle: nmap's OWN bundled Lua interpreter.
#
# The oracle for M6.1 is not a re-implementation of how nmap reads `script.db`
# and `.nse` metadata — it is `liblua/`, compiled from this repository's tree,
# running excerpts lifted verbatim out of `nse_main.lua`. That is the strongest
# oracle available: the interpreter under test IS the interpreter nmap ships,
# down to the point release.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIBLUA="$(cd "$HERE/../../../../../liblua" && pwd)"
OUT="$HERE/lua"

# Rebuild only when the interpreter is missing or older than any liblua source.
if [[ -x "$OUT" ]] && [[ -z "$(find "$LIBLUA" -name '*.[ch]' -newer "$OUT" -print -quit)" ]]; then
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$LIBLUA"/*.c "$LIBLUA"/*.h "$WORK/"
rm -f "$WORK/luac.c"   # the compiler binary has its own main()
( cd "$WORK" && cc -O1 -std=gnu99 -DLUA_USE_LINUX -o lua ./*.c -lm -ldl )
mv "$WORK/lua" "$OUT"
"$OUT" -v
