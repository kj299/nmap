#!/usr/bin/env bash
# Build the M6 differential oracle: nmap's OWN bundled Lua interpreter, with
# nmap's OWN bundled LPeg linked in.
#
# The oracle for M6 is not a re-implementation of how nmap reads `script.db`,
# `.nse` metadata (M6.1) or `--script` expressions (M6.2) — it is `liblua/` and
# `lpeg.c`, compiled from this repository's tree, running excerpts lifted
# verbatim out of `nse_main.lua`. That is the strongest oracle available: the
# interpreter and the PEG engine under test ARE the ones nmap ships, down to
# the point release.
#
# LPeg matters for M6.2 specifically. The `--script` selection grammar is an
# LPeg grammar, and its observable behaviour (ordered choice, possessive
# repetition, when capture functions run, the backtrack-stack ceiling) is a
# property of THIS engine, not of PEGs in general. Re-implementing it to
# generate the golden would prove nothing.
#
#   build_lua_oracle.sh                    oracle/lua, the oracle every corpus uses
#   build_lua_oracle.sh --variant fwrapv   oracle/lua-fwrapv: the same with -fwrapv,
#        so a signed `int` that overflows wraps, as defined behaviour. Only the
#        step b tree corpus uses it (regen_m66b_trees.sh), for the 14 rows whose
#        sizes overflow lpeg.c's `int` (lpeg-tree-size-int-overflow): the answer
#        recorded is the C's arithmetic modulo 2^32, defined, not what one
#        compiler made of undefined code (LESSONS #033).
#   build_lua_oracle.sh --variant ubsan    oracle/lua-ubsan: the same with
#        -fsanitize=undefined -fno-sanitize-recover=all, so the first undefined
#        operation ends the process (regen_m66b_trees.sh's screen,
#        oracle/ubsan_m66b_trees.py).
# Variants are built from the same sources by the same recipe below, and, like
# oracle/lua, are not committed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE="$(cd "$HERE/../../../../.." && pwd)"
LIBLUA="$TREE/liblua"
case "${1:-} ${2:-}" in
  " ")            EXTRA=(); LDEXTRA=(); OUT="$HERE/lua" ;;
  "--variant fwrapv") EXTRA=(-fwrapv); LDEXTRA=(); OUT="$HERE/lua-fwrapv" ;;
  "--variant ubsan")  EXTRA=(-g -fsanitize=undefined -fno-sanitize-recover=all)
                      LDEXTRA=(-fsanitize=undefined); OUT="$HERE/lua-ubsan" ;;
  *) echo "usage: $0 [--variant fwrapv|ubsan]" >&2; exit 2 ;;
esac

# Rebuild only when the interpreter is missing or older than any input source,
# or than this recipe.
if [[ -x "$OUT" ]] \
  && [[ -z "$(find "$LIBLUA" -name '*.[ch]' -newer "$OUT" -print -quit)" ]] \
  && [[ "$TREE/lpeg.c" -ot "$OUT" ]] && [[ "$TREE/nse_lpeg.cc" -ot "$OUT" ]] \
  && [[ "$TREE/nse_lpeg.h" -ot "$OUT" ]] && [[ "$TREE/nse_lua.h" -ot "$OUT" ]] \
  && [[ "${BASH_SOURCE[0]}" -ot "$OUT" ]]; then
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$LIBLUA"/*.c "$LIBLUA"/*.h "$WORK/"
rm -f "$WORK/luac.c"   # the compiler binary has its own main()
# nmap builds LPeg by #including lpeg.c from nse_lpeg.cc, which supplies the
# Lua 5.1-era compatibility shims that this vendored LPeg still expects. Use
# that same path rather than compiling lpeg.c directly, so the oracle's engine
# is byte-for-byte the one nmap links.
cp "$TREE/lpeg.c" "$TREE/nse_lpeg.cc" "$TREE/nse_lpeg.h" "$TREE/nse_lua.h" "$WORK/"

# liblua is C and nse_lpeg.cc is C++, so `luaopen_lpeg` comes out of the C++
# translation unit name-mangled and the C `linit.c` cannot reference it. Bridge
# it explicitly rather than compiling all of liblua as C++ (which would change
# the interpreter under test).
printf '\nextern "C" int oracle_open_lpeg (lua_State *L) { return luaopen_lpeg(L); }\n' >> "$WORK/nse_lpeg.cc"

# Register lpeg in the stock library table. Both edits are anchored, and a
# missing anchor is a hard failure: an oracle that silently lost its PEG engine
# would make every M6.2 case vacuously pass.
python3 - "$WORK/linit.c" <<'PY'
import sys
path = sys.argv[1]
src = open(path).read()
table_anchor = '  {LUA_DBLIBNAME, luaopen_debug},'
decl_anchor = '#include "lualib.h"'
for anchor in (table_anchor, decl_anchor):
    if src.count(anchor) != 1:
        sys.exit("linit.c anchor moved, refusing to build a silently lpeg-less oracle: %r" % anchor)
src = src.replace(table_anchor, table_anchor + '\n  {"lpeg", oracle_open_lpeg},', 1)
src = src.replace(decl_anchor, decl_anchor + '\nLUALIB_API int oracle_open_lpeg (lua_State *L);', 1)
open(path, 'w').write(src)
PY

cd "$WORK"
for f in $(ls ./*.c | grep -v '/lpeg\.c$'); do   # lpeg.c is #included, not compiled
  cc -O1 ${EXTRA[@]+"${EXTRA[@]}"} -std=gnu99 -DLUA_USE_LINUX -I. -c "$f" -o "${f%.c}.o"
done
c++ -O1 ${EXTRA[@]+"${EXTRA[@]}"} -DLUA_INCLUDED -I. -c nse_lpeg.cc -o nse_lpeg.o
c++ -O1 ${LDEXTRA[@]+"${LDEXTRA[@]}"} -o lua ./*.o -lm -ldl
mv "$WORK/lua" "$OUT"
"$OUT" -v
"$OUT" -e 'assert(type(require"lpeg".P) == "function", "oracle built without lpeg")' \
  && echo "lpeg linked."
