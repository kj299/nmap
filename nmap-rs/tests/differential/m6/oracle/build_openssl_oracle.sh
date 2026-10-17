#!/usr/bin/env bash
# Build the M6.5 oracle (docs/M6.5-ANALYSIS.md §11 row a, D1): this tree's
# `liblua/` with this tree's `nse_openssl.cc` and `nse_ssl_cert.cc` linked in,
# against the system OpenSSL 3. It is the spec side of the `openssl` corpora;
# nmap 7.94 (the installed binary) is the other side, and the drift between
# them is pinned family by family (§2).
#
# The two C files are compiled as they are, apart from two anchored edits
# that swap nmap's own headers for oracle/openssl_oracle_shim.h, which gives
# them the five things they take from the rest of nmap: `o.debugging` and
# `o.verbose` (both 0), `log_write`, `SCRIPT_ENGINE`, nbase's
# `get_random_bytes` (over RAND_bytes: only lengths are compared), and
# `nse_nsock_get_ssl` (NULL: `get_ssl_certificate` needs a live nsock socket
# and is covered by the TLS fixtures instead). A missing anchor is a hard
# failure, so the oracle cannot silently compile something other than the C.
#
# One more edit is a named repair (LESSONS #019): `iv-length-uaf`. On a
# non-empty IV of the wrong length, encrypt and decrypt free the cipher
# context and then read it for the error message (`nse_openssl.cc:438-441,
# 499-502`, DIVERGENCES `nse-openssl-iv-length-uaf`): undefined, and fatal in
# 7.94 and here alike. The repair reads the length before the free, so the
# message is the one the C means; it changes nothing else. The cases that
# reach it are tagged `ub:iv-length-uaf` (oracle/gen_m65_cases.py `ub_iv`),
# no golden is recorded from the unrepaired C, and oracle/gen_m65.py checks
# that the repaired oracle raises "Length of iv" on exactly those rows.
#
#   build_openssl_oracle.sh                  oracle/lua-openssl
#   build_openssl_oracle.sh --variant asan   oracle/lua-openssl-asan: the same
#       with -fsanitize=address,undefined -fno-sanitize-recover=all and
#       LUA_USE_APICHECK, for the screen (ORACLE-CHECKS §3, LESSONS #049, #051)
#   build_openssl_oracle.sh --sabotage FILE  oracle/lua-openssl-sabotage: the
#       same after applying the sabotage FILE (oracle/sabotage_m65.py's
#       format), for ORACLE-CHECKS §4
#
# In the built interpreter, `require "openssl"` is nmap's module, and
# `require "nmap.socket"` returns { parse_ssl_certificate = ... } with the
# SSL_CERT metatable registered as nse_nsock.cc does (`nse_nsock_init_ssl_cert`),
# under the name nmap gives nsock (`nse_nmaplib.cc:1048`), which is the name
# `luaL_argerror` reports, and opened before `openssl`, as nmap opens it.
# Variants are built from the same sources by the same recipe, and are not
# committed.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TREE="$(cd "$HERE/../../../../.." && pwd)"
LIBLUA="$TREE/liblua"
SABOTAGE=""
case "${1:-} ${2:-}" in
  " ")                EXTRA=(-O1); LDEXTRA=(); OUT="$HERE/lua-openssl" ;;
  "--variant asan")   EXTRA=(-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -DLUA_USE_APICHECK)
                      LDEXTRA=(-fsanitize=address,undefined); OUT="$HERE/lua-openssl-asan" ;;
  --sabotage\ *)      EXTRA=(-O1); LDEXTRA=(); OUT="$HERE/lua-openssl-sabotage"; SABOTAGE="$2" ;;
  *) echo "usage: $0 [--variant asan | --sabotage FILE]" >&2; exit 2 ;;
esac

if [[ -z "$SABOTAGE" && -x "$OUT" ]] \
  && [[ -z "$(find "$LIBLUA" -name '*.[ch]' -newer "$OUT" -print -quit)" ]] \
  && [[ "$TREE/nse_openssl.cc" -ot "$OUT" ]] && [[ "$TREE/nse_ssl_cert.cc" -ot "$OUT" ]] \
  && [[ "$TREE/nse_openssl.h" -ot "$OUT" ]] && [[ "$TREE/nse_lua.h" -ot "$OUT" ]] \
  && [[ "$HERE/openssl_oracle_shim.h" -ot "$OUT" ]] && [[ "${BASH_SOURCE[0]}" -ot "$OUT" ]]; then
  exit 0
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
cp "$LIBLUA"/*.c "$LIBLUA"/*.h "$WORK/"
rm -f "$WORK/luac.c"
cp "$TREE/nse_openssl.cc" "$TREE/nse_ssl_cert.cc" "$TREE/nse_openssl.h" "$TREE/nse_lua.h" \
   "$HERE/openssl_oracle_shim.h" "$WORK/"

python3 - "$WORK" <<'PY'
import sys
work = sys.argv[1]

def edit(name, pairs):
    path = f"{work}/{name}"
    src = open(path).read()
    for old, new in pairs:
        if src.count(old) != 1:
            sys.exit(f"{name}: anchor moved, refusing to build an oracle that is not the C: {old!r}")
        src = src.replace(old, new, 1)
    open(path, "w").write(src)

edit("nse_openssl.cc", [
    ('#include <nbase.h>\n#include "NmapOps.h"\n#include "output.h"\nextern NmapOps o;',
     '#include "openssl_oracle_shim.h"'),
])
# The repair `iv-length-uaf` (above), in encrypt and decrypt alike.
def repair():
    path = f"{work}/nse_openssl.cc"
    src = open(path).read()
    old = ('    EVP_CIPHER_CTX_free(cipher_ctx);\n'
           '    return luaL_error( L, "Length of iv is %d; should be %d",\n'
           '      (int) iv_len, EVP_CIPHER_CTX_iv_length( cipher_ctx ));\n')
    new = ('    int oracle_iv_length = EVP_CIPHER_CTX_iv_length( cipher_ctx ); /* repair: iv-length-uaf */\n'
           '    EVP_CIPHER_CTX_free(cipher_ctx);\n'
           '    return luaL_error( L, "Length of iv is %d; should be %d",\n'
           '      (int) iv_len, oracle_iv_length);\n')
    if src.count(old) != 2:
        sys.exit("nse_openssl.cc: the iv-length-uaf anchor moved, refusing to build")
    open(path, "w").write(src.replace(old, new))
repair()
edit("nse_ssl_cert.cc", [
    ('#include "nbase.h"', '#include "openssl_oracle_shim.h"'),
    ('#include "nse_nsock.h"\n', ''),
])
# The cert functions as a module of their own, registered as nse_nsock.cc
# registers them (`nse_nsock.cc:1187, 1222`).
with open(f"{work}/nse_ssl_cert.cc", "a") as f:
    f.write('''
extern "C" int oracle_open_sslcert(lua_State *L) {
  oracle_nsock_ssl_env();  /* luaopen_nsock's nsock_pool_ssl_init: openssl_oracle_shim.h */
  nse_nsock_init_ssl_cert(L);
  lua_newtable(L);
  lua_pushcfunction(L, l_parse_ssl_certificate);
  lua_setfield(L, -2, "parse_ssl_certificate");
  return 1;
}
''')
with open(f"{work}/nse_openssl.cc", "a") as f:
    f.write('\nextern "C" int oracle_open_openssl(lua_State *L) {\n'
            '  oracle_nsock_ssl_env();  /* `nmap` (and nsock) open first: openssl_oracle_shim.h */\n'
            '  return luaopen_openssl(L);\n}\n')
edit("linit.c", [
    ('  {LUA_DBLIBNAME, luaopen_debug},',
     '  {LUA_DBLIBNAME, luaopen_debug},\n  {"nmap.socket", oracle_open_sslcert},\n  {"openssl", oracle_open_openssl},'),
    ('#include "lualib.h"',
     '#include "lualib.h"\nLUALIB_API int oracle_open_openssl (lua_State *L);\nLUALIB_API int oracle_open_sslcert (lua_State *L);'),
])
PY

if [[ -n "$SABOTAGE" ]]; then
  python3 "$HERE/sabotage_m65.py" --apply "$SABOTAGE" "$WORK"
fi

cd "$WORK"
for f in ./*.c; do
  cc ${EXTRA[@]+"${EXTRA[@]}"} -std=gnu99 -DLUA_USE_LINUX -I. -c "$f" -o "${f%.c}.o"
done
for f in nse_openssl.cc nse_ssl_cert.cc; do
  c++ ${EXTRA[@]+"${EXTRA[@]}"} -DHAVE_OPENSSL=1 -DLUA_INCLUDED -I. -c "$f" -o "${f%.cc}.o"
done
c++ ${LDEXTRA[@]+"${LDEXTRA[@]}"} -o lua ./*.o -lcrypto -lssl -lm -ldl
mv "$WORK/lua" "$OUT"
"$OUT" -e 'local o = require "openssl"; local c = require "nmap.socket";
  assert(type(o.md5) == "function" and type(c.parse_ssl_certificate) == "function",
         "oracle built without the openssl module")
  print("openssl and nmap.socket linked:", #o.supported_ciphers(), "ciphers")'
