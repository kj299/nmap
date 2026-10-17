#!/usr/bin/env python3
"""Sabotage the C to measure the M6.5 `openssl` corpus (ORACLE-CHECKS §4,
LESSONS #044). Each variant changes one behaviour of `nse_openssl.cc` or
`nse_ssl_cert.cc` that the port must reproduce; the corpus must tell every
variant apart from the unsabotaged C. A variant the corpus passes marks a
behaviour no row pins.

    sabotage_m65.py [NAME ...]          build and run each variant (default:
                                        all, and the result is recorded in
                                        m65_sabotage.txt); fails if any one
                                        goes uncaught
    sabotage_m65.py --list              the variants
    sabotage_m65.py --apply NAME DIR    apply one variant to the sources in DIR
                                        (what build_openssl_oracle.sh
                                        --sabotage runs)

The baseline is this tree's C, oracle/lua-openssl, run once over the cases;
each variant is oracle/lua-openssl-sabotage over the same cases. A row
counts as different under oracle/gen_m65.py's `compare` (random rows by
shape), and a variant that dies counts as caught. Rows tagged
`ub:rc4-empty-key` are skipped: their output is undefined. LOCAL ONLY: CI
does not build the variants.
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))

O, C = "nse_openssl.cc", "nse_ssl_cert.cc"

# (name, file, old, new, occurrences of old in file, which one to change)
# `old` must occur exactly `count` times, so a moved anchor stops the run.
VARIANTS = [
    ("bn-div-swap", O,
     "  nse_pushbn(L, dv, true);\n  nse_pushbn(L, rem, true);",
     "  nse_pushbn(L, rem, true);\n  nse_pushbn(L, dv, true);", 1, 1),
    ("bn-add-sub", O, "BN_add( result, a->bn, b->bn );", "BN_sub( result, a->bn, b->bn );", 1, 1),
    ("bn-mod-exp-args", O, "BN_mod_exp( result, a->bn, p->bn, m->bn, ctx );",
     "BN_mod_exp( result, p->bn, a->bn, m->bn, ctx );", 1, 1),
    ("bn-hex2bn-dec", O, "BN_hex2bn( &num, s );", "BN_dec2bn( &num, s );", 1, 1),
    ("bn-dec2bn-hex", O, "BN_dec2bn( &num, s );", "BN_hex2bn( &num, s );", 1, 1),
    ("bn-bin2bn-short", O, "BN_bin2bn( s, len, num );", "BN_bin2bn( s, len > 32 ? 32 : len, num );", 1, 1),
    ("bn-num-bytes-zero", O, "lua_pushinteger( L, BN_num_bytes( userdata->bn) );",
     "lua_pushinteger( L, BN_num_bytes( userdata->bn) + BN_is_zero( userdata->bn ) );", 1, 1),
    ("bn-set-bit-off", O, "BN_set_bit( userdata->bn, position );",
     "BN_set_bit( userdata->bn, position + 1 );", 1, 1),
    ("bn-clear-bit-low", O, "BN_clear_bit( userdata->bn, position );",
     "if (position < 64) BN_clear_bit( userdata->bn, position );", 1, 1),
    ("bn-safe-prime-order", O, "  lua_pushboolean( L, is_safe );\n  lua_pushboolean( L, is_prime );",
     "  lua_pushboolean( L, is_prime );\n  lua_pushboolean( L, is_safe );", 1, 1),
    ("bn-safe-prime-nohalf", O, "    BN_div_word( n, (BN_ULONG)2 );\n", "", 1, 1),
    ("bn-rand-top", O, "BN_rand( num, bits, -1, 0 );", "BN_rand( num, bits, bits ? 0 : -1, 0 );", 1, 1),
    ("rand-bytes-short", O,
     '    return luaL_error(L, "Failure in RAND_bytes.");\n  }\n  lua_pushlstring( L, (char *) result, len );',
     '    return luaL_error(L, "Failure in RAND_bytes.");\n  }\n  lua_pushlstring( L, (char *) result, len ? len - 1 : 0 );',
     1, 1),
    ("digest-short-msg", O, "EVP_DigestUpdate( mdctx, msg, msg_len )",
     "EVP_DigestUpdate( mdctx, msg, msg_len > 1000 ? 1000 : msg_len )", 1, 1),
    ("digest-unknown-msg", O,
     'if (!evp_md) return luaL_error( L, "Unknown digest algorithm: %s", algorithm );\n\n  mdctx',
     'if (!evp_md) return luaL_error( L, "Unknown digest: %s", algorithm );\n\n  mdctx', 1, 1),
    ("hmac-key-cap", O, "HMAC( evp_md, key, key_len, msg",
     "HMAC( evp_md, key, key_len > 128 ? 128 : key_len, msg", 1, 1),
    ("hmac-result-checked", O, "  HMAC( evp_md, key, key_len, msg, msg_len, digest, &digest_len );",
     "  if (!HMAC( evp_md, key, key_len, msg, msg_len, digest, &digest_len ))\n"
     "    return luaL_error( L, \"HMAC failed\" );", 1, 1),
    ("cipher-padding-inverted", O,
     "EVP_CIPHER_CTX_set_padding( cipher_ctx, padding )",
     "EVP_CIPHER_CTX_set_padding( cipher_ctx, !padding )", 2, 1),
    ("cipher-ivnul-794", O, "  if (!iv_len)\n    iv = NULL;",
     "  if (!iv_len || iv[0] == 0)\n    iv = NULL;", 2, 1),
    ("cipher-keylen-unchecked", O, "EVP_CIPHER_CTX_set_key_length( cipher_ctx, key_len ) &&",
     "(EVP_CIPHER_CTX_set_key_length( cipher_ctx, key_len ) || 1) &&", 2, 1),
    ("cipher-unknown-msg", O,
     'if (!evp_cipher) return luaL_error( L, "Unknown cipher algorithm: %s", algorithm );',
     'if (!evp_cipher) return luaL_error( L, "Unknown cipher: %s", algorithm );', 2, 2),
    ("err-queue-newest", O, "ERR_error_string(ERR_get_error(), NULL)",
     "ERR_error_string(ERR_peek_last_error(), NULL)", 3, 1),
    ("ciphers-unsorted", O, "OBJ_NAME_do_all_sorted( OBJ_NAME_TYPE_CIPHER_METH",
     "OBJ_NAME_do_all( OBJ_NAME_TYPE_CIPHER_METH", 1, 1),
    ("des-parity", O, "  // DES_set_odd_parity( &key );",
     "  for (int j = 0; j < 8; j++) key[j] |= 1; //", 1, 1),
    ("des-length-msg", O, '"String must have length of 7 bytes."', '"String must be 7 bytes."', 1, 1),
    # The time parser at nse_ssl_cert.cc:310-358 is dead with OpenSSL 3
    # (HAVE_OPAQUE_STRUCTS: ASN1_TIME_to_tm); these change the live path.
    ("cert-month", C, "lua_pushinteger(L, tm->tm_mon + 1);", "lua_pushinteger(L, tm->tm_mon);", 1, 1),
    ("cert-unparsed-time-nil", C,
     "  } else {\n      lua_pushlstring(L, (const char *) FUNC_ASN1_STRING_get0_data(s), FUNC_ASN1_STRING_length(s));",
     "  } else {\n      lua_pushnil(L);", 1, 1),
    ("cert-critical-dropped", C, "    if (X509_EXTENSION_get_critical(ext)) {", "    if (0) {", 1, 1),
    ("cert-ext-error-dropped", C,
     "      lua_pushboolean(L, true);\n      lua_setfield(L, -2, \"error\");",
     "      lua_pushboolean(L, false);\n      lua_setfield(L, -2, \"error\");", 1, 1),
    ("cert-name-first-wins", C,
     "    lua_settable(L, -3);\n  }\n}",
     "    lua_pushvalue(L, -2);\n    lua_rawget(L, -4);\n"
     "    if (lua_isnil(L, -1)) { lua_pop(L, 1); lua_settable(L, -3); } else lua_pop(L, 3);\n  }\n}",
     1, 1),
    ("cert-oid-numeric", C, "  if (nid == NID_undef) {", "  if (nid == NID_undef || nid == NID_organizationalUnitName) {", 1, 1),
    ("cert-digest-unknown-raises", C, "  if (md == NULL)\n      return 0;",
     '  if (md == NULL)\n      return luaL_error(L, "unknown digest");', 1, 1),
    ("cert-bits-security", C, "lua_pushinteger(L, EVP_PKEY_bits(pubkey));",
     "lua_pushinteger(L, EVP_PKEY_security_bits(pubkey));", 1, 1),
    ("cert-bad-der-false", C,
     "  cert = d2i_X509(NULL, (const unsigned char **) &der, l);\n  if (cert == NULL) {\n    lua_pushnil(L);",
     "  cert = d2i_X509(NULL, (const unsigned char **) &der, l);\n  if (cert == NULL) {\n    lua_pushboolean(L, 0);",
     1, 1),
]


def apply(name, work):
    v = [x for x in VARIANTS if x[0] == name]
    if not v:
        sys.exit("no variant %s" % name)
    _, f, old, new, count, which = v[0]
    path = os.path.join(work, f)
    src = open(path).read()
    if src.count(old) != count:
        sys.exit("%s: the anchor for %s occurs %d times, not %d" % (f, name, src.count(old), count))
    at = -1
    for _ in range(which):
        at = src.index(old, at + 1)
    open(path, "w").write(src[:at] + new + src[at + len(old):])


def main():
    if sys.argv[1:2] == ["--apply"]:
        apply(sys.argv[2], sys.argv[3])
        return
    if sys.argv[1:2] == ["--list"]:
        for v in VARIANTS:
            print("%-28s %s" % (v[0], v[1]))
        return
    sys.path.insert(0, HERE)
    import gen_m65 as g
    names = sys.argv[1:] or [v[0] for v in VARIANTS]
    build = os.path.join(HERE, "build_openssl_oracle.sh")
    cases = g.read_cases()
    subprocess.run([build], check=True)
    missed, lines = [], []
    with tempfile.TemporaryDirectory() as d:
        base_out = os.path.join(d, "base")
        if g.run("tree", base_out):
            sys.exit("the unsabotaged C died")
        base = g.read_results(base_out)
        for name in names:
            subprocess.run([build, "--sabotage", name], check=True, stdout=subprocess.DEVNULL)
            out = os.path.join(d, name)
            crashes = g.run("sabotage", out)
            got = g.read_results(out)
            diff = [cid for cid, tags, *_ in cases
                    if "ub:rc4-empty-key" not in tags
                    and (got[cid][0] == "crash" or not g.compare(got[cid], base[cid], tags))]
            lines.append("%-28s %s" % (name, ("caught: %d rows (first %s)%s" % (
                len(diff), diff[0], ", %d crashed" % len(crashes) if crashes else ""))
                if diff else "MISSED"))
            print(lines[-1], flush=True)
            if not diff:
                missed.append(name)
    if missed:
        sys.exit("%d of %d variants passed the corpus: %s" % (len(missed), len(names), " ".join(missed)))
    print("the corpus catches all %d variants" % len(names))
    if not sys.argv[1:]:
        with open(os.path.join(os.path.dirname(HERE), "m65_sabotage.txt"), "w") as fh:
            fh.write("# M6.5 C sabotage (oracle/sabotage_m65.py, ORACLE-CHECKS §4): each variant\n"
                     "# breaks one behaviour of the C; the corpus (cases %s) caught every one.\n"
                     % g.sha256(g.CASES)[:16])
            for line in lines:
                fh.write(line + "\n")


if __name__ == "__main__":
    main()
