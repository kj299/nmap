#!/usr/bin/env python3
"""The M6.5 `openssl` case matrix (docs/M6.5-ANALYSIS.md §11 row a).

    python3 oracle/gen_m65_cases.py ALGS CERTS OUT       write the cases
    python3 oracle/gen_m65_cases.py --capture-algs OUT   write the algorithm table
    python3 oracle/gen_m65_cases.py --self-test

The cases are a pure function of this file, ALGS (`m65_algs.txt`) and CERTS
(`m65_certs.txt`), with a fixed seed, so any host regenerates them byte for
byte. ALGS is the algorithm table: the names `supported_digests` and
`supported_ciphers` list, OpenSSL's own aliases (`openssl list
-{digest,cipher}-algorithms`), and the key, IV and block length libcrypto
reports after `EVP_EncryptInit_ex` for each cipher name, each alias and each
other name the cname family looks up (the IV length the C checks,
`nse_openssl.cc:438-441`, is the context's: CCM's is 7, not 12). It is
captured once with --capture-algs, from the oracle (oracle/lua-openssl) and
the system libcrypto, and committed; nothing here reads the host's OpenSSL.
CERTS is the certificate corpus (oracle/gen_m65_certs.py), committed as data:
its keys are random, so it is generated once, not regenerated.

Rows: `ID<TAB>TAGS<TAB>OP<TAB>SUB<TAB>ARG...`, decoded by oracle/m65_core.lua.
TAGS is a comma list: the step that gates the row (`b` bignums, `c` digests,
HMAC and randomness, `d` ciphers and DES_string_to_key, `e` certificates, `g`
the module's shape), then any of
  `nondet:<why>`  the oracle's answer is random; its shape is compared, not
                  its bytes (oracle/gen_m65.py refuses a golden in which an
                  untagged row differs between two runs). `random` for the
                  random functions; `random-iv` for an encryption with GCM or
                  3DES key wrap and no IV (none, empty, or, to 7.94, a first
                  byte NUL), where libcrypto draws the IV itself;
                  `alias-name` for an argument error of bignum_rand or
                  bignum_pseudo_rand: one C function under two names
                  (`nse_openssl.cc` openssllib), and `luaL_argerror` names
                  whichever its search of package.loaded meets first, an
                  order Lua's per-state hash seed decides (`lstate.c:71`);
  `drift:<fam>`   7.94 and this tree's C differ here by design, family <fam>
                  of §2 (oracle/gen_m65.py --check-tree names every other
                  difference as a failure);
  `ivnul`         the IV's first byte is NUL (§2's IV family);
  `ub:iv-length-uaf`
                  the C is undefined here (LESSONS #033, ORACLE-CHECKS 5c): a
                  non-empty IV of the wrong length frees the cipher context and
                  then reads it for the error message (`nse_openssl.cc:438-441,
                  499-502`, DIVERGENCES `nse-openssl-iv-length-uaf`), which
                  kills 7.94 and this tree's C alike. No C run executes these
                  rows as written: the golden records `ub` and the message the
                  C means, from the oracle's one named repair
                  (oracle/build_openssl_oracle.sh). `ub_iv` decides the tag
                  from ALGS, and oracle/gen_m65.py checks that the rows raising
                  "Length of iv" are exactly the tagged ones;
  `ub:rc4-empty-key`
                  undefined inside libcrypto: RC4 (and RC4-40) with a
                  zero-length key, which RC4_set_key reads 256 bytes past
                  (DIVERGENCES `nse-openssl-rc4-empty-key`; the output differs
                  run to run). No golden: the row is covered from the Rust side.

Families (each generates the rows named; the counts are printed):
  meta     the module's keys, the BIGNUM metatable, supported_* lists
  digest   every digest name at the block-boundary lengths; every alias,
           case variant and junk name at two lengths
  hash     md4, md5, sha1, ripemd160 at the same lengths
  hmac     every digest name x key lengths around the block size x 3 messages
  keylen   which key lengths each cipher accepts
  cipher   primary cipher names: IV shapes x data lengths around the block x
           padding, encrypt, decrypt and the round trip
  cname    every alias and case variant of a cipher name: one encrypt
  bignum   construction from each text form; add/div pairs; mod_exp; bits;
           primality around the Carmichael and strong-pseudoprime edges;
           the methods
  des      DES_string_to_key
  rand     the random functions' shapes
  args     every function x every argument position x every wrong type
  cert     parse_ssl_certificate over CERTS (`der:ID` names a row of CERTS),
           its fields, pem and digest
"""

import random
import re
import subprocess
import sys

SEED = 0x6D65

# ---- tokens ------------------------------------------------------------------


def s(b):
    """A string argument: hex of its bytes (decoded by m65_core.lua)."""
    return "s:" + (b if isinstance(b, bytes) else b.encode("latin-1")).hex()


def bn(v, form):
    if form == "d" or v < 0:
        return "bnd:" + str(v).encode().hex()
    if form == "h":
        return "bnh:" + ("%x" % v).encode().hex()
    if form == "H":
        return "bnh:" + ("%X" % v).encode().hex()
    return "bnb:" + v.to_bytes((v.bit_length() + 7) // 8, "big").hex()


# ---- the algorithm table -----------------------------------------------------


def read_algs(path):
    """digests (a list), ciphers (name -> (key, iv, block) or None), digest
    aliases (a list), cipher aliases (a list), and `lookup`: every cipher name
    the cases use -> its lengths, or None where libcrypto finds no cipher."""
    digests, ciphers, adig, aciph, lookup = [], {}, [], [], {}

    def lens(f):
        return tuple(int(x) for x in f) if f[0] != "-" else None
    for line in open(path):
        if not line.strip() or line.startswith("#"):
            continue
        f = line.rstrip("\n").split("\t")
        if f[0] == "digest":
            digests.append(f[1])
        elif f[0] == "cipher":
            ciphers[f[1]] = lookup[f[1]] = lens(f[2:5])
        elif f[0] == "alias-digest":
            adig.append(f[1])
        elif f[0] == "alias-cipher":
            aciph.append(f[1])
            lookup[f[1]] = lens(f[2:5])
        elif f[0] == "lookup":
            lookup[bytes.fromhex(f[1]).decode("latin-1")] = lens(f[2:5])
    return digests, ciphers, adig, aciph, lookup


# Cipher names that are not in the table: junk, near misses, a NUL-truncated
# name (the C reads `luaL_checkstring`, so "aes-128-cbc\0x" is aes-128-cbc).
CJUNK = ["", "nope", "aes-128-cbc\0x", "AES-128-CBC-CTS", "NULL", "idea-cbc",
         " aes-128-cbc", "Aes-128-Cbc"]


def cipher_names(ciphers, aciph):
    """The ciphers that get the full sweep (`primary`: one name per algorithm,
    dropping the bare aliases the table lists for another name, aes128 for
    aes-128-cbc, ...) and every other name the cname family looks up."""
    alias_set = set(aciph)
    primary = [n for n in ciphers if n not in alias_set or "-" in n]
    variants = sorted((alias_set | {c.upper() for c in ciphers} | set(ciphers) | set(CJUNK))
                      - set(primary))
    return primary, variants


def capture_algs(out):
    import ctypes
    import os

    oracle = os.path.join(os.path.dirname(os.path.abspath(__file__)), "lua-openssl")
    names = subprocess.run(
        [oracle, "-e", 'local o = require "openssl"\n'
         'for _, n in ipairs(o.supported_digests()) do print("digest\\t" .. n) end\n'
         'for _, n in ipairs(o.supported_ciphers()) do print("cipher\\t" .. n) end'],
        capture_output=True, text=True, check=True).stdout.splitlines()
    lc = ctypes.CDLL("libcrypto.so.3")
    lc.OSSL_PROVIDER_load.restype = ctypes.c_void_p
    lc.OSSL_PROVIDER_load.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
    lc.OSSL_PROVIDER_load(None, b"legacy")
    lc.OSSL_PROVIDER_load(None, b"default")
    lc.EVP_get_cipherbyname.restype = ctypes.c_void_p
    lc.EVP_get_cipherbyname.argtypes = [ctypes.c_char_p]
    for f in ("EVP_CIPHER_get_key_length", "EVP_CIPHER_get_block_size"):
        getattr(lc, f).argtypes = [ctypes.c_void_p]
    lc.EVP_CIPHER_CTX_new.restype = ctypes.c_void_p
    lc.EVP_CIPHER_CTX_free.argtypes = [ctypes.c_void_p]
    lc.EVP_EncryptInit_ex.argtypes = [ctypes.c_void_p] * 5
    lc.EVP_CIPHER_CTX_get_iv_length.argtypes = [ctypes.c_void_p]

    def cinfo(name):
        c = lc.EVP_get_cipherbyname(name.encode("latin-1"))
        if not c:
            return None
        ctx = lc.EVP_CIPHER_CTX_new()
        lc.EVP_EncryptInit_ex(ctx, c, None, None, None)
        ivl = lc.EVP_CIPHER_CTX_get_iv_length(ctx)
        lc.EVP_CIPHER_CTX_free(ctx)
        return (lc.EVP_CIPHER_get_key_length(c), ivl, lc.EVP_CIPHER_get_block_size(c))

    def lens(name):
        info = cinfo(name)
        return "\t".join(map(str, info)) if info else "-\t-\t-"

    def aliases(kind):
        text = subprocess.run(["openssl", "list", "-%s-algorithms" % kind],
                              capture_output=True, text=True, check=True).stdout
        found = set()
        for m in re.finditer(r"\{([^}]*)\}|^\s+([\w./-]+)(?: =>.*)?(?: @.*)?$", text, re.M):
            for n in (m.group(1) or m.group(2) or "").split(","):
                n = n.strip()
                if n and not re.match(r"^[\d.]+$", n):
                    found.add(n)
        return sorted(found)

    version = subprocess.run(["openssl", "version"], capture_output=True, text=True).stdout.strip()
    ciphers = {}
    with open(out, "w") as fh:
        fh.write("# M6.5 algorithm table (gen_m65_cases.py --capture-algs), from the oracle\n"
                 "# and libcrypto: %s.\n"
                 "# Captured once and committed: the cases are generated from it, not\n"
                 "# from the host's OpenSSL. Lengths: key, IV (the context's,\n"
                 "# after EVP_EncryptInit_ex), block; `-` where no cipher resolves.\n"
                 "# `lookup` names are hex (one holds a NUL).\n" % version)
        for line in names:
            kind, name = line.split("\t")
            if kind == "digest":
                fh.write("digest\t%s\n" % name)
            else:
                ciphers[name] = None
                fh.write("cipher\t%s\t%s\n" % (name, lens(name)))
        for n in aliases("digest"):
            fh.write("alias-digest\t%s\n" % n)
        acs = aliases("cipher")
        for n in acs:
            fh.write("alias-cipher\t%s\t%s\n" % (n, lens(n)))
        known = set(ciphers) | set(acs)
        for n in cipher_names(ciphers, acs)[1]:
            if n not in known:
                fh.write("lookup\t%s\t%s\n" % (n.encode("latin-1").hex(), lens(n)))


# ---- the cases -----------------------------------------------------------------


def generate(algs, certs):
    R = random.Random(SEED)
    rows = []
    counts = {}

    def rb(n):
        return bytes(R.getrandbits(8) for _ in range(n))

    def rb_nz(n):
        b = bytearray(rb(n))
        if b:
            b[0] |= 1
        return bytes(b)

    digests, ciphers, adig, aciph, lookup = algs

    def case(fam, tags, op, sub, *args):
        for extra in (ub_iv(lookup, op, sub, args), ub_rc4(lookup, op, sub, args),
                      random_iv(lookup, op, sub, args)):
            if extra:
                tags += "," + extra
        rows.append((tags, op, sub) + args)
        counts[fam] = counts.get(fam, 0) + 1

    # -- meta (g) ---------------------------------------------------------------
    for what in ("keys", "bnmeta", "digests", "ciphers", "state"):
        case("meta", "g", "meta", what)

    # -- digests (c) ------------------------------------------------------------
    # Lengths at the block boundaries of every digest: 64-byte blocks (MD, SHA-1,
    # SHA-256), 128 (SHA-512), and the SHA-3/SHAKE rates 72, 104, 136, 144, 168.
    LENS = [0, 1, 55, 56, 57, 63, 64, 65, 71, 72, 103, 104, 111, 112, 113, 127, 128,
            129, 135, 136, 143, 144, 167, 168, 1000, 4099]
    junk = ["", "nope", "md5\0junk", "MD2", "MDC2", "sha512/224", "KECCAK-256", "SHA-256",
            " md5", "md5 ", "Md5", "sha1\0"]
    dvariants = sorted((set(adig) | {d.upper() for d in digests} | set(junk)) - set(digests))
    for n in digests:
        for L in LENS:
            case("digest", "c", "call", "digest", s(n), s(rb(L)))
    for n in dvariants:
        for L in (0, 3):
            case("digest", "c", "call", "digest", s(n), s(rb(L)))
    for fn in ("md4", "md5", "sha1", "ripemd160"):
        for L in LENS:
            case("hash", "c", "call", fn, s(rb(L)))
    # -- hmac (c) ---------------------------------------------------------------
    for n in digests + dvariants[::4]:
        for kl in (0, 1, 64, 65, 129, 200):
            case("hmac", "c", "call", "hmac", s(n), s(rb(kl)), s(rb(R.choice((0, 1, 200)))))
    for kl in range(0, 260, 7):
        case("hmac", "c", "call", "hmac", s("sha512"), s(rb(kl)), s(rb(33)))

    # -- ciphers (d) ------------------------------------------------------------
    # One name per algorithm gets the full sweep; its aliases, case variants
    # and near misses get a resolution row each, with the key and IV the name
    # resolves to (`lookup`), so that the row tests the name.
    primary, cvariants = cipher_names(ciphers, aciph)
    for n in primary:
        info = ciphers[n]
        kl, ivl, bs = info if info else (16, 16, 16)
        # Which key lengths the C accepts (`EVP_CIPHER_CTX_set_key_length`):
        # around the cipher's own, and the usual sizes.
        for k in sorted({0, 1, 5, 7, 8, 15, 16, 17, 24, 31, 32, 33, 48, 64, 72,
                         max(kl - 1, 0), kl, kl + 1}):
            case("keylen", "d", "call", "encrypt", s(n), s(rb(k)), "nil", s(rb(16)), "nil")
        key = rb(kl)
        # The data sweep runs with the correct IV (none, for a cipher without
        # one); each other IV shape (none, empty, the first byte NUL, one byte
        # long, one short; any, for a cipher without one) tests the IV rules,
        # which one data length shows (`nse_openssl.cc:413-441`). The wrong
        # lengths are `ub:iv-length-uaf` (`ub_iv`).
        if ivl:
            good = s(rb_nz(ivl))
            ivs = [(good, ""), ("nil", ""), (s(b""), ""), (s(b"\0" + rb(ivl - 1)), "ivnul"),
                   (s(rb_nz(ivl + 1)), ""), (s(rb_nz(max(ivl - 1, 1))), "")]
        else:
            good = "nil"
            ivs = [(good, ""), (s(b""), ""), (s(rb_nz(16)), "")]
        datas = sorted({0, 1, bs - 1, bs, bs + 1, 2 * bs + 3, 33} - {-1})
        for iv, ivtag in ivs:
            tags = "d" + ("," + ivtag if ivtag else "")
            for L in (datas if iv == good else [bs]):
                for p in ("nil", "T"):
                    d = s(rb(L))
                    case("cipher", tags, "call", "encrypt", s(n), s(key), iv, d, p)
                    case("cipher", tags, "call", "decrypt", s(n), s(key), iv, d, p)
                    case("cipher", tags, "rt", n, s(key), iv, d, p)
        # The padding argument's truthiness, once per cipher (`false` and nil
        # are both "off", `lua_toboolean`).
        for p in ("F", "i:0", "s:", "tbl"):
            case("cipher", "d", "call", "encrypt", s(n), s(key), good, s(rb(bs)), p)
    for n in cvariants:
        info = lookup[n]
        kl, ivl, bs = info if info else (16, 16, 16)
        iv = s(rb_nz(ivl)) if ivl else "nil"
        case("cname", "d", "call", "encrypt", s(n), s(rb(kl)), iv, s(rb(bs)), "nil")

    # -- DES_string_to_key (d) --------------------------------------------------
    for _ in range(200):
        case("des", "d", "call", "DES_string_to_key", s(rb(7)))
    for L in (0, 6, 8, 14):
        case("des", "d", "call", "DES_string_to_key", s(rb(L)))

    # -- bignums (b) --------------------------------------------------------------
    V = [0, 1, 2, 3, 4, 7, 8, 255, 256, 257, 65535, 65536, 2**31 - 1, 2**31, 2**32 - 1, 2**32,
         2**63 - 1, 2**63, 2**64 - 1, 2**64, 2**64 + 1, 2**127, 2**128 - 1, 2**128,
         2**61 - 1, 2**89 - 1, 2**127 - 1, 2**521 - 1, 2**255 - 19,
         561, 1105, 1729, 2465, 2821, 6601, 8911, 2047, 3215031751, 3825123056546413051,
         318665857834031151167461, 5, 7, 11, 23, 47, 59, 83, 107]
    V += [R.getrandbits(b) | 1 for b in (64, 127, 128, 129, 255, 256, 511, 512, 1024, 2048)
          for _ in range(2)]
    V += [-v for v in V if v]

    def anybn(v):
        return bn(v, R.choice("dhHb") if v >= 0 else "d")

    for v in V:
        for form in "dhHb":
            if v >= 0 or form == "d":
                case("bignum", "b", "call", "bignum_add", bn(v, form), bn(0, "b"))
    for t in ["", "-", "+5", " 5", "5 ", "0x10", "--5", "00012", "-0", "12abc", "9" * 2000,
              "\x00", "1\x002", "-00", "1e3"]:
        case("bignum", "b", "call", "bignum_dec2bn", s(t))
    for t in ["", "-", "0x10", "ff", "FF", "-ff", "fG", "000000ff", "f" * 2000, "-0", "1 2", "f"]:
        case("bignum", "b", "call", "bignum_hex2bn", s(t))
    for t in [b"", b"\0", b"\0\0\x01", b"\x80", b"\xff" * 300]:
        case("bignum", "b", "call", "bignum_bin2bn", s(t))
    pairs = [(a, b) for a in V for b in V]
    R.shuffle(pairs)
    for a, b in pairs[:2500]:
        case("bignum", "b", "call", "bignum_add", anybn(a), anybn(b))
        case("bignum", "b", "call", "bignum_div", anybn(a), anybn(b))
    for _ in range(2000):
        a, p, m = R.choice(V), R.choice(V), R.choice(V)
        if abs(p).bit_length() > 600 and abs(m).bit_length() > 1100:
            continue
        case("bignum", "b", "call", "bignum_mod_exp", anybn(a), anybn(p), anybn(m))
    POS = [-1, 0, 1, 7, 8, 31, 32, 63, 64, 65, 200, (1 << 32) + 3, -(1 << 32) + 1]
    for v in V[::3]:
        for p in POS:
            for fn in ("bignum_set_bit", "bignum_clear_bit"):
                case("bignum", "b", "mut", fn, anybn(v), "i:%d" % p)
            case("bignum", "b", "call", "bignum_is_bit_set", anybn(v), "i:%d" % p)
    # Primality: small values exhaustively, then the edges in V. Random
    # witnesses (`BN_check_prime`), but every composite here fails a round
    # with overwhelming probability, so the answer is deterministic.
    for n in list(range(-10, 400)) + V:
        case("bignum", "b", "call", "bignum_is_prime", anybn(n))
        case("bignum", "b", "call", "bignum_is_safe_prime", anybn(n))
    for v in V[::4]:
        for m in ("num_bits", "num_bytes", "tobin", "tompi", "todec", "tohex",
                  "is_prime", "is_safe_prime"):
            case("bignum", "b", "meth", m, anybn(v))
        for m in ("set_bit", "clear_bit", "is_bit_set"):
            for p in (0, 1, 64, 200):
                case("bignum", "b", "meth", m, anybn(v), "i:%d" % p)

    # -- randomness (c, b) --------------------------------------------------------
    for fn in ("rand_bytes", "rand_pseudo_bytes"):
        for n in (0, 1, 2, 16, 1000, -1):
            case("rand", "c,nondet:random", "rlen", fn, "i:%d" % n)
    for fn in ("bignum_rand", "bignum_pseudo_rand"):
        for n in (0, 1, 2, 7, 8, 9, 64, 1024, -1):
            case("rand", "b,nondet:random", "rlen", fn, "i:%d" % n)

    # -- argument checking -------------------------------------------------------
    one, two, three, five, seven, nine = (bn(v, "b") for v in (1, 2, 3, 5, 7, 9))
    GOOD = {
        "digest": ("c", [s("md5"), s(b"x")]), "hmac": ("c", [s("md5"), s(b"k"), s(b"x")]),
        "encrypt": ("d", [s("rc4"), s(b"k" * 16), "nil", s(b"x"), "nil"]),
        "decrypt": ("d", [s("rc4"), s(b"k" * 16), "nil", s(b"x"), "nil"]),
        "md4": ("c", [s(b"x")]), "md5": ("c", [s(b"x")]), "sha1": ("c", [s(b"x")]),
        "ripemd160": ("c", [s(b"x")]), "DES_string_to_key": ("d", [s(b"x" * 7)]),
        "rand_bytes": ("c", ["i:4"]), "rand_pseudo_bytes": ("c", ["i:4"]),
        "bignum_bin2bn": ("b", [s(b"\1")]), "bignum_dec2bn": ("b", [s("1")]),
        "bignum_hex2bn": ("b", [s("1")]), "bignum_rand": ("b", ["i:8"]),
        "bignum_pseudo_rand": ("b", ["i:8"]), "bignum_add": ("b", [one, two]),
        "bignum_div": ("b", [seven, two]), "bignum_mod_exp": ("b", [two, three, five]),
        "bignum_num_bits": ("b", [five]), "bignum_num_bytes": ("b", [five]),
        "bignum_bn2bin": ("b", [five]), "bignum_bn2mpi": ("b", [five]),
        "bignum_bn2dec": ("b", [five]), "bignum_bn2hex": ("b", [five]),
        "bignum_is_prime": ("b", [five]), "bignum_is_safe_prime": ("b", [five]),
        "bignum_set_bit": ("b", [five, "i:1"]), "bignum_clear_bit": ("b", [five, "i:1"]),
        "bignum_is_bit_set": ("b", [five, "i:1"]),
        "parse_ssl_certificate": ("e", [s(b"\x30\x00")]),
    }
    BAD = ["nil", "T", "tbl", "fn", "i:42", "f:1.5", "f:3.0", s(b"7"), nine]
    for fn, (step, good) in sorted(GOOD.items()):
        rnd = ",nondet:random" if fn in ("rand_bytes", "rand_pseudo_bytes", "bignum_rand",
                                        "bignum_pseudo_rand") else ""
        if fn in ("bignum_rand", "bignum_pseudo_rand"):
            rnd += ",nondet:alias-name"
        op = "cert" if fn == "parse_ssl_certificate" else "call"
        for i in range(len(good)):
            for b in BAD:
                args = list(good)
                args[i] = b
                case("args", step + rnd, op, fn, *args)
            case("args", step + rnd, op, fn, *good[:i])

    # -- certificates (e) --------------------------------------------------------
    for line in open(certs):
        if line.startswith("#") or not line.strip():
            continue
        cid = line.split("\t", 1)[0]
        case("cert", "e", "cert", "parse_ssl_certificate", "der:" + cid)

    return rows, counts


def lua_tostring(tok):
    """The string `luaL_optlstring` makes of an argument token, or None where
    it raises (a non-string, non-number) or sees none (nil)."""
    if tok.startswith("s:"):
        return bytes.fromhex(tok[2:])
    if tok.startswith("i:"):
        return tok[2:].encode()
    if tok.startswith("f:"):
        v = float(tok[2:])  # LUAI_NUMFFORMAT "%.14g", with ".0" when integral
        t = "%.14g" % v
        return (t + ".0" if re.match(r"^-?\d+$", t) else t).encode()
    return None


def cipher_args(op, sub, args):
    """(name, key token, iv token) of a cipher row, or None."""
    if op == "rt":
        return sub, args[0], args[1]
    if op == "call" and sub in ("encrypt", "decrypt") and len(args) >= 3 \
            and args[0].startswith("s:"):
        return bytes.fromhex(args[0][2:]).decode("latin-1").split("\0")[0], args[1], args[2]
    return None


def ub_rc4(lookup, op, sub, args):
    """`ub:rc4-empty-key`: RC4 under any of its names with a zero-length key
    (RC4_set_key reads 256 bytes of it). rc4-hmac-md5 refuses the length."""
    ca = cipher_args(op, sub, args)
    if ca is None or lua_tostring(ca[1]) != b"":
        return None
    info = lookup.get(ca[0])
    name = ca[0].lower()
    if info is not None and name in ("rc4", "rc4-40"):
        return "ub:rc4-empty-key"
    return None


RANDOM_IV = ("des3-wrap", "id-smime-alg-cms3deswrap")


def random_iv(lookup, op, sub, args):
    """`nondet:random-iv`: an encryption with GCM or 3DES key wrap and no
    IV, to this tree's C (nil or empty) or to 7.94 (also a first byte NUL)."""
    ca = cipher_args(op, sub, args)
    if ca is None or (op == "call" and sub != "encrypt") or lookup.get(ca[0]) is None:
        return None
    name = ca[0].lower()
    if not (name.endswith("gcm") or name in RANDOM_IV):
        return None
    ivb = lua_tostring(ca[2])
    if ivb is None and ca[2] != "nil":
        return None  # raises
    if not ivb or ivb[0] == 0:
        return "nondet:random-iv"
    return None


def ub_iv(lookup, op, sub, args):
    """`ub:iv-length-uaf` when the C reaches the use-after-free on this row
    (`nse_openssl.cc:438-441,499-502`): a known cipher, a key length it takes,
    and a non-empty IV whose length is not the context's. Every key in a
    wrong-IV row of this generator is the cipher's own length; one that is
    not would make the key check decide first, and is refused here."""
    ca = cipher_args(op, sub, args)
    if ca is None:
        return None
    name, key, iv = ca
    info = lookup.get(name)
    ivb = lua_tostring(iv)
    if info is None or not ivb or len(ivb) == info[1]:
        return None
    keyb = lua_tostring(key)
    if keyb is None or len(keyb) != info[0]:
        raise SystemExit("a wrong-length IV with a key the key check may refuse: %s %s %s"
                         % (op, sub, args))
    if ivb[0] == 0:
        raise SystemExit("a wrong-length IV whose first byte is NUL is UB in the tree and "
                         "not in 7.94 (§2): %s %s %s" % (op, sub, args))
    return "ub:iv-length-uaf"


def write(rows, out):
    with open(out, "w") as fh:
        fh.write("# M6.5 openssl cases: gen_m65_cases.py from m65_algs.txt and m65_certs.txt.\n"
                 "# ID<TAB>TAGS<TAB>OP<TAB>SUB<TAB>ARG...   (tokens: oracle/m65_core.lua)\n")
        for i, r in enumerate(rows, 1):
            fh.write("c%06d\t%s\n" % (i, "\t".join(r)))


def self_test():
    import os
    import tempfile
    here = os.path.dirname(os.path.abspath(__file__))
    algs = os.path.join(here, "..", "m65_algs.txt")
    certs = os.path.join(here, "..", "m65_certs.txt")
    assert lua_tostring("f:3.0") == b"3.0" and lua_tostring("f:1.5") == b"1.5"
    a = generate(read_algs(algs), certs)[0]
    b = generate(read_algs(algs), certs)[0]
    assert a == b, "the generator is not deterministic"
    with tempfile.TemporaryDirectory() as d:
        write(a, os.path.join(d, "x"))
        text = open(os.path.join(d, "x")).read()
    assert "\r" not in text
    for r in a:
        for tok in r[3:]:
            assert re.match(r"^(nil|T|F|tbl|fn|s:([0-9a-f]{2})*|bn[dhb]:([0-9a-f]{2})*|"
                            r"i:-?\d+|f:[\d.]+|der:[xbkp]\d+)$", tok), tok
    print("self-test ok: %d rows, deterministic" % len(a))


def main():
    if sys.argv[1:2] == ["--capture-algs"]:
        capture_algs(sys.argv[2])
        return
    if sys.argv[1:2] == ["--self-test"]:
        self_test()
        return
    algs, certs, out = sys.argv[1:4]
    rows, counts = generate(read_algs(algs), certs)
    write(rows, out)
    print("%d rows: %s" % (len(rows), ", ".join("%s %d" % kv for kv in counts.items())),
          file=sys.stderr)


if __name__ == "__main__":
    main()
