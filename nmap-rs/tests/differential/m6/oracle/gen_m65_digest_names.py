#!/usr/bin/env python3
"""The M6.5 digest name table (docs/M6.5-ANALYSIS.md §11 row c, D4).

    python3 oracle/gen_m65_digest_names.py OUT       write the table
    python3 oracle/gen_m65_digest_names.py --check   regenerate and compare

`EVP_get_digestbyname` (`nse_openssl.cc:316,361`) resolves a name through
OpenSSL's object-name table and its provider namemap: case-insensitively,
with aliases, signature-algorithm names and dotted OIDs, and only up to the
first NUL (`luaL_checkstring`). D4(b) keeps the md4, md5, sha1, ripemd160 and
SHA-2 families; every other name the oracle accepts is `other`, which the
port refuses as an unknown digest (`openssl-algorithm-subset`).

The table is every spelling below, each classified by asking the oracle
(oracle/lua-openssl, this tree's C over the system OpenSSL 3.0.13, the
version nmap 7.94's golden records) for `digest(name, "abc")` and matching
the answer against the published vectors for "abc" (RFC 1320, RFC 1321,
FIPS 180-4, the RIPEMD-160 page) and Python's hashlib:

    HEXNAME<TAB>CLASS

CLASS is one of the D4 algorithms (`md4`, `md5`, `sha1`, `ripemd160`,
`sha224`, `sha256`, `sha384`, `sha512`, `sha512-224`, `sha512-256`), `other`
(accepted, outside D4) or `unknown` (refused). The spellings: every name of
`m65_algs.txt` (`supported_digests` and OpenSSL's aliases) and of the case
corpus's `digest` and `hmac` rows, their case
variants, the corpus's near misses, each D4 algorithm's OIDs and
signature-algorithm names with and without padding, separators changed, a
NUL and junk appended, and the OIDs of digests outside D4: more than 150
spellings, which crates/core/src/nse/openssl/digest.rs must resolve exactly
as recorded (`every_recorded_spelling_resolves_as_the_oracle_does`).
"""

import hashlib
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
ORACLE = os.path.join(HERE, "lua-openssl")
ALGS = os.path.join(M6, "m65_algs.txt")
CASES = os.path.join(M6, "m65_cases.txt")
OUT = os.path.join(M6, "m65_digest_names.txt")

# digest(name, "abc") for each D4 algorithm. md4 and ripemd160 are the
# published vectors (hashlib's need OpenSSL's legacy provider); the rest are
# hashlib's, which are FIPS 180-4's.
ABC = {
    "md4": "a448017aaf21d8525fc10ae87aa6729d",  # RFC 1320 A.5
    "md5": "900150983cd24fb0d6963f7d28e17f72",  # RFC 1321 A.5
    "ripemd160": "8eb208f7e05d987a9b044a8e98c6b087f15a0bfc",
    "sha1": hashlib.sha1(b"abc").hexdigest(),
    "sha224": hashlib.sha224(b"abc").hexdigest(),
    "sha256": hashlib.sha256(b"abc").hexdigest(),
    "sha384": hashlib.sha384(b"abc").hexdigest(),
    "sha512": hashlib.sha512(b"abc").hexdigest(),
    "sha512-224": "4634270f707b6a54daae7530460842e20e37ed265ceee9a43e8924aa",
    "sha512-256": "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
}
assert ABC["sha1"] == "a9993e364706816aba3e25717850c26c9cd0d89d"
BY_DIGEST = {v: k for k, v in ABC.items()}

# Each D4 algorithm's OID (`objects.txt`) and the OIDs of its signature
# algorithms, which name no digest.
OIDS = {
    "md4": "1.2.840.113549.2.4",
    "md5": "1.2.840.113549.2.5",
    "sha1": "1.3.14.3.2.26",
    "ripemd160": "1.3.36.3.2.1",
    "sha224": "2.16.840.1.101.3.4.2.4",
    "sha256": "2.16.840.1.101.3.4.2.1",
    "sha384": "2.16.840.1.101.3.4.2.2",
    "sha512": "2.16.840.1.101.3.4.2.3",
    "sha512-224": "2.16.840.1.101.3.4.2.5",
    "sha512-256": "2.16.840.1.101.3.4.2.6",
}
OTHER_OIDS = [
    "1.2.840.113549.2.2",  # md2
    "2.5.8.3.101",  # mdc2
    "1.0.10118.3.0.55",  # whirlpool
    "1.2.156.10197.1.401",  # sm3
    "1.3.6.1.4.1.1722.12.2.1.16",  # blake2b512
    "1.3.6.1.4.1.1722.12.2.2.8",  # blake2s256
] + ["2.16.840.1.101.3.4.2.%d" % i for i in range(7, 13)] + [  # sha3, shake
    "1.2.840.113549.1.1.2", "1.2.840.113549.1.1.3", "1.2.840.113549.1.1.4",
    "1.2.840.113549.1.1.5", "1.2.840.113549.1.1.11", "1.2.840.113549.1.1.14",
    "1.3.14.3.2.29", "1.3.36.3.3.1.2",  # signature algorithms
]


def read_names():
    names = []
    for line in open(ALGS):
        f = line.rstrip("\n").split("\t")
        if f[0] in ("digest", "alias-digest"):
            names.append(f[1].encode())
    return names


def corpus_names():
    """Every name a `digest` or `hmac` row of the case corpus passes."""
    names = set()
    for line in open(CASES):
        f = line.rstrip("\n").split("\t")
        if len(f) > 4 and f[2] == "call" and f[3] in ("digest", "hmac") and f[4].startswith("s:"):
            names.add(bytes.fromhex(f[4][2:]))
    return names


def spellings():
    base = read_names()
    out = set(base) | corpus_names()
    for n in base:
        out.add(n.lower())
        out.add(n.upper())
        out.add(n.swapcase())
    for alg, oid in OIDS.items():
        out.add(oid.encode())
        out.add(oid.encode() + b".0")
        out.add(oid.encode() + b" ")
        out.add(b" " + oid.encode())
        out.add(oid.encode().replace(b".", b".0", 1))
        out.add(b"OID." + oid.encode())
        out.add(alg.encode() + b"\0")
        out.add(alg.encode() + b"\0junk")
        out.add(alg.upper().encode() + b"\0" + b"md5")
        out.add(b" " + alg.encode())
        out.add(alg.encode() + b" ")
        out.add(b"\t" + alg.encode())
        out.add(alg.encode().replace(b"-", b"_"))
        out.add(alg.encode().replace(b"-", b"/"))
        out.add(alg.encode() + b"WithRSA")
        out.add(b"hmac-" + alg.encode())
        out.add(b"HMAC" + alg.upper().encode())
    for oid in OTHER_OIDS:
        out.add(oid.encode())
    out |= {
        b"", b"\0", b"\0md5", b"nope", b"MD2", b"MDC2", b"NULL", b"md5 ", b" md5",
        b"Md5", b"mD5", b"sha", b"SHA", b"sha2", b"sha-2", b"sha-0", b"sha0",
        b"sha-1-", b"sha--256", b"sha 256", b"sha256 ", b"sha256\n", b"md5\xff",
        b"\xffmd5", b"m\xc3\xa45", b"sha512/224", b"SHA512/256", b"sha512_224",
        b"sha-512-224", b"sha512224", b"rmd-160", b"ripemd-128", b"ripemd128",
        b"RIPEMD320", b"KECCAK-256", b"md5sum", b"dsaWithSHA1", b"DSA-SHA1",
        b"ecdsa-with-SHA256", b"md5-sha1", b"ssl2-md5", b"0", b"42", b"1.5",
        b"RSA", b"rsaEncryption", b"1.2.840.113549", b"2.16.840.1.101.3.4.2",
    }
    return sorted(out)


def lua_quote(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def classify(names):
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write("local o = openssl or require 'openssl'\n")
        f.write("for _, n in ipairs{%s} do\n" % ",\n".join(lua_quote(n) for n in names))
        f.write("local function hex(s) return (s:gsub('.', function(c) return ('%02x'):format(c:byte()) end)) end\n")
        f.write("  local ok, r = pcall(o.digest, n, 'abc')\n")
        f.write("  print((ok and '' or 'ERR ') .. hex(r))\nend\n")
        script = f.name
    try:
        out = subprocess.run([ORACLE, script], check=True, capture_output=True).stdout
    finally:
        os.unlink(script)
    lines = out.decode("latin-1").splitlines()
    assert len(lines) == len(names), (len(lines), len(names))
    rows = []
    for n, r in zip(names, lines):
        if r.startswith("ERR "):
            want = b"Unknown digest algorithm: " + n.split(b"\0")[0]
            assert bytes.fromhex(r[4:]) == want, (n, r)
            rows.append((n, "unknown"))
        else:
            rows.append((n, BY_DIGEST.get(r, "other")))
    return rows


def render(rows):
    lines = [
        "# M6.5 digest names (oracle/gen_m65_digest_names.py): how this tree's C",
        "# over OpenSSL 3.0.13 resolves each spelling, by digest(name, \"abc\").",
        "# HEXNAME<TAB>CLASS: a D4(b) algorithm, `other` (accepted, outside D4:",
        "# `openssl-algorithm-subset`), or `unknown`.",
    ]
    lines += ["%s\t%s" % (n.hex(), c) for n, c in rows]
    return "\n".join(lines) + "\n"


def main():
    names = spellings()
    assert len(names) > 150, len(names)
    text = render(classify(names))
    if sys.argv[1:] == ["--check"]:
        if open(OUT).read() != text:
            sys.exit("FAIL: m65_digest_names.txt is stale: run oracle/gen_m65_digest_names.py")
        print("m6.5 digest names: current (%d spellings)" % len(names))
        return
    path = sys.argv[1] if sys.argv[1:] else OUT
    open(path, "w").write(text)
    counts = {}
    for line in text.splitlines():
        if not line.startswith("#"):
            c = line.split("\t")[1]
            counts[c] = counts.get(c, 0) + 1
    print("m6.5 digest names: %d spellings, %s" % (len(names), sorted(counts.items())))


if __name__ == "__main__":
    main()
