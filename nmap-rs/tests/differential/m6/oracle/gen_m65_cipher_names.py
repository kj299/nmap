#!/usr/bin/env python3
"""The M6.5 cipher name table (docs/M6.5-ANALYSIS.md §11 row d, D4).

    python3 oracle/gen_m65_cipher_names.py OUT       write the table
    python3 oracle/gen_m65_cipher_names.py --check   regenerate and compare

`EVP_get_cipherbyname` (`nse_openssl.cc:405,469`) resolves a name through
OpenSSL's object-name table and its provider namemap: ASCII
case-insensitively, with aliases and dotted OIDs, and only up to the first
NUL (`luaL_checkstring`). D4(b) keeps des-ecb, des-cbc, aes-128/192/256 in
ECB and CBC, and cast5-ecb and cast5-cbc; every other name the oracle
accepts is `other`, which the port refuses as an unknown cipher
(`openssl-algorithm-subset`).

Each spelling is classified by asking the oracle (oracle/lua-openssl, this
tree's C over the system OpenSSL 3.0.13, the version 7.94's golden records)
to encrypt with it, and comparing with the same encryptions under each D4
algorithm's canonical name, with that algorithm's key and IV lengths: two
whole blocks without padding, and 33 bytes with it (which tells a CBC mode
from the stitched `-hmac-sha1` ones that share its key and IV):

    HEXNAME<TAB>CLASS

CLASS is a canonical D4 name, `other` (accepted, outside D4) or `unknown`
(refused). The spellings: every cipher name and alias of `m65_algs.txt` and
every name the case corpus passes, their case variants, each D4 algorithm's
OIDs padded and prefixed, a NUL and junk appended, separators changed, and
near misses. crates/core/src/nse/openssl/cipher.rs must resolve each exactly
as recorded (`every_recorded_cipher_spelling_resolves_as_the_oracle_does`).
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
ORACLE = os.path.join(HERE, "lua-openssl")
ALGS = os.path.join(M6, "m65_algs.txt")
CASES = os.path.join(M6, "m65_cases.txt")
OUT = os.path.join(M6, "m65_cipher_names.txt")

# D4(b): canonical name -> (key length, IV length, block size), and OID.
D4 = {
    "des-ecb": (8, 0, 8, "1.3.14.3.2.6"),
    "des-cbc": (8, 8, 8, "1.3.14.3.2.7"),
    "aes-128-ecb": (16, 0, 16, "2.16.840.1.101.3.4.1.1"),
    "aes-128-cbc": (16, 16, 16, "2.16.840.1.101.3.4.1.2"),
    "aes-192-ecb": (24, 0, 16, "2.16.840.1.101.3.4.1.21"),
    "aes-192-cbc": (24, 16, 16, "2.16.840.1.101.3.4.1.22"),
    "aes-256-ecb": (32, 0, 16, "2.16.840.1.101.3.4.1.41"),
    "aes-256-cbc": (32, 16, 16, "2.16.840.1.101.3.4.1.42"),
    "cast5-ecb": (16, 0, 8, None),
    "cast5-cbc": (16, 8, 8, "1.2.840.113533.7.66.10"),
}
OTHER_OIDS = [
    "1.3.14.3.2.8", "1.3.14.3.2.9", "1.2.840.113549.3.7", "1.2.840.113549.3.2",
    "2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.6",
    "2.16.840.1.101.3.4.1.5", "1.2.840.113549.3.4", "1.3.6.1.4.1.3029.1.2",
]


def algs_names():
    names = set()
    for line in open(ALGS):
        f = line.rstrip("\n").split("\t")
        if f[0] in ("cipher", "alias-cipher"):
            names.add(f[1].encode())
        elif f[0] == "lookup":
            names.add(bytes.fromhex(f[1]))
    return names


def corpus_names():
    names = set()
    for line in open(CASES):
        f = line.rstrip("\n").split("\t")
        if len(f) > 4 and f[2] == "call" and f[3] in ("encrypt", "decrypt") and f[4].startswith("s:"):
            names.add(bytes.fromhex(f[4][2:]))
        elif len(f) > 3 and f[2] == "rt":
            names.add(f[3].encode())
    return names


def spellings():
    base = algs_names() | corpus_names()
    out = set(base)
    for n in base:
        out |= {n.lower(), n.upper(), n.swapcase()}
    for name, (_, _, _, oid) in D4.items():
        n = name.encode()
        out |= {n + b"\0", n + b"\0junk", n.upper() + b"\0des", b" " + n, n + b" ",
                b"\t" + n, n.replace(b"-", b"_"), n.replace(b"-", b""), n + b"-", n + b"-pad",
                n.replace(b"-", b"/"), b"evp-" + n}
        if oid:
            o = oid.encode()
            out |= {o, o + b".0", o + b" ", b" " + o, o.replace(b".", b".0", 1), b"OID." + o}
    for oid in OTHER_OIDS:
        out.add(oid.encode())
    out |= {
        b"", b"\0", b"\0des", b"nope", b"aes", b"AES", b"aes-128", b"aes-cbc", b"aes128-cbc",
        b"aes-128-cbc-pad", b"des-cbc-pad", b"des-56", b"des56", b"cast5", b"CAST5", b"cast-128",
        b"cast128", b"cast5-128-cbc", b"blowfish", b"des\xff", b"\xffdes", b"d\xc3\xa9s", b"0",
        b"42", b"1.5", b"aes-128-cbc\n", b"rijndael", b"3des", b"tripledes",
    }
    return sorted(out)


def lua_quote(b):
    return '"' + "".join("\\x%02x" % c for c in b) + '"'


def classify(names):
    probes = []
    for name, (kl, ivl, _, _) in D4.items():
        key = bytes((i * 7 + kl) & 0xFF for i in range(kl))
        iv = bytes((i * 13 + 1) & 0xFF for i in range(ivl)) if ivl else b""
        probes.append((name, key, iv))
    with tempfile.NamedTemporaryFile("w", suffix=".lua", delete=False) as f:
        f.write("local o = openssl or require 'openssl'\n")
        f.write("local function hex(s) return (s:gsub('.', function(c) "
                "return ('%02x'):format(c:byte()) end)) end\n")
        f.write("local d32, d33 = ('\\x5a'):rep(32), ('\\xa5'):rep(33)\n")
        f.write("local probes = {%s}\n" % ",".join(
            "{%s,%s,%s}" % (lua_quote(n.encode()), lua_quote(k), lua_quote(v)) for n, k, v in probes))
        f.write("local function sig(name, p)\n"
                "  local ok1, a = pcall(o.encrypt, name, p[2], p[3], d32, false)\n"
                "  local ok2, b = pcall(o.encrypt, name, p[2], p[3], d33, true)\n"
                "  return (ok1 and hex(a) or 'E') .. '/' .. (ok2 and hex(b) or 'E')\n"
                "end\n")
        f.write("local want = {} for i, p in ipairs(probes) do want[i] = sig(p[1], p) end\n")
        f.write("for _, n in ipairs{%s} do\n" % ",\n".join(lua_quote(n) for n in names))
        f.write("  local ok, e = pcall(o.encrypt, n, '', nil, '', false)\n"
                "  if not ok and tostring(e):find('^Unknown cipher algorithm: ') then\n"
                "    print('unknown ' .. hex(e))\n"
                "  else\n"
                "    local cls = 'other'\n"
                "    for i, p in ipairs(probes) do\n"
                "      if sig(n, p) == want[i] then cls = p[1] break end\n"
                "    end\n"
                "    print(cls)\n"
                "  end\n"
                "end\n")
        script = f.name
    try:
        out = subprocess.run([ORACLE, script], check=True, capture_output=True).stdout
    finally:
        os.unlink(script)
    lines = out.decode("latin-1").splitlines()
    assert len(lines) == len(names), (len(lines), len(names))
    rows = []
    for n, r in zip(names, lines):
        if r.startswith("unknown "):
            want = b"Unknown cipher algorithm: " + n.split(b"\0")[0]
            assert bytes.fromhex(r[8:]) == want, (n, r)
            rows.append((n, "unknown"))
        else:
            rows.append((n, r))
    for canon in D4:
        assert (canon.encode(), canon) in rows, canon
    return rows


def render(rows):
    lines = [
        "# M6.5 cipher names (oracle/gen_m65_cipher_names.py): how this tree's C",
        "# over OpenSSL 3.0.13 resolves each spelling, by what it encrypts to.",
        "# HEXNAME<TAB>CLASS: a D4(b) cipher's canonical name, `other` (accepted,",
        "# outside D4: `openssl-algorithm-subset`), or `unknown`.",
    ]
    lines += ["%s\t%s" % (n.hex(), c) for n, c in rows]
    return "\n".join(lines) + "\n"


def main():
    names = spellings()
    text = render(classify(names))
    if sys.argv[1:] == ["--check"]:
        if open(OUT).read() != text:
            sys.exit("FAIL: m65_cipher_names.txt is stale: run oracle/gen_m65_cipher_names.py")
        print("m6.5 cipher names: current (%d spellings)" % len(names))
        return
    path = sys.argv[1] if sys.argv[1:] else OUT
    open(path, "w").write(text)
    counts = {}
    for line in text.splitlines():
        if not line.startswith("#"):
            c = line.split("\t")[1]
            counts[c] = counts.get(c, 0) + 1
    print("m6.5 cipher names: %d spellings, %s" % (len(names), sorted(counts.items())))


if __name__ == "__main__":
    main()
