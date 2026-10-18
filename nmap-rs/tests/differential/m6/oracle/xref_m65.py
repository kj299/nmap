#!/usr/bin/env python3
"""Cross-check the M6.5 golden against references that share no code with
OpenSSL (docs/M6.5-ANALYSIS.md §11 step a, "independent references"):

  - Python ints for the bignum rows: add, div, mod_exp, the bit functions,
    primality (Miller-Rabin, deterministic below 3.3e24) and every bignum's
    rendering (hex, decimal, MPI, bits, bytes);
  - CPython's own hash modules (`_md5`, `_sha1`, `_sha256` and `_sha512`, or
    `_sha2` from 3.12, `_sha3`, `_blake2`: not `hashlib`, which is OpenSSL,
    and HACL* from 3.12) for the digest, hash
    and HMAC rows (HMAC computed here, RFC 2104);
  - nettle (libnettle.so.8, through ctypes) for md4, ripemd160, sha512-224,
    sha512-256 and sm3;
  - nettle's DES, AES and CAST-128 block functions for every `encrypt`,
    `decrypt` and round-trip row on a D4(b) cipher (`m65_cipher_names.txt`,
    step d) that 7.94 answered, with ECB, CBC and PKCS#7 written here, and
    `DES_string_to_key` written here from its comment.

    python3 oracle/xref_m65.py      exit 1 on any disagreement

The golden is 7.94's answer and these are the references': a disagreement is
either a bug in the oracle or a behaviour the port must reproduce and the
ledger must name, never something to tune away. The behaviours the C has on
purpose (DIVERGENCES "Faithfully reproduced": `div` by 0 is (0, 0),
`mod_exp` ignores the signs of p and m, positions are int32) are written
here as the expectation, each where it applies. whirlpool has no reference
and is counted as unverified.
"""

import ctypes
import os
import random
import re
import sys

import _blake2
import _md5
import _sha1
import _sha3

try:  # CPython 3.12 merged _sha256 and _sha512 into _sha2 (HACL*)
    import _sha2 as _sha256
    import _sha2 as _sha512
except ImportError:
    import _sha256
    import _sha512

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
sys.path.insert(0, HERE)
from gen_m65_cases import lua_tostring as lstr  # noqa: E402  (the string luaL_checklstring sees)

# ---- references ------------------------------------------------------------------

try:
    NETTLE = ctypes.CDLL("libnettle.so.8")
except OSError:
    NETTLE = None


class Nettle:
    def __init__(self, name, size, block):
        self.name, self.digest_size, self.block_size = name, size, block
        self.data = b""

    def copy(self):
        c = Nettle(self.name, self.digest_size, self.block_size)
        c.data = self.data
        return c

    def update(self, b):
        self.data += b

    def digest(self):
        ctx = ctypes.create_string_buffer(1024)
        out = ctypes.create_string_buffer(self.digest_size)
        getattr(NETTLE, "nettle_%s_init" % self.name)(ctx)
        # sha512_224 and sha512_256 update through sha512's function (nettle's
        # headers #define them to it).
        update = "nettle_%s_update" % self.name
        if not hasattr(NETTLE, update):
            update = "nettle_%s_update" % self.name.split("_")[0]
        getattr(NETTLE, update)(ctx, ctypes.c_size_t(len(self.data)), self.data)
        getattr(NETTLE, "nettle_%s_digest" % self.name)(ctx, ctypes.c_size_t(self.digest_size), out)
        return out.raw


def nettle(name, size, block):
    if NETTLE is None or not hasattr(NETTLE, "nettle_%s_init" % name):
        return None
    return lambda: Nettle(name, size, block)


class Shake:
    def __init__(self, ctor, n, block):
        self.h, self.n, self.block_size, self.digest_size = ctor(), n, block, n

    def copy(self):
        c = Shake(lambda: None, self.n, self.block_size)
        c.h = self.h.copy()
        return c

    def update(self, b):
        self.h.update(b)

    def digest(self):
        return self.h.digest(self.n)


class Concat:  # md5-sha1
    block_size, digest_size = 64, 36

    def __init__(self):
        self.a, self.b = _md5.md5(), _sha1.sha1()

    def copy(self):
        c = Concat()
        c.a, c.b = self.a.copy(), self.b.copy()
        return c

    def update(self, d):
        self.a.update(d)
        self.b.update(d)

    def digest(self):
        return self.a.digest() + self.b.digest()


FAMILIES = {
    ("md4", "rsa-md4", "md4withrsaencryption"): nettle("md4", 16, 64),
    ("md5", "rsa-md5", "md5withrsaencryption", "ssl3-md5"): _md5.md5,
    ("ripemd160", "rsa-ripemd160", "ripemd", "rmd160", "ripemd160withrsa", "ripemd-160"): nettle("ripemd160", 20, 64),
    ("sha1", "rsa-sha1", "rsa-sha1-2", "sha1withrsaencryption", "ssl3-sha1", "sha-1"): _sha1.sha1,
    ("sha224", "rsa-sha224", "sha224withrsaencryption", "sha-224", "sha2-224"): _sha256.sha224,
    ("sha256", "rsa-sha256", "sha256withrsaencryption", "sha-256", "sha2-256"): _sha256.sha256,
    ("sha384", "rsa-sha384", "sha384withrsaencryption", "sha-384", "sha2-384"): _sha512.sha384,
    ("sha512", "rsa-sha512", "sha512withrsaencryption", "sha-512", "sha2-512"): _sha512.sha512,
    ("sha512-224", "rsa-sha512/224", "sha512-224withrsaencryption", "sha-512/224", "sha2-512/224"): nettle("sha512_224", 28, 128),
    ("sha512-256", "rsa-sha512/256", "sha512-256withrsaencryption", "sha-512/256", "sha2-512/256"): nettle("sha512_256", 32, 128),
    ("sha3-224", "rsa-sha3-224", "id-rsassa-pkcs1-v1_5-with-sha3-224"): _sha3.sha3_224,
    ("sha3-256", "rsa-sha3-256", "id-rsassa-pkcs1-v1_5-with-sha3-256"): _sha3.sha3_256,
    ("sha3-384", "rsa-sha3-384", "id-rsassa-pkcs1-v1_5-with-sha3-384"): _sha3.sha3_384,
    ("sha3-512", "rsa-sha3-512", "id-rsassa-pkcs1-v1_5-with-sha3-512"): _sha3.sha3_512,
    ("shake128", "shake-128"): lambda: Shake(_sha3.shake_128, 16, 168),
    ("shake256", "shake-256"): lambda: Shake(_sha3.shake_256, 32, 136),
    ("blake2b512", "blake2b-512"): _blake2.blake2b,
    ("blake2s256", "blake2s-256"): _blake2.blake2s,
    ("md5-sha1",): Concat,
    ("sm3", "rsa-sm3", "sm3withrsaencryption"): nettle("sm3", 32, 64),
}
DIGEST = {n: ctor for names, ctor in FAMILIES.items() for n in names}
UNVERIFIED = {"whirlpool"}


def hash_of(name, data):
    h = DIGEST[name]()
    h.update(data)
    return h.digest()


def hmac_of(name, key, msg):
    ctor = DIGEST[name]
    block = ctor().block_size
    if len(key) > block:
        key = hash_of(name, key)
    key = key.ljust(block, b"\0")
    inner = ctor()
    inner.update(bytes(k ^ 0x36 for k in key) + msg)
    outer = ctor()
    outer.update(bytes(k ^ 0x5C for k in key) + inner.digest())
    return outer.digest()


def is_probable_prime(n):
    if n < 2:
        return False
    small = (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41)
    for p in small:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d, s = d // 2, s + 1
    bases = small if n < 3317044064679887385961981 else \
        small + tuple(random.Random(n).randrange(2, n - 1) for _ in range(40))
    for a in bases:
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = x * x % n
            if x == n - 1:
                break
        else:
            return False
    return True


# ---- reading -----------------------------------------------------------------------

STR = r'"(?:[^"\\]|\\x[0-9a-f]{2})*"|#\d+:[0-9a-f]{16}'
BN = re.compile(r'bn<(-?[0-9A-F]+)\|(-?\d+)\|(' + STR + r')\|(\d+)\|(\d+)>')


def unstr(tok):
    if tok.startswith("#"):
        return None
    return re.sub(r"\\x([0-9a-f]{2})", lambda m: chr(int(m.group(1), 16)),
                  tok[1:-1]).encode("latin-1")


def arg(tok):
    tag, body = tok.split(":", 1)
    if tag == "s":
        return bytes.fromhex(body)
    if tag == "i":
        return int(body)
    if tag == "bnd":
        t = bytes.fromhex(body).decode()
        return int(t) if re.fullmatch(r"-?\d+", t) else None
    if tag == "bnh":
        t = bytes.fromhex(body).decode()
        return int(t, 16) if re.fullmatch(r"-?[0-9a-fA-F]+", t) else None
    if tag == "bnb":
        return int.from_bytes(bytes.fromhex(body), "big")
    return None


def mpi(v):
    mag = abs(v)
    if mag == 0:
        return b"\0\0\0\0"
    b = mag.to_bytes((mag.bit_length() + 7) // 8, "big")
    if b[0] & 0x80:
        b = b"\0" + b
    if v < 0:
        b = bytes([b[0] | 0x80]) + b[1:]
    return len(b).to_bytes(4, "big") + b


def int32(tok):
    """A position argument as `luaL_checkinteger` and the C's `int` take it,
    or None where it raises."""
    tag, body = tok.split(":", 1) if ":" in tok else (tok, "")
    if tag == "i":
        p = int(body)
    elif tag == "f" and float(body).is_integer():
        p = int(float(body))
    elif tag == "s" and re.fullmatch(rb"\s*-?\d+\s*", bytes.fromhex(body)):
        p = int(bytes.fromhex(body))
    else:
        return None
    p &= 0xFFFFFFFF
    return p - (1 << 32) if p >= 1 << 31 else p


# ---- the D4 ciphers (step d) --------------------------------------------------------------

D4_CIPHERS = {  # canonical name -> (nettle family, key length, block, CBC)
    "des-ecb": ("des", 8, 8, False), "des-cbc": ("des", 8, 8, True),
    "aes-128-ecb": ("aes128", 16, 16, False), "aes-128-cbc": ("aes128", 16, 16, True),
    "aes-192-ecb": ("aes192", 24, 16, False), "aes-192-cbc": ("aes192", 24, 16, True),
    "aes-256-ecb": ("aes256", 32, 16, False), "aes-256-cbc": ("aes256", 32, 16, True),
    "cast5-ecb": ("cast128", 16, 8, False), "cast5-cbc": ("cast128", 16, 8, True),
}


def cipher_classes():
    out = {}
    for line in open(os.path.join(M6, "m65_cipher_names.txt")):
        if not line.startswith("#"):
            h, c = line.rstrip("\n").split("\t")
            out[bytes.fromhex(h)] = c
    return out


def nettle_blocks(family, key, encrypt):
    """A function running nettle's block cipher over whole blocks."""
    ctx = ctypes.create_string_buffer(8192)
    if family == "des":
        NETTLE.nettle_des_set_key(ctx, key)  # nettle ignores the parity bits too
        fn = NETTLE.nettle_des_encrypt if encrypt else NETTLE.nettle_des_decrypt
    elif family == "cast128":
        # CAST_set_key: the first 16 bytes, a shorter key zero-padded, 12 rounds
        # up to 10 bytes; nettle's cast5_set_key takes 5 to 16 with the same rules.
        k = key[:16].ljust(5, b"\0")
        NETTLE.nettle_cast5_set_key(ctx, ctypes.c_size_t(len(k)), k)
        fn = NETTLE.nettle_cast128_encrypt if encrypt else NETTLE.nettle_cast128_decrypt
    else:
        getattr(NETTLE, "nettle_%s_set_%s_key" % (family, "encrypt" if encrypt else "decrypt"))(ctx, key)
        fn = getattr(NETTLE, "nettle_%s_%s" % (family, "encrypt" if encrypt else "decrypt"))

    def run(data):
        out = ctypes.create_string_buffer(len(data))
        fn(ctx, ctypes.c_size_t(len(data)), out, data)
        return out.raw
    return run


def cipher_ref(canon, encrypt, key, iv, data, padding):
    """What EVP gives for a D4 cipher: the output, or None where it errors."""
    family, klen, bs, cbc = D4_CIPHERS[canon]
    if family != "cast128" and len(key) != klen:
        return None
    if iv is not None and len(iv) != (bs if cbc else 0):
        return None
    if len(data) % bs and not (encrypt and padding) or not encrypt and padding and not data:
        return None
    if encrypt and padding:
        n = bs - len(data) % bs
        data = data + bytes([n]) * n
    blk = nettle_blocks(family, key, encrypt)
    chain, out = (iv or bytes(bs)) if cbc else None, b""
    for i in range(0, len(data), bs):
        b = data[i:i + bs]
        if not cbc:
            out += blk(b)
        elif encrypt:
            chain = blk(bytes(x ^ y for x, y in zip(b, chain)))
            out += chain
        else:
            out += bytes(x ^ y for x, y in zip(blk(b), chain))
            chain = b
    if not encrypt and padding:
        n = out[-1]
        if n == 0 or n > bs or out[-n:] != bytes([n]) * n:
            return None
        out = out[:-n]
    return out


def des_string_to_key(d):
    """`l_DES_string_to_key`, from its comment: seven bits of each byte, the
    low bit of every key byte clear (the C's data[7] is the string's NUL)."""
    d = d + b"\0"
    key = [d[0] & 0xFE]
    for i in range(1, 8):
        key.append(((d[i - 1] << (8 - i)) | (d[i] >> i)) & 0xFE)
    return bytes(key)


def check_ciphers(cases, golden, ok):
    """Step d's rows on D4 ciphers, against nettle."""
    classes = cipher_classes()
    for cid, (st, vals) in golden.items():
        tags, op, sub, args = cases[cid]
        if st != "ok" or tags[0] != "d" or any(t.startswith(("nondet:", "ivnul", "ub:")) for t in tags):
            continue
        if op == "call" and sub == "DES_string_to_key":
            ok("des2key", unstr(vals) == des_string_to_key(lstr(args[0])), cid)
            continue
        if op == "call" and sub in ("encrypt", "decrypt"):
            name, rest, kinds = lstr(args[0]), args[1:], [sub == "encrypt"]
        elif op == "rt":
            name, rest, kinds = sub.encode(), args, [True, False]
        else:
            continue
        canon = classes.get(name)
        if canon not in D4_CIPHERS or len(rest) < 3:
            continue
        key, data = lstr(rest[0]), lstr(rest[2])
        iv = lstr(rest[1]) if rest[1] != "nil" else None
        iv = iv or None  # an empty IV is none
        pad = len(rest) > 3 and rest[3] not in ("nil", "F")
        if key is None or data is None:
            continue
        ct = cipher_ref(canon, kinds[0], key, iv, data, pad)
        if op == "call":
            ok("cipher", ct is not None and unstr(vals) == ct, cid, canon)
        else:
            # OPS.rt: the ciphertext, then whether decrypting it gives the data
            # back, or "dec-err" and the error.
            toks = re.findall(STR + r"|\S+", vals)
            back = cipher_ref(canon, False, key, iv, ct, pad) if ct is not None else None
            second = '"dec-err"' if back is None else str(back == data).lower()
            ok("cipher-rt", ct is not None and len(toks) > 1 and unstr(toks[0]) == ct
               and toks[1] == second, cid, canon)


# ---- the checks -----------------------------------------------------------------------


def main():
    if NETTLE is None:
        sys.exit("libnettle.so.8 not found: md4, ripemd160, sha512-224/256 and sm3 have no "
                 "other reference here (install nettle)")
    cases = {}
    for line in open(os.path.join(M6, "m65_cases.txt")):
        if not line.startswith("#"):
            f = line.rstrip("\n").split("\t")
            cases[f[0]] = (f[1].split(","), f[2], f[3], f[4:])
    golden = {}
    for line in open(os.path.join(M6, "m65_golden.txt")):
        if not line.startswith("#"):
            f = line.rstrip("\n").split("\t")
            golden[f[0]] = (f[1], f[2])
    counts, bad, unverified = {}, [], set()

    def ok(kind, cond, cid, why=""):
        counts[kind] = counts.get(kind, 0) + 1
        if not cond:
            bad.append("%s %s %s" % (kind, cid, why))

    for cid, (st, vals) in golden.items():
        tags, op, sub, args = cases[cid]
        if st == "ub" or any(t.startswith("nondet:") for t in tags):
            continue
        # Every bignum rendered anywhere: its five renderings agree.
        for h, d, m, bits, nbytes in BN.findall(vals):
            v = int(h, 16)
            mb = unstr(m)
            ok("bn-render", str(v) == d and int(bits) == abs(v).bit_length()
               and int(nbytes) == (abs(v).bit_length() + 7) // 8
               and (mb is None or mb == mpi(v)) and h == h.upper()
               and (v == 0 or len(h.lstrip("-")) % 2 == 0), cid, vals[:80])
        if op != "call" and op != "mut":
            continue
        bns = [int(x[0], 16) for x in BN.findall(vals)]
        if sub in ("digest", "md4", "md5", "sha1", "ripemd160", "hmac") and st == "ok":
            if sub == "digest":
                name, data = lstr(args[0]).decode("latin-1").lower(), lstr(args[1])
            elif sub == "hmac":
                name, data = lstr(args[0]).decode("latin-1").lower(), None
            else:
                name, data = sub, lstr(args[0])
            name = name.split("\0")[0]  # luaL_checkstring: the C stops at a NUL
            if name in UNVERIFIED or name not in DIGEST or DIGEST[name] is None:
                unverified.add(name)
                continue
            got = unstr(vals)
            if sub == "hmac":
                if name.startswith("shake"):
                    ok("hmac", got == b"", cid, "an XOF: HMAC fails and the C pushes \"\"")
                else:
                    ok("hmac", got == hmac_of(name, lstr(args[1]), lstr(args[2])), cid, name)
            else:
                ok("digest", got == hash_of(name, data), cid, name)
        elif sub == "bignum_add" and st == "ok":
            a, b = arg(args[0]), arg(args[1])
            if a is not None and b is not None:
                ok("add", bns == [a + b], cid)
        elif sub == "bignum_div" and st == "ok":
            a, b = arg(args[0]), arg(args[1])
            if a is not None and b is not None:
                if b == 0:
                    want = [0, 0]  # BN_div fails; both results stay BN_new's 0
                else:
                    q = abs(a) // abs(b) * (1 if (a < 0) == (b < 0) else -1)
                    want = [q, a - q * b]  # truncation; the remainder takes a's sign
                ok("div", bns == want, cid, "%s / %s" % (a, b))
        elif sub == "bignum_mod_exp" and st == "ok":
            a, p, m = (arg(x) for x in args)
            if None not in (a, p, m):
                want = 0 if m == 0 else pow(a, abs(p), abs(m))
                ok("mod_exp", bns == [want], cid, "%s^%s mod %s" % (a, p, m))
        elif sub in ("bignum_set_bit", "bignum_clear_bit") and st == "ok" and op == "call":
            ok("bits", vals == "", cid, "the C returns nothing")
        elif sub in ("bignum_set_bit", "bignum_clear_bit") and st == "ok":
            v, pos = arg(args[0]), int32(args[1])
            if v is not None and pos is not None:
                mag = abs(v)
                if pos >= 0:
                    mag = mag | (1 << pos) if sub == "bignum_set_bit" else mag & ~(1 << pos)
                want = -mag if v < 0 and mag else mag
                ok("bits", bns == [want], cid, "%s %s %s" % (sub, v, pos))
        elif sub == "bignum_is_bit_set" and st == "ok":
            v, pos = arg(args[0]), int32(args[1])
            if v is not None and pos is not None:
                want = pos >= 0 and bool(abs(v) >> pos & 1)
                ok("bits", vals == str(want).lower(), cid)
        elif sub in ("bignum_is_prime", "bignum_is_safe_prime") and st == "ok":
            v = arg(args[0])
            if v is not None:
                pr = is_probable_prime(v)
                if sub == "bignum_is_prime":
                    want = str(pr).lower()
                else:
                    safe = pr and is_probable_prime((v - 1) // 2)
                    want = "%s %s" % (str(safe).lower(), str(pr).lower())
                ok("prime", vals == want, cid, "%s" % v)

    check_ciphers(cases, golden, ok)
    for k in sorted(counts):
        print("%-10s %6d rows agree" % (k, counts[k]))
    print("unverified digest names: %s" % ", ".join(sorted(unverified)))
    if not unverified <= UNVERIFIED | {"sm3", "rsa-sm3", "sm3withrsaencryption"}:
        bad.append("names with no reference: %s" % sorted(unverified - UNVERIFIED))
    for want in ("bn-render", "digest", "hmac", "add", "div", "mod_exp", "bits", "prime",
                 "cipher", "cipher-rt", "des2key"):
        if not counts.get(want):
            bad.append("no %s row was checked" % want)
    for b in bad[:30]:
        print("DISAGREE", b)
    if bad:
        sys.exit("%d disagreements with the independent references" % len(bad))


if __name__ == "__main__":
    main()
