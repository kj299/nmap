#!/usr/bin/env python3
"""M6.5 step e: the generated certificate families (`k` rows of m65_certs.txt).

    python3 -I -B oracle/gen_m65_x509.py              rewrite the k rows of m65_certs.txt
    python3 -I -B oracle/gen_m65_x509.py --check      FAIL unless they are what this writes
    python3 -I -B oracle/gen_m65_x509.py --check-golden
                                                      FAIL unless nmap 7.94's golden says on
                                                      every k row what the row expects

Phase 0's corpus (the x rows) and the spike's BER rows (b) cover the reader's
framing; these rows cover what decides the rest of what parse_ssl_certificate
returns, each certificate built here byte by byte, deterministically (no
randomness, no signing: nothing verifies a signature):

  - the public key: every SPKI OID OpenSSL's name map gives a decoder (rsa
    under both its OIDs, RSA-PSS with and without parameters, DSA under five
    OIDs, DH, DHX, EC, SM2, the four ECX types), each with the parameter and
    key shapes the C accepts and refuses; every built-in curve's generator,
    uncompressed and compressed; hybrid, infinity, off-curve and out-of-field
    points; explicit EC parameters that match a built-in curve and that do
    not, over prime and binary fields, and each of their checks;
  - Name values: the string types canonicalisation refuses (a BMP
    surrogate, a UniversalString past U+10FFFF, malformed UTF-8) and the
    non-string types B_ASN1_PRINTABLE admits (BIT STRING, SEQUENCE, the
    "unknown" tags), unknown attribute OIDs, and OIDs too long to render;
  - extension framing: names of 255, 256 and 300 characters, an OID too long
    to render, the critical octet's values, an empty extensions SEQUENCE.

The note column ends with what the row should do, which is the ground truth
--check-golden holds the golden to: `expect=reject` (parse returns nil), `expect=raise` (an error),
`expect=nokey` (nil and "Error parsing cert"), or `expect=TYPE/BITS` with
`/CURVE` for EC, or `expect=ok` where only acceptance is claimed.
"""

import os
import re
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
CERTS = os.path.join(M6, "m65_certs.txt")
GOLDEN = os.path.join(M6, "m65_golden.txt")
CASES = os.path.join(M6, "m65_cases.txt")
DATA = os.path.abspath(os.path.join(M6, "..", "..", "..", "crates", "vendor", "openssl-data"))
sys.path.insert(0, DATA)
import gen as openssl_data  # noqa: E402  (crates/vendor/openssl-data/gen.py)

# ---- DER -------------------------------------------------------------------------


def length(n):
    if n < 0x80:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def tlv(tag, content):
    return bytes([tag]) + length(len(content)) + content


def seq(*items):
    return tlv(0x30, b"".join(items))


def set_(*items):
    return tlv(0x31, b"".join(items))


def explicit(n, inner):
    return tlv(0xA0 | n, inner)


def oid_content(dotted):
    arcs = [int(a) for a in dotted.split(".")]
    out = bytearray()
    for v in [arcs[0] * 40 + arcs[1]] + arcs[2:]:
        r = [v & 0x7F]
        v >>= 7
        while v:
            r.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(r))
    return bytes(out)


def oid(dotted):
    return tlv(0x06, oid_content(dotted))


def integer(n):
    if n == 0:
        return tlv(0x02, b"\x00")
    if n > 0:
        b = n.to_bytes((n.bit_length() + 8) // 8, "big")
    else:
        b = n.to_bytes(((-n - 1).bit_length() + 8) // 8, "big", signed=True)
    return tlv(0x02, b)


def raw_int(content):
    return tlv(0x02, content)


def octet(b):
    return tlv(0x04, b)


def bits(b, unused=0):
    return tlv(0x03, bytes([unused]) + b)


NULL = b"\x05\x00"


def utf8(s):
    return tlv(0x0C, s.encode() if isinstance(s, str) else s)


def utctime(s):
    return tlv(0x17, s.encode())


def algid(dotted, param=None):
    return seq(oid(dotted), param) if param is not None else seq(oid(dotted))


def name(*rdns):
    """rdns: (oid, value DER) pairs, each its own RDN."""
    return seq(*[set_(seq(oid(o) if isinstance(o, str) else tlv(0x06, o), v)) for o, v in rdns])


CN = "2.5.4.3"
SHA256_RSA = "1.2.840.113549.1.1.11"
RSA = "1.2.840.113549.1.1.1"
SIGNATURE = bits(b"\x5a" * 32)

# A fixed 2048-bit RSA modulus (odd, top bit set): nothing checks it factors.
N2048 = int("c3d54dd34a0733ec11f0af1ca7e7a60db0036be4a4410db9263748b7cfecf17d"
            "6df10e7cfcc7c6067dd5520d6764adcc654ee2d5dae1dcbe9595c69b7ecfe2c1"
            "5d6884ddb0d2a93b6d203f6ca38fbd80de59b32592491e2aabf6d58291d8bc07"
            "40581012c00968efa394dc0c377faa2b57791fa4d5e6834869ab269bbd491cb1"
            "80dd7bda1e004a95331966e2d3b01e6aab031b86b23789a2ac7b129e106f9c7e"
            "a7f9c69e82cea2635fc4821ee92ab989eb504ce8259650ebab7e44a61f1c6709"
            "ac91d9b585c8cc068eeed2f328918326462023260781d782d5d816c6b24f6792"
            "ca3f7e61194ccc7f84ddb2597b683bfb967f7efea9091fdfabf53948a3ba3f49", 16)
RSA_KEY = seq(integer(N2048), integer(65537))
# A 1024-bit DSA/DH prime-sized number, a 160-bit q, g = 2.
P1024 = (1 << 1023) | 0x1F3
Q160 = (1 << 159) | 0x75
SPKI_RSA = seq(algid(RSA, NULL), bits(RSA_KEY))


def cert(spki=SPKI_RSA, subject=None, exts=None, issuer=None):
    subject = subject if subject is not None else name((CN, utf8("m65k")))
    issuer = issuer if issuer is not None else name((CN, utf8("m65k")))
    fields = [explicit(0, integer(2)), integer(1), algid(SHA256_RSA, NULL), issuer,
              seq(utctime("200101000000Z"), utctime("300101000000Z")), subject, spki]
    if exts is not None:
        fields.append(explicit(3, seq(*exts)))
    return seq(seq(*fields), algid(SHA256_RSA, NULL), SIGNATURE)


def spki(alg, key_bytes, unused=0):
    return seq(alg, bits(key_bytes, unused))


# ---- EC arithmetic over the built-in curves, for points to put in keys --------------


def gf2_mul(a, b, poly):
    m = poly.bit_length() - 1
    r = 0
    while b:
        if b & 1:
            r ^= a
        b >>= 1
        a <<= 1
        if a >> m & 1:
            a ^= poly
    return r


def gf2_inv(a, poly):
    m = poly.bit_length() - 1
    r, base, e = 1, a, (1 << m) - 2
    while e:
        if e & 1:
            r = gf2_mul(r, base, poly)
        base = gf2_mul(base, base, poly)
        e >>= 1
    return r


def curve_points(c):
    """The generator's encodings: uncompressed, compressed, hybrid, and a few
    invalid ones, sized as OpenSSL's oct2point wants them."""
    nid, char2, seed, p, a, b, x, y, order, cof = c
    pi, xi, yi = (int.from_bytes(v, "big") for v in (p, x, y))
    flen = ((pi.bit_length() - 1 + 7) // 8) if char2 else ((pi.bit_length() + 7) // 8)
    X, Y = xi.to_bytes(flen, "big"), yi.to_bytes(flen, "big")
    if char2:
        ybit = gf2_mul(yi, gf2_inv(xi, pi), pi) & 1 if xi else 0
    else:
        ybit = yi & 1
    return {
        "uncompressed": b"\x04" + X + Y,
        "compressed": bytes([2 | ybit]) + X,
        "hybrid": bytes([6 | ybit]) + X + Y,
        "hybrid-wrong-bit": bytes([6 | (ybit ^ 1)]) + X + Y,
        "compressed-wrong-bit": bytes([2 | (ybit ^ 1)]) + X,
        "off-curve": b"\x04" + X + (yi ^ 1).to_bytes(flen, "big"),
        "infinity": b"\x00",
        "short": b"\x04" + X + Y[:-1],
        "form-5": b"\x05" + X + Y,
        "uncompressed-ybit": b"\x05" + X + Y,
    }


# ---- the families ---------------------------------------------------------------------


def rows():
    out = []

    def add(family, note, der):
        out.append((family, note, der))

    # RSA, under rsaEncryption and the X.500 OID 2.5.8.1.1.
    add("k-rsa", "null-param expect=rsa/2048", cert())
    add("k-rsa", "no-param expect=rsa/2048", cert(spki(algid(RSA), RSA_KEY)))
    add("k-rsa", "int-param expect=rsa/2048", cert(spki(algid(RSA, integer(5)), RSA_KEY)))
    add("k-rsa", "x500-oid expect=rsa/2048", cert(spki(algid("2.5.8.1.1", NULL), RSA_KEY)))
    add("k-rsa", "n-padded expect=rsa/2048",
        cert(spki(algid(RSA, NULL), seq(raw_int(b"\x00\x00" + N2048.to_bytes(256, "big")), integer(65537)))))
    add("k-rsa", "n-negative expect=rsa/2048",
        cert(spki(algid(RSA, NULL), seq(raw_int(N2048.to_bytes(256, "big")), integer(65537)))))
    add("k-rsa", "n-empty expect=rsa/0", cert(spki(algid(RSA, NULL), seq(raw_int(b""), integer(65537)))))
    add("k-rsa", "e-empty expect=rsa/2048", cert(spki(algid(RSA, NULL), seq(integer(N2048), raw_int(b"")))))
    add("k-rsa", "trailing-after-key expect=rsa/2048", cert(spki(algid(RSA, NULL), RSA_KEY + b"\x00\x01")))
    add("k-rsa", "third-integer expect=nokey",
        cert(spki(algid(RSA, NULL), seq(integer(N2048), integer(65537), integer(3)))))
    add("k-rsa", "one-integer expect=nokey", cert(spki(algid(RSA, NULL), seq(integer(N2048)))))
    add("k-rsa", "not-a-sequence expect=nokey", cert(spki(algid(RSA, NULL), integer(N2048))))
    add("k-rsa", "unused-bits expect=rsa/2048", cert(spki(algid(RSA, NULL), RSA_KEY, unused=3)))
    add("k-rsa", "indefinite-key expect=rsa/2048",
        cert(spki(algid(RSA, NULL), b"\x30\x80" + integer(N2048) + integer(65537) + b"\x00\x00")))
    add("k-rsa", "constructed-integer expect=nokey",
        cert(spki(algid(RSA, NULL), seq(b"\x22" + length(4) + raw_int(b"\x01\x02"), integer(65537)))))
    add("k-rsa", "small expect=rsa/9", cert(spki(algid(RSA, NULL), seq(integer(257), integer(3)))))

    # RSA-PSS.
    PSS = "1.2.840.113549.1.1.10"
    SHA256 = "2.16.840.1.101.3.4.2.1"
    MGF1 = "1.2.840.113549.1.1.8"
    full = seq(explicit(0, algid(SHA256, NULL)), explicit(1, algid(MGF1, algid(SHA256, NULL))),
               explicit(2, integer(32)), explicit(3, integer(1)))
    for note, param in [
        ("no-param expect=unknown/2048", None),
        ("empty-seq expect=unknown/2048", seq()),
        ("full expect=unknown/2048", full),
        ("hash-only expect=unknown/2048", seq(explicit(0, algid(SHA256)))),
        ("salt-huge expect=unknown/2048", seq(explicit(2, integer(1 << 80)))),
        ("trailer-2 expect=unknown/2048", seq(explicit(3, integer(2)))),
        ("hash-sha3 expect=unknown/2048", seq(explicit(0, algid("2.16.840.1.101.3.4.2.8")))),
        ("hash-unknown expect=nokey", seq(explicit(0, algid("1.2.3.4")))),
        ("hash-is-rsa expect=nokey", seq(explicit(0, algid(RSA)))),
        ("mgf-not-mgf1 expect=nokey", seq(explicit(1, algid(SHA256, algid(SHA256))))),
        ("mgf1-null-param expect=nokey", seq(explicit(1, algid(MGF1, NULL)))),
        ("mgf1-no-param expect=nokey", seq(explicit(1, algid(MGF1)))),
        ("mgf1-hash-unknown expect=nokey", seq(explicit(1, algid(MGF1, algid("1.2.3.4"))))),
        ("null-param expect=nokey", NULL),
        ("int-param expect=nokey", integer(1)),
        ("bad-field-order expect=nokey", seq(explicit(1, algid(MGF1, algid(SHA256))), explicit(0, algid(SHA256)))),
    ]:
        alg = algid(PSS, param) if param is not None else algid(PSS)
        add("k-pss", note, cert(spki(alg, RSA_KEY)))

    # DSA.
    DSA = "1.2.840.10040.4.1"
    dsa_params = seq(integer(P1024), integer(Q160), integer(2))
    y = integer(P1024 - 5)
    for note, alg, key in [
        ("params expect=dsa/1024", algid(DSA, dsa_params), y),
        ("null-params expect=nokey", algid(DSA, NULL), y),
        ("no-params expect=nokey", algid(DSA), y),
        ("octet-params expect=nokey", algid(DSA, octet(b"\x01")), y),
        ("params-two-ints expect=nokey", algid(DSA, seq(integer(P1024), integer(Q160))), y),
        ("params-padded expect=dsa/1024", algid(DSA, seq(raw_int(b"\x00\x00" + P1024.to_bytes(128, "big")), integer(Q160), integer(2))), y),
        ("key-negative expect=dsa/1024", algid(DSA, dsa_params), integer(-7)),
        ("key-padded expect=nokey", algid(DSA, dsa_params), raw_int(b"\x00\x01")),
        ("key-empty expect=nokey", algid(DSA, dsa_params), raw_int(b"")),
        ("key-octet expect=nokey", algid(DSA, dsa_params), octet(b"\x01")),
        ("key-trailing expect=dsa/1024", algid(DSA, dsa_params), y + b"\x00"),
        ("oid-dsaWithSHA1 expect=dsa/1024", algid("1.2.840.10040.4.3", dsa_params), y),
        ("oid-dsaEncryption-old expect=dsa/1024", algid("1.3.14.3.2.12", dsa_params), y),
        ("oid-dsaWithSHA expect=dsa/1024", algid("1.3.14.3.2.13", dsa_params), y),
        ("oid-dsaWithSHA1-old expect=dsa/1024", algid("1.3.14.3.2.27", dsa_params), y),
        ("oid-dsa-with-sha256 expect=nokey", algid("2.16.840.1.101.3.4.3.2", dsa_params), y),
    ]:
        add("k-dsa", note, cert(spki(alg, key)))

    # DH (PKCS#3) and DHX (X9.42).
    DH, DHX = "1.2.840.113549.1.3.1", "1.2.840.10046.2.1"
    for note, alg, key in [
        ("pg expect=dh/1024", algid(DH, seq(integer(P1024), integer(2))), y),
        ("pg-length expect=dh/1024", algid(DH, seq(integer(P1024), integer(2), integer(160))), y),
        ("pg-length-neg expect=dh/1024", algid(DH, seq(integer(P1024), integer(2), integer(-1))), y),
        ("pg-length-empty expect=dh/1024", algid(DH, seq(integer(P1024), integer(2), raw_int(b""))), y),
        ("pg-length-huge expect=nokey", algid(DH, seq(integer(P1024), integer(2), integer(1 << 31))), y),
        ("pg-length-min expect=dh/1024", algid(DH, seq(integer(P1024), integer(2), integer(-(1 << 31)))), y),
        ("pg-length-padded-neg expect=nokey", algid(DH, seq(integer(P1024), integer(2), raw_int(b"\xff\x80\x00\x00\x00"))), y),
        ("p-only expect=nokey", algid(DH, seq(integer(P1024))), y),
        ("no-params expect=nokey", algid(DH), y),
        ("null-params expect=nokey", algid(DH, NULL), y),
        ("key-negative expect=dh/1024", algid(DH, seq(integer(P1024), integer(2))), integer(-3)),
        ("dhx-pgq expect=unknown/1024", algid(DHX, seq(integer(P1024), integer(2), integer(Q160))), y),
        ("dhx-pgqj expect=unknown/1024", algid(DHX, seq(integer(P1024), integer(2), integer(Q160), integer(7))), y),
        ("dhx-vparams expect=unknown/1024",
         algid(DHX, seq(integer(P1024), integer(2), integer(Q160), seq(bits(b"\x01" * 20), integer(5)))), y),
        ("dhx-pg expect=nokey", algid(DHX, seq(integer(P1024), integer(2))), y),
        ("dhx-no-params expect=nokey", algid(DHX), y),
    ]:
        add("k-dh", note, cert(spki(alg, key)))

    # ECX.
    for kind, dotted, klen, nbits in [("x25519", "1.3.101.110", 32, 253), ("x448", "1.3.101.111", 56, 448),
                                      ("ed25519", "1.3.101.112", 32, 256), ("ed448", "1.3.101.113", 57, 456)]:
        add("k-ecx", "%s expect=unknown/%d" % (kind, nbits), cert(spki(algid(dotted), b"\x09" * klen)))
        add("k-ecx", "%s-short expect=nokey" % kind, cert(spki(algid(dotted), b"\x09" * (klen - 1))))
        add("k-ecx", "%s-long expect=nokey" % kind, cert(spki(algid(dotted), b"\x09" * (klen + 1))))
        add("k-ecx", "%s-null-param expect=nokey" % kind, cert(spki(algid(dotted, NULL), b"\x09" * klen)))

    # EC over every built-in curve.
    EC = "1.2.840.10045.2.1"
    curves, names = openssl_data.curves()
    cnames = {n: nm for nm, n in reversed(names)}
    table = openssl_data.objects()
    for c in curves:
        nid = c[0]
        arcs = table[nid][2]
        nm = cnames[nid]
        order_bits = int.from_bytes(c[8], "big").bit_length()
        pts = curve_points(c)
        if not arcs:
            continue
        param = oid(".".join(map(str, arcs)))
        ok = "expect=%s/%d/%s" % ("unknown" if nm == "SM2" else "ec", order_bits, nm)
        add("k-ec", "%s uncompressed %s" % (nm, ok), cert(spki(algid(EC, param), pts["uncompressed"])))
        add("k-ec", "%s compressed %s" % (nm, ok), cert(spki(algid(EC, param), pts["compressed"])))
    p256 = next(c for c in curves if c[0] == 415)
    k283 = next(c for c in curves if c[0] == 729)
    for c, nm in [(p256, "prime256v1"), (k283, "sect283k1")]:
        pts = curve_points(c)
        param = oid(".".join(map(str, table[c[0]][2])))
        bits_ = int.from_bytes(c[8], "big").bit_length()
        for form, expect in [("hybrid", "ec/%d/%s" % (bits_, nm)), ("hybrid-wrong-bit", "nokey"),
                             ("compressed-wrong-bit", "ec/%d/%s" % (bits_, nm)), ("off-curve", "nokey"),
                             ("infinity", "ec/%d/%s" % (bits_, nm)), ("short", "nokey"), ("form-5", "nokey")]:
            add("k-ec", "%s %s expect=%s" % (nm, form, expect), cert(spki(algid(EC, param), pts[form])))
    p256pts = curve_points(p256)
    p256oid = oid("1.2.840.10045.3.1.7")
    pfield = int.from_bytes(p256[3], "big")
    add("k-ec", "x-equals-p expect=nokey",
        cert(spki(algid(EC, p256oid), b"\x04" + p256[3] + p256[7])))
    add("k-ec", "empty-key expect=nokey", cert(spki(algid(EC, p256oid), b"")))
    add("k-ec", "unknown-curve-oid expect=nokey", cert(spki(algid(EC, oid("1.2.3.4")), p256pts["uncompressed"])))
    add("k-ec", "curve-oid-not-a-curve expect=nokey", cert(spki(algid(EC, oid(RSA)), p256pts["uncompressed"])))
    add("k-ec", "null-param expect=nokey", cert(spki(algid(EC, NULL), p256pts["uncompressed"])))
    add("k-ec", "no-param expect=nokey", cert(spki(algid(EC), p256pts["uncompressed"])))
    add("k-ec", "int-param expect=nokey", cert(spki(algid(EC, integer(1)), p256pts["uncompressed"])))
    del pfield
    # SM2: its curve under id-ecPublicKey and under the SM2 OID.
    sm2 = next(c for c in curves if c[0] == 1172)
    sm2pts = curve_points(sm2)
    sm2oid = oid("1.2.156.10197.1.301")
    add("k-sm2", "sm2-oid sm2-curve expect=unknown/256", cert(spki(algid("1.2.156.10197.1.301", sm2oid), sm2pts["uncompressed"])))
    add("k-sm2", "sm2-oid p256 expect=nokey", cert(spki(algid("1.2.156.10197.1.301", p256oid), p256pts["uncompressed"])))

    # Explicit EC parameters.
    def ecparams(c, *, version=1, seed=True, cofactor=True, base="uncompressed", b_delta=0,
                 field=None, order=None, cof_value=None, basis=None, seed_bytes=None):
        nid, char2, cseed, p, a, b, x, y, order_b, cof = c
        pts = curve_points(c)
        bb = (int.from_bytes(b, "big") ^ b_delta).to_bytes(len(b), "big")
        if field is not None:
            fid = field
        elif char2:
            poly = int.from_bytes(p, "big")
            m = poly.bit_length() - 1
            ks = [i for i in range(1, m) if poly >> i & 1]
            if basis is not None:
                fid = seq(oid("1.2.840.10045.1.2"), basis(m, ks))
            elif len(ks) == 1:
                fid = seq(oid("1.2.840.10045.1.2"), seq(integer(m), oid("1.2.840.10045.1.2.3.2"), integer(ks[0])))
            else:
                fid = seq(oid("1.2.840.10045.1.2"),
                          seq(integer(m), oid("1.2.840.10045.1.2.3.3"), seq(*[integer(k) for k in ks])))
        else:
            fid = seq(oid("1.2.840.10045.1.1"), integer(int.from_bytes(p, "big")))
        curve_fields = [octet(a), octet(bb)]
        if seed and cseed:
            curve_fields.append(bits(seed_bytes if seed_bytes is not None else cseed))
        elif seed_bytes is not None:
            curve_fields.append(bits(seed_bytes))
        fields = [integer(version), fid, seq(*curve_fields), octet(pts[base] if isinstance(base, str) else base),
                  integer(order if order is not None else int.from_bytes(order_b, "big"))]
        if cofactor:
            fields.append(integer(cof_value if cof_value is not None else cof))
        return seq(*fields)

    def ec_explicit(note, params, key, expect):
        add("k-ec-explicit", "%s expect=%s" % (note, expect), cert(spki(algid(EC, params), key)))

    p256n = "ec/256/prime256v1"
    k283n = "ec/281/sect283k1"
    k163 = next(c for c in curves if c[0] == 721)  # sect163k1
    k163n = "ec/163/sect163k1"
    k163pts = curve_points(k163)
    ec_explicit("p256", ecparams(p256), p256pts["uncompressed"], p256n)
    ec_explicit("p256-no-seed", ecparams(p256, seed=False), p256pts["uncompressed"], p256n)
    ec_explicit("p256-no-cofactor", ecparams(p256, cofactor=False), p256pts["uncompressed"], p256n)
    ec_explicit("p256-cofactor-2", ecparams(p256, cof_value=2), p256pts["uncompressed"], p256n)
    ec_explicit("p256-cofactor-0", ecparams(p256, cof_value=0), p256pts["uncompressed"], p256n)
    ec_explicit("p256-cofactor-neg", ecparams(p256, cof_value=-1), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-compressed-base", ecparams(p256, base="compressed"), p256pts["uncompressed"], p256n)
    ec_explicit("p256-other-seed", ecparams(p256, seed_bytes=b"\x01" * 20), p256pts["uncompressed"], p256n)
    ec_explicit("p256-empty-seed", ecparams(p256, seed_bytes=b""), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-version-3", ecparams(p256, version=3), p256pts["uncompressed"], p256n)
    ec_explicit("p256-version-huge", ecparams(p256, version=1 << 40), p256pts["uncompressed"], "nokey")
    n256 = int.from_bytes(p256[8], "big")
    ec_explicit("p256-order-changed", ecparams(p256, order=n256 - 2), p256pts["uncompressed"], "ec/256/explicit_prime")
    ec_explicit("p256-order-changed-infinity-key", ecparams(p256, order=n256 - 2), b"\x00", "ec/256/explicit_prime")
    ec_explicit("p256-b-changed", ecparams(p256, b_delta=1), b"\x00", "nokey")
    ec_explicit("p256-base-infinity", ecparams(p256, base="infinity"), b"\x00", "nokey")
    ec_explicit("p256-base-off-curve", ecparams(p256, base="off-curve"), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-base-empty", ecparams(p256, base=b""), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-order-0", ecparams(p256, order=0), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-order-neg", ecparams(p256, order=-5), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-order-258-bits", ecparams(p256, order=1 << 257), p256pts["uncompressed"], "nokey")
    ec_explicit("p256-order-257-bits", ecparams(p256, order=(1 << 256) + 1), b"\x00", "ec/257/explicit_prime")
    ec_explicit("p256-order-small", ecparams(p256, order=7), b"\x00", "ec/3/explicit_prime")
    ec_explicit("p-even", ecparams(p256, field=seq(oid("1.2.840.10045.1.1"), integer((1 << 255) * 2))), b"\x00", "nokey")
    ec_explicit("p-3", ecparams(p256, field=seq(oid("1.2.840.10045.1.1"), integer(3))), b"\x00", "nokey")
    ec_explicit("p-negative", ecparams(p256, field=seq(oid("1.2.840.10045.1.1"), integer(-int.from_bytes(p256[3], "big")))), b"\x00", "nokey")
    ec_explicit("p-662-bits", ecparams(p256, field=seq(oid("1.2.840.10045.1.1"), integer((1 << 661) + 1))), b"\x00", "nokey")
    ec_explicit("field-unknown", ecparams(p256, field=seq(oid("1.2.3.4"), integer(5))), p256pts["uncompressed"], "nokey")
    ec_explicit("k163-pentanomial", ecparams(k163), k163pts["uncompressed"], k163n)
    ec_explicit("k163-compressed-base", ecparams(k163, base="compressed"), k163pts["compressed"], k163n)
    n163 = int.from_bytes(k163[8], "big")
    ec_explicit("k163-order-changed", ecparams(k163, order=n163 - 2), k163pts["uncompressed"], "ec/163/explicit_char2")
    ec_explicit("k283-pentanomial", ecparams(k283), curve_points(k283)["uncompressed"], k283n)
    ec_explicit("k163-onbasis", ecparams(k163, basis=lambda m, ks: seq(integer(m), oid("1.2.840.10045.1.2.3.1"), NULL)),
                k163pts["uncompressed"], "nokey")
    ec_explicit("k163-basis-unknown", ecparams(k163, basis=lambda m, ks: seq(integer(m), oid("1.2.3.4"), NULL)),
                k163pts["uncompressed"], "nokey")
    ec_explicit("k163-pentanomial-unordered",
                ecparams(k163, basis=lambda m, ks: seq(integer(m), oid("1.2.840.10045.1.2.3.3"), seq(*[integer(k) for k in reversed(ks)]))),
                k163pts["uncompressed"], "nokey")
    ec_explicit("k163-m-662", ecparams(k163, basis=lambda m, ks: seq(integer(662), oid("1.2.840.10045.1.2.3.2"), integer(3))),
                b"\x00", "nokey")
    for tnid in (726, 727):  # sect233k1, sect233r1: trinomials
        tc = next(c for c in curves if c[0] == tnid)
        ec_explicit("trinomial-%s" % cnames[tnid], ecparams(tc), curve_points(tc)["uncompressed"],
                    "ec/%d/%s" % (int.from_bytes(tc[8], "big").bit_length(), cnames[tnid]))
    ec_explicit("tp-k-zero", ecparams(k163, basis=lambda m, ks: seq(integer(m), oid("1.2.840.10045.1.2.3.2"), integer(0))),
                b"\x00", "nokey")
    ec_explicit("not-a-sequence", integer(5), p256pts["uncompressed"], "nokey")

    # Name values.
    def subj(value, attr=CN):
        return name((attr, value))

    for note, value, expect in [
        ("bmp-ok", tlv(0x1E, "Ünï".encode("utf-16-be")), "ok"),
        ("bmp-surrogate", tlv(0x1E, b"\xd8\x00"), "reject"),
        ("bmp-odd", tlv(0x1E, b"\x00\x41\x00"), "reject"),
        ("univ-ok", tlv(0x1C, b"\x00\x01\xf6\x00"), "ok"),
        ("univ-past-10ffff", tlv(0x1C, b"\x00\x11\x00\x00"), "reject"),
        ("univ-surrogate", tlv(0x1C, b"\x00\x00\xdc\x00"), "reject"),
        ("utf8-overlong", tlv(0x0C, b"\xc0\x80"), "reject"),
        ("utf8-surrogate", tlv(0x0C, b"\xed\xa0\x80"), "reject"),
        ("utf8-past-10ffff", tlv(0x0C, b"\xf4\x90\x80\x80"), "reject"),
        ("utf8-truncated", tlv(0x0C, b"a\xe2\x82"), "reject"),
        ("utf8-f8", tlv(0x0C, b"\xf8\x88\x80\x80\x80"), "reject"),
        ("t61-high", tlv(0x14, b"\xe9t\xe9"), "ok"),
        ("ia5-high", tlv(0x16, b"\xff"), "ok"),
        ("numeric-letters", tlv(0x12, b"abc"), "ok"),
        ("printable-at", tlv(0x13, b"a@b"), "ok"),
        ("bit-string", bits(b"\xff\x0f", 4), "ok"),
        ("bit-string-unused-8", bits(b"\xff", 8), "reject"),
        ("sequence", seq(integer(1)), "ok"),
        ("sequence-indefinite", b"\x30\x80" + integer(1) + b"\x00\x00", "ok"),
        ("primitive-sequence", b"\x10\x01\x00", "reject"),
        ("tag-7", tlv(0x07, b"ext"), "ok"),
        ("tag-9", tlv(0x09, b"\x80"), "ok"),
        ("tag-13", tlv(0x0D, b"\x01\x02"), "ok"),
        ("tag-29", tlv(0x1D, b"x"), "ok"),
        ("tag-31", b"\x1f\x1f\x01x", "reject"),
        ("visible", tlv(0x1A, b"v"), "reject"),
        ("utf8-constructed", b"\x2c\x08" + tlv(0x04, b"ab") + tlv(0x04, b"cd"), "ok"),
        ("utf8-constructed-indefinite", b"\x2c\x80" + tlv(0x04, b"ab") + b"\x00\x00", "ok"),
        ("context-tag", tlv(0x80, b"x"), "reject"),
        ("empty-utf8", tlv(0x0C, b""), "ok"),
    ]:
        add("k-name", "%s expect=%s" % (note, expect), cert(subject=subj(value)))
    add("k-name", "unknown-attr expect=ok", cert(subject=name(("1.2.3.4.5", utf8("x")))))
    add("k-name", "unknown-attr-big-arc expect=ok", cert(subject=name(("1.2.99999999999999999999", utf8("x")))))
    add("k-name", "unknown-attr-2-999 expect=ok", cert(subject=name(("2.999.7", utf8("x")))))
    add("k-name", "oid-586-bytes expect=ok", cert(subject=name((b"\x2a" + b"\x01" * 585, utf8("x")))))
    add("k-name", "issuer-unknown-attr expect=ok", cert(issuer=name(("1.2.3.4.5", utf8("x")))))
    add("k-name", "dup-unknown-attr expect=ok",
        cert(subject=name(("1.2.3.4.5", utf8("x")), ("1.2.3.4.5", utf8("y")))))
    add("k-name", "multi-ava expect=ok",
        cert(subject=seq(set_(seq(oid(CN), utf8("a")), seq(oid("2.5.4.10"), utf8("b"))))))

    # Extension framing (the printers are the p rows).
    def ext(dotted_or_content, value=b"", critical=None):
        o = oid(dotted_or_content) if isinstance(dotted_or_content, str) else tlv(0x06, dotted_or_content)
        parts = [o]
        if critical is not None:
            parts.append(tlv(0x01, bytes([critical])))
        parts.append(octet(value))
        return seq(*parts)

    def long_oid(chars):
        """A dotted OID unknown to OpenSSL whose text is `chars` long."""
        text = "1.3.9999"
        while len(text) + 2 <= chars:
            text += ".1"
        if len(text) < chars:
            text = text[:-1] + "11"[: chars - len(text) + 1]
        assert len(text) == chars, (chars, len(text))
        return text

    for n in (254, 255, 256, 257, 300):
        add("k-ext", "name-%d-chars expect=ok" % n, cert(exts=[ext(long_oid(n))]))
    add("k-ext", "critical-00 expect=ok", cert(exts=[ext("1.2.3.4", b"", 0x00)]))
    add("k-ext", "critical-01 expect=ok", cert(exts=[ext("1.2.3.4", b"", 0x01)]))
    add("k-ext", "critical-80 expect=ok", cert(exts=[ext("1.2.3.4", b"", 0x80)]))
    add("k-ext", "critical-ff expect=ok", cert(exts=[ext("1.2.3.4", b"", 0xFF)]))
    add("k-ext", "empty-sequence expect=ok", cert(exts=[]))
    add("k-ext", "oid-586-bytes expect=ok", cert(exts=[ext(b"\x2a" + b"\x01" * 585)]))
    add("k-ext", "oid-587-bytes expect=raise", cert(exts=[ext(b"\x2a" + b"\x01" * 586)]))
    add("k-ext", "value-constructed expect=ok",
        cert(exts=[seq(oid("1.2.3.4"), b"\x24\x08" + tlv(0x04, b"ab") + tlv(0x04, b"cd"))]))
    add("k-ext", "critical-2-octets expect=reject", cert(exts=[seq(oid("1.2.3.4"), tlv(0x01, b"\x00\x00"), octet(b""))]))
    add("k-ext", "no-value expect=reject", cert(exts=[seq(oid("1.2.3.4"))]))
    return out


def k_rows():
    return ["k%05d\t%s %s\t%s" % (i + 1, fam, note, der.hex()) for i, (fam, note, der) in enumerate(rows())]


def read_certs():
    head, xb, k = [], [], []
    for line in open(CERTS, encoding="ascii"):
        line = line.rstrip("\n")
        if line.startswith("#"):
            head.append(line)
        elif line.startswith("k"):
            k.append(line)
        elif line:
            xb.append(line)
    return head, xb, k


HEADER_K = ("# Rows k*: oracle/gen_m65_x509.py (step e: key types, Name values, extension"
            " framing; deterministic, the note ends with the row's expected outcome).")


def write():
    head, xb, _ = read_certs()
    head = [h for h in head if not h.startswith("# Rows k*")] + [HEADER_K]
    # Everything is built before the file is opened, so a generator error
    # leaves the corpus as it was.
    text = "\n".join(head + xb + k_rows()) + "\n"
    with open(CERTS, "w", encoding="ascii") as fh:
        fh.write(text)
    print("m65_certs.txt: %d k rows" % len(k_rows()))


def check():
    _, _, k = read_certs()
    if k != k_rows():
        sys.exit("FAIL: m65_certs.txt's k rows are not what gen_m65_x509.py writes; run it")
    print("m65_certs.txt: %d k rows current" % len(k))


def check_golden():
    _, _, k = read_certs()
    expect = {}
    for line in k:
        cid, note, _ = line.split("\t")
        m = re.search(r"expect=(\S+)$", note)
        expect[cid] = (m.group(1), note)
    case_of = {}
    for line in open(CASES, encoding="ascii"):
        f = line.rstrip("\n").split("\t")
        if len(f) >= 5 and f[3] == "parse_ssl_certificate" and f[4].startswith("der:k"):
            case_of[f[0]] = f[4][4:]
    bad = 0
    for line in open(GOLDEN, encoding="utf-8", errors="replace"):
        f = line.rstrip("\n").split("\t")
        if f[0] not in case_of:
            continue
        cid = case_of[f[0]]
        want, note = expect[cid]
        got = f[2] if len(f) > 2 else ""
        if want == "reject":
            ok = f[1] == "ok" and got == "nil"
        elif want == "raise":
            ok = f[1] == "err"
        elif want == "nokey":
            ok = got.startswith('nil "Error parsing cert:')
        elif want == "ok":
            ok = got.startswith("cert<")
        else:
            kind, nbits, *curve = want.split("/")
            ok = got.startswith("cert<") and ('"bits"=i%s,' % nbits) in got and ('"type"="%s"' % kind) in got
            if kind == "unknown":
                ok = ok and '"ecdhparams"' not in got
            elif curve and curve[0].startswith("explicit_"):
                ok = ok and ('"ec_curve_type"="%s"' % curve[0]) in got
            elif curve:
                ok = ok and ('"curve"="%s"' % curve[0]) in got
        if not ok:
            bad += 1
            print("%s %s: expected %s, golden %s" % (cid, note, want, got[:300]), file=sys.stderr)
    if bad:
        sys.exit("FAIL: %d k rows differ from what they expect" % bad)
    print("m65 golden: every k row as it expects (%d)" % len(expect))


if __name__ == "__main__":
    arg = sys.argv[1:2]
    if arg == ["--check"]:
        check()
    elif arg == ["--check-golden"]:
        check_golden()
    elif not arg:
        write()
    else:
        sys.exit(__doc__)
