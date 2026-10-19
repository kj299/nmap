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


def cert(spki=SPKI_RSA, subject=None, exts=None, issuer=None, sig_alg=None):
    subject = subject if subject is not None else name((CN, utf8("m65k")))
    issuer = issuer if issuer is not None else name((CN, utf8("m65k")))
    fields = [explicit(0, integer(2)), integer(1), algid(SHA256_RSA, NULL), issuer,
              seq(utctime("200101000000Z"), utctime("300101000000Z")), subject, spki]
    if exts is not None:
        fields.append(explicit(3, seq(*exts)))
    return seq(seq(*fields), sig_alg if sig_alg is not None else algid(SHA256_RSA, NULL), SIGNATURE)


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

    # A signature algorithm parameter of universal tag 0 in a constructed
    # header: d2i_X509 keeps it as an ASN1_TYPE of type 0, and i2d_X509 writes
    # it primitive, as an EOC (00 00), which the PEM and digest are computed
    # over and d2i_X509 would refuse (the fuzz target nse_sslcert_der's one
    # re-encoding that does not decode).
    add("k-sigalg", "param-tag0 expect=ok", cert(sig_alg=seq(oid(SHA256_RSA), b"\x20\x00")))
    add("k-sigalg", "param-tag0-indefinite expect=ok", cert(sig_alg=seq(oid(SHA256_RSA), b"\x20\x80\x00\x00")))
    add("k-sigalg", "param-tag0-primitive-is-eoc expect=reject", cert(sig_alg=seq(oid(SHA256_RSA), b"\x00\x00")))

    # Constructed strings nested around a primitive one, definite and
    # indefinite: asn1_collect counts the levels below the outer header and
    # refuses past ASN1_MAX_STRING_NEST (5), so six constructed levels are
    # read and seven are not.
    def nested(depth, inf, inner=tlv(0x04, b"A")):
        v = inner
        for _ in range(depth):
            v = b"\x24\x80" + v + b"\x00\x00" if inf else tlv(0x24, v)
        return v

    for depth in (5, 6, 7):
        for inf in (False, True):
            form = "indefinite" if inf else "definite"
            want = "ok" if depth <= 6 else "reject"
            add("k-nest", "ext-value-%d-%s expect=%s" % (depth, form, want),
                cert(exts=[seq(oid("1.2.3.4"), nested(depth, inf))]))
    for depth in (6, 7):
        add("k-nest", "subject-utf8-%d expect=%s" % (depth, "ok" if depth <= 6 else "reject"),
            # A constructed UTF8String whose segments nest `depth` deep in all.
            cert(subject=name((CN, tlv(0x2C, nested(depth - 1, False, tlv(0x0C, b"v")))))))
    return out


# ---- the extension printers (p rows) ------------------------------------------------
#
# One certificate per row, its extensions built here and the text
# X509V3_EXT_print gives written out by hand from OpenSSL 3.0.13's printers
# (crypto/x509/v3_*.c, crypto/ocsp/v3_ocsp.c, crypto/ct/ct_prn.c), so the
# golden checks this file's reading of the C as much as the port's. The note
# ends with `expect=value:HEX` (the extension's value, hex of the bytes),
# `expect=error` (error = true), or `expect=nokey:CODE` (the key does not
# decode, so the call returns nil and "Error parsing cert: " with the first
# error the printing raised, ERR_error_string's 8 hex digits).

BADKEY = seq(algid(RSA, NULL), bits(b"\x01\x02"))


def gn_other(dotted, value):
    return tlv(0xA0, oid(dotted) + explicit(0, value))


def gn_email(s):
    return tlv(0x81, s)


def gn_dns(s):
    return tlv(0x82, s)


def gn_dir(n):
    return tlv(0xA4, n)


def gn_uri(s):
    return tlv(0x86, s)


def gn_ip(b):
    return tlv(0x87, b)


def gn_rid(dotted):
    return tlv(0x88, oid_content(dotted))


def ia5(s):
    return tlv(0x16, s)


def gtime(s):
    return tlv(0x18, s)


def hex_string(data, indent=16, width=16):
    """BIO_hex_string(out, indent, width, data, len)."""
    out, j = "", 0
    if not data:
        return out
    for i in range(len(data) - 1):
        if i and not j:
            out += " " * indent
        out += "%02X:" % data[i]
        j = (j + 1) % width
        if not j:
            out += "\n"
    if len(data) > 1 and not j:
        out += " " * indent
    return out + "%02X" % data[-1]


def printer_rows():
    out = []

    def ext(dotted, value, critical=None):
        parts = [oid(dotted)]
        if critical is not None:
            parts.append(tlv(0x01, bytes([critical])))
        return seq(*parts, octet(value))

    def val(fam, note, dotted, value, text):
        if isinstance(text, str):
            text = text.encode("latin-1")
        out.append((fam, "%s expect=value:%s" % (note, text.hex()), cert(exts=[ext(dotted, value)])))

    def err(fam, note, dotted, value):
        out.append((fam, note + " expect=error", cert(exts=[ext(dotted, value)])))

    def nokey(fam, note, code, *exts):
        out.append((fam, "%s expect=nokey:%08X" % (note, code), cert(spki=BADKEY, exts=list(exts))))

    # Packed codes, ERR_PACK(lib, 0, reason), from the vendored openssl.txt
    # and err.c / err.h.in (the tables `err` is generated from).
    codes, libs = {}, {}
    for prefix, num, _, rs in openssl_data.errors():
        libs[prefix] = num
        for nm, code, _ in rs:
            codes["%s_R_%s" % (prefix, nm)] = (num << 23) | code
    common = {nm: code for nm, code, _ in openssl_data.common_reasons()}

    def asn1(reason):
        return codes["ASN1_R_" + reason]

    WRONG_TAG, NO_CHOICE, TOO_LARGE = asn1("WRONG_TAG"), asn1("NO_MATCHING_CHOICE_TYPE"), asn1("TOO_LARGE")
    FIELD_MISSING = asn1("FIELD_MISSING")
    X509V3_MALLOC = (libs["X509V3"] << 23) | common["MALLOC_FAILURE"]
    X509V3_NULL_PARAM = (libs["X509V3"] << 23) | common["PASSED_NULL_PARAMETER"]
    DECODE = codes["EVP_R_DECODE_ERROR"]

    # Bit strings: key usage, Netscape cert type.
    KU, NSCT = "2.5.29.15", "2.16.840.1.113730.1.1"
    val("p-bits", "ku-three", KU, bits(b"\x86", 1), "Digital Signature, Certificate Sign, CRL Sign")
    val("p-bits", "ku-decipher-only", KU, bits(b"\x00\x80", 7), "Decipher Only")
    val("p-bits", "ku-all", KU, bits(b"\xff\x80", 7),
        "Digital Signature, Non Repudiation, Key Encipherment, Data Encipherment, Key Agreement, "
        "Certificate Sign, CRL Sign, Encipher Only, Decipher Only")
    val("p-bits", "ku-padding-masked", KU, bits(b"\x81", 1), "Digital Signature")
    err("p-bits", "ku-empty", KU, bits(b""))
    err("p-bits", "ku-zero", KU, bits(b"\x00\x00"))
    val("p-bits", "ku-trailing-bytes", KU, bits(b"\x80", 7) + b"\xff\xff", "Digital Signature")
    nokey("p-bits", "ku-wrong-tag", WRONG_TAG, ext(KU, octet(b"\x80")))
    val("p-bits", "nscert-all", NSCT, bits(b"\xff"),
        "SSL Client, SSL Server, S/MIME, Object Signing, Unused, SSL CA, S/MIME CA, Object Signing CA")

    # IA5String i2s (the Netscape URLs and comment): %s stops at a NUL; empty is
    # an error with nothing raised.
    NSC = "2.16.840.1.113730.1.13"
    val("p-ia5", "comment", NSC, ia5(b"hello, world"), "hello, world")
    val("p-ia5", "comment-nul", NSC, ia5(b"ab\x00cd"), "ab")
    val("p-ia5", "comment-high-bytes", NSC, ia5(b"\xe9\x01x"), b"\xe9\x01x")
    err("p-ia5", "comment-empty", NSC, ia5(b""))
    nokey("p-ia5", "comment-empty-no-raise", DECODE, ext(NSC, ia5(b"")))
    nokey("p-ia5", "comment-utf8-tag", WRONG_TAG, ext(NSC, utf8("x")))
    for arc in (2, 3, 4, 7, 8, 12):
        val("p-ia5", "ns-url-%d" % arc, "2.16.840.1.113730.1.%d" % arc, ia5(b"http://x"), "http://x")

    # Subject key identifier.
    SKID = "2.5.29.14"
    val("p-skid", "two-octets", SKID, octet(b"\xab\x01"), "AB:01")
    val("p-skid", "empty", SKID, octet(b""), "")
    val("p-skid", "twenty", SKID, octet(bytes(range(20))),
        ":".join("%02X" % i for i in range(20)))

    # Private key usage period: ASN1_TIME_print of GeneralizedTimes.
    PKU = "2.5.29.16"
    t0 = lambda s: tlv(0x80, s)  # noqa: E731
    t1 = lambda s: tlv(0x81, s)  # noqa: E731
    val("p-pku", "both", PKU, seq(t0(b"20200101000000Z"), t1(b"20301231235959Z")),
        "Not Before: Jan  1 00:00:00 2020 GMT, Not After: Dec 31 23:59:59 2030 GMT")
    val("p-pku", "after-only", PKU, seq(t1(b"20200229120000Z")), "Not After: Feb 29 12:00:00 2020 GMT")
    val("p-pku", "before-only", PKU, seq(t0(b"19991231235959Z")), "Not Before: Dec 31 23:59:59 1999 GMT")
    val("p-pku", "empty", PKU, seq(), "")
    val("p-pku", "bad-time", PKU, seq(t0(b"2020")), "Not Before: Bad time value")
    val("p-pku", "feb-29-non-leap", PKU, seq(t0(b"20190229000000Z")), "Not Before: Bad time value")
    val("p-pku", "fraction-offset", PKU, seq(t0(b"20200101000000.5+0130")),
        "Not Before: Dec 31 22:30:00.5 2019")
    val("p-pku", "minus-offset", PKU, seq(t0(b"20201231233000-0100")), "Not Before: Jan  1 00:30:00 2021")
    val("p-pku", "no-seconds", PKU, seq(t0(b"202001011200Z")), "Not Before: Jan  1 12:00:00 2020 GMT")
    val("p-pku", "no-zone", PKU, seq(t0(b"20200101000000")), "Not Before: Bad time value")
    val("p-pku", "offset-below-1900", PKU, seq(t0(b"19000101000000+0100")), "Not Before: Bad time value")
    val("p-pku", "offset-to-1900", PKU, seq(t0(b"18991231230000-0100")), "Not Before: Jan  1 00:00:00 1900")
    val("p-pku", "year-0000", PKU, seq(t0(b"00000101000000Z")), "Not Before: Jan  1 00:00:00 0 GMT")
    val("p-pku", "hour-24", PKU, seq(t0(b"20200101240000Z")), "Not Before: Bad time value")
    val("p-pku", "dot-no-digits", PKU, seq(t0(b"20200101000000.Z")), "Not Before: Bad time value")
    nokey("p-pku", "utctime-tag", WRONG_TAG, ext(PKU, seq(tlv(0x17, b"200101000000Z"))))

    # GENERAL_NAMES (subject and issuer alternative names, certificate issuer).
    SAN, IAN, CI = "2.5.29.17", "2.5.29.18", "2.5.29.29"
    val("p-gn", "dns-ip-email-uri", SAN,
        seq(gn_dns(b"a.example"), gn_ip(b"\x0a\x00\x00\x01"), gn_email(b"x@y"), gn_uri(b"http://u")),
        "DNS:a.example, IP Address:10.0.0.1, email:x@y, URI:http://u")
    val("p-gn", "ipv6", SAN, seq(gn_ip(bytes.fromhex("20010db8000000000000000000000001"))),
        "IP Address:2001:DB8:0:0:0:0:0:1")
    val("p-gn", "ip-5-octets", SAN, seq(gn_ip(b"\x01\x02\x03\x04\x05")), "IP Address:<invalid length=5>")
    val("p-gn", "ip-empty", SAN, seq(gn_ip(b"")), "IP Address:<invalid length=0>")
    val("p-gn", "empty", SAN, seq(), "<EMPTY>\n")
    val("p-gn", "rid-unknown", SAN, seq(gn_rid("1.2.3.4")), "Registered ID:1.2.3.4")
    val("p-gn", "rid-known", SAN, seq(gn_rid("2.5.4.3")), "Registered ID:commonName")
    val("p-gn", "x400", SAN, seq(tlv(0xA3, utf8("x"))), "X400Name:<unsupported>")
    val("p-gn", "edi-party", SAN, seq(tlv(0xA5, explicit(1, utf8("party")))), "EdiPartyName:<unsupported>")
    val("p-gn", "edi-party-assigner", SAN, seq(tlv(0xA5, explicit(0, utf8("a")) + explicit(1, utf8("p")))),
        "EdiPartyName:<unsupported>")
    nokey("p-gn", "edi-party-not-a-string", asn1("MSTRING_WRONG_TAG"), ext(SAN, seq(tlv(0xA5, explicit(1, tlv(0x02, b"\x01"))))))
    val("p-gn", "upn", SAN, seq(gn_other("1.3.6.1.4.1.311.20.2.3", utf8("user@x"))), "othername: UPN::user@x")
    val("p-gn", "smtputf8", SAN, seq(gn_other("1.3.6.1.5.5.7.8.9", utf8("é@x"))),
        "othername: SmtpUTF8Mailbox::é@x".encode())
    val("p-gn", "xmpp", SAN, seq(gn_other("1.3.6.1.5.5.7.8.5", utf8("a@b"))), "othername: XmppAddr::a@b")
    val("p-gn", "srvname", SAN, seq(gn_other("1.3.6.1.5.5.7.8.7", ia5(b"_x.y"))), "othername: SRVName::_x.y")
    val("p-gn", "nairealm", SAN, seq(gn_other("1.3.6.1.5.5.7.8.8", utf8("r"))), "othername: NAIRealm::r")
    err("p-gn", "upn-ia5", SAN, seq(gn_other("1.3.6.1.4.1.311.20.2.3", ia5(b"u"))))
    nokey("p-gn", "upn-ia5-no-raise", DECODE, ext(SAN, seq(gn_other("1.3.6.1.4.1.311.20.2.3", ia5(b"u")))))
    err("p-gn", "srvname-utf8", SAN, seq(gn_other("1.3.6.1.5.5.7.8.7", utf8("u"))))
    val("p-gn", "other-unknown-ia5", SAN, seq(gn_other("1.2.3.4", ia5(b"v"))), "othername: 1.2.3.4::v")
    val("p-gn", "other-unknown-utf8", SAN, seq(gn_other("1.2.3.4", utf8("v"))), "othername: 1.2.3.4::v")
    val("p-gn", "other-unknown-int", SAN, seq(gn_other("1.2.3.4", integer(5))),
        "othername: 1.2.3.4::<unsupported>")
    val("p-gn", "other-known-oid", SAN, seq(gn_other("2.5.4.3", utf8("v"))), "othername: commonName::v")
    val("p-gn", "other-context-value", SAN, seq(gn_other("1.2.3.4", tlv(0x80, b"v"))),
        "othername: 1.2.3.4::<unsupported>")
    val("p-gn", "other-ia5-nul", SAN, seq(gn_other("1.2.3.4", ia5(b"a\x00b"))),
        "othername: 1.2.3.4::<unsupported>")
    nokey("p-gn", "other-ia5-nul-raises", X509V3_MALLOC, ext(SAN, seq(gn_other("1.2.3.4", ia5(b"a\x00b")))))
    long_oid = "1.3.9999" + ".1" * 130
    val("p-gn", "other-oid-255", SAN, seq(gn_other(long_oid, ia5(b"v"))),
        "othername: " + long_oid[:255] + "::v")
    err("p-gn", "dns-nul", SAN, seq(gn_dns(b"a\x00b")))
    nokey("p-gn", "dns-nul-raises", X509V3_MALLOC, ext(SAN, seq(gn_dns(b"a\x00b"))))
    nokey("p-gn", "unknown-tag", NO_CHOICE, ext(SAN, seq(tlv(0x89, b"x"))))
    nokey("p-gn", "dns-utf8-tag", NO_CHOICE, ext(SAN, seq(utf8("x"))))
    val("p-gn", "dirname", SAN, seq(gn_dir(name((CN, utf8("a/b+c")), ("2.5.4.10", utf8("o"))))),
        "DirName:/CN=a\\/b\\+c/O=o")
    val("p-gn", "dirname-multivalued", SAN,
        seq(gn_dir(seq(set_(seq(oid(CN), utf8("a")), seq(oid("2.5.4.10"), utf8("b")))))),
        "DirName:/CN=a+O=b")
    val("p-gn", "dirname-bytes", SAN, seq(gn_dir(name((CN, utf8("é\x01\x7f"))))),
        "DirName:/CN=\\xC3\\xA9\\x01\\x7F")
    val("p-gn", "dirname-unknown-oid", SAN, seq(gn_dir(name(("1.2.3.4", utf8("v"))))), "DirName:/1.2.3.4=v")
    val("p-gn", "dirname-t61", SAN, seq(gn_dir(name((CN, tlv(0x14, b"t\xe9"))))), "DirName:/CN=t\\xE9")
    nokey("p-gn", "dirname-generalstring", asn1("MSTRING_WRONG_TAG"),
          ext(SAN, seq(gn_dir(name((CN, tlv(0x1B, b"AB")))))))
    val("p-gn", "dirname-empty", SAN, seq(gn_dir(seq())), "DirName:")
    val("p-gn", "dirname-truncated", SAN,
        seq(gn_dir(name((CN, utf8("x" * 200)), (CN, utf8("y" * 60))))), "DirName:/CN=" + "x" * 200)
    val("p-gn", "dirname-sequence-value", SAN, seq(gn_dir(name((CN, seq(integer(1)))))),
        "DirName:/CN=0\\x03\\x02\\x01\\x01")
    nokey("p-gn", "dirname-bad-utf8", asn1("INVALID_UTF8STRING"), ext(SAN, seq(gn_dir(name((CN, utf8(b"\xff")))))))
    val("p-gn", "issuer-alt", IAN, seq(gn_email(b"ca@x")), "email:ca@x")
    val("p-gn", "cert-issuer", CI, seq(gn_dns(b"x")), "DNS:x")
    val("p-gn", "trailing-bytes", SAN, seq(gn_dns(b"x")) + b"\x00garbage", "DNS:x")

    # Basic constraints.
    BC = "2.5.29.19"
    val("p-bc", "ca-pathlen", BC, seq(tlv(0x01, b"\xff"), integer(0)), "CA:TRUE, pathlen:0")
    val("p-bc", "empty", BC, seq(), "CA:FALSE")
    val("p-bc", "ca-01", BC, seq(tlv(0x01, b"\x01")), "CA:TRUE")
    val("p-bc", "ca-false-explicit", BC, seq(tlv(0x01, b"\x00")), "CA:FALSE")
    val("p-bc", "pathlen-negative", BC, seq(integer(-1)), "CA:FALSE, pathlen:-1")
    val("p-bc", "pathlen-127-bits", BC, seq(integer((1 << 127) - 1)),
        "CA:FALSE, pathlen:%d" % ((1 << 127) - 1))
    val("p-bc", "pathlen-128-bits", BC, seq(integer(1 << 127)), "CA:FALSE, pathlen:0x80" + "00" * 15)
    val("p-bc", "pathlen-negative-big", BC, seq(integer(-(1 << 130))), "CA:FALSE, pathlen:-0x04" + "00" * 16)
    nokey("p-bc", "bool-2-octets", asn1("BOOLEAN_IS_WRONG_LENGTH"), ext(BC, seq(tlv(0x01, b"\x00\x00"))))
    nokey("p-bc", "pathlen-padded", asn1("ILLEGAL_PADDING"), ext(BC, seq(raw_int(b"\x00\x01"))))

    # INTEGER i2s: CRL number, delta CRL, inhibit any policy.
    for dotted, nm in (("2.5.29.20", "crl-number"), ("2.5.29.27", "delta-crl"), ("2.5.29.54", "inhibit-any")):
        val("p-int", nm, dotted, integer(5), "5")
    val("p-int", "zero", "2.5.29.20", integer(0), "0")
    val("p-int", "negative", "2.5.29.20", integer(-300), "-300")
    val("p-int", "big", "2.5.29.20", integer(0x0102 << 200), "0x0102" + "00" * 25)
    nokey("p-int", "empty", asn1("ILLEGAL_ZERO_CONTENT"), ext("2.5.29.20", raw_int(b"")))

    # Certificate policies.
    CP = "2.5.29.32"

    def qual(dotted, value):
        return seq(oid(dotted), value)

    CPS, UNOTICE = "1.3.6.1.5.5.7.2.1", "1.3.6.1.5.5.7.2.2"
    val("p-cpol", "any-policy", CP, seq(seq(oid("2.5.29.32.0"))), "Policy: X509v3 Any Policy")
    val("p-cpol", "cps-and-notice", CP,
        seq(seq(oid("1.2.3.4"), seq(qual(CPS, ia5(b"http://cps")),
                                    qual(UNOTICE, seq(seq(utf8("Org"), seq(integer(1), integer(2))),
                                                      utf8("text")))))),
        "Policy: 1.2.3.4\n  CPS: http://cps\n  User Notice:\n    Organization: Org\n"
        "    Numbers: 1, 2\n    Explicit Text: text")
    val("p-cpol", "notice-one-number", CP,
        seq(seq(oid("1.2.3.4"), seq(qual(UNOTICE, seq(seq(ia5(b"O"), seq(integer(7)))))))),
        "Policy: 1.2.3.4\n  User Notice:\n    Organization: O\n    Number: 7")
    val("p-cpol", "notice-empty", CP, seq(seq(oid("1.2.3.4"), seq(qual(UNOTICE, seq())))),
        "Policy: 1.2.3.4\n  User Notice:\n")
    val("p-cpol", "notice-bmp-text", CP,
        seq(seq(oid("1.2.3.4"), seq(qual(UNOTICE, seq(tlv(0x1E, b"\x00h\x00i")))))),
        "Policy: 1.2.3.4\n  User Notice:\n    Explicit Text: ")
    val("p-cpol", "unknown-qualifier", CP, seq(seq(oid("1.2.3.4"), seq(qual("1.2.3.5", integer(1))))),
        "Policy: 1.2.3.4\n    Unknown Qualifier: 1.2.3.5")
    val("p-cpol", "empty-qualifiers", CP, seq(seq(oid("1.2.3.4"), seq())), "Policy: 1.2.3.4\n")
    val("p-cpol", "two-policies", CP, seq(seq(oid("1.2.3.4")), seq(oid("1.2.3.5"), seq(qual(CPS, ia5(b"c"))))),
        "Policy: 1.2.3.4\nPolicy: 1.2.3.5\n  CPS: c")
    val("p-cpol", "cps-nul", CP, seq(seq(oid("1.2.3.4"), seq(qual(CPS, ia5(b"a\x00b"))))),
        "Policy: 1.2.3.4\n  CPS: a")
    val("p-cpol", "empty", CP, seq(), "")
    nokey("p-cpol", "cps-utf8", WRONG_TAG, ext(CP, seq(seq(oid("1.2.3.4"), seq(qual(CPS, utf8("c")))))))
    nokey("p-cpol", "qualifier-missing", FIELD_MISSING, ext(CP, seq(seq(oid("1.2.3.4"), seq(seq(oid(CPS)))))))

    # Authority key identifier (multiline).
    AKID = "2.5.29.35"
    val("p-akid", "keyid-only", AKID, seq(tlv(0x80, b"\xab\xcd")), "AB:CD")
    val("p-akid", "all", AKID, seq(tlv(0x80, b"\xab"), tlv(0xA1, gn_dir(name((CN, utf8("x"))))),
                                   tlv(0x82, b"\x01\x02")),
        "keyid:AB\nDirName:/CN=x\nserial:01:02")
    val("p-akid", "serial-negative", AKID, seq(tlv(0x82, b"\xff\x00")), "serial:01:00")
    val("p-akid", "keyid-empty-issuer", AKID, seq(tlv(0x80, b"\x01"), tlv(0xA1, b"")), "keyid:01")
    val("p-akid", "issuer-empty", AKID, seq(tlv(0xA1, b"")), "<EMPTY>\n")
    err("p-akid", "empty", AKID, seq())
    nokey("p-akid", "issuer-nul", X509V3_MALLOC, ext(AKID, seq(tlv(0xA1, gn_dns(b"a\x00")))))

    # CRL distribution points, freshest CRL.
    CRLDP, FRESHEST = "2.5.29.31", "2.5.29.46"

    def dp(name=None, reasons=None, issuer=None):
        parts = []
        if name is not None:
            parts.append(explicit(0, name))
        if reasons is not None:
            parts.append(tlv(0x81, reasons))
        if issuer is not None:
            parts.append(tlv(0xA2, issuer))
        return seq(*parts)

    def full(*gens):
        return tlv(0xA0, b"".join(gens))

    def rel(*ents):
        return tlv(0xA1, b"".join(seq(oid(o), v) for o, v in ents))

    val("p-crldp", "uri", CRLDP, seq(dp(full(gn_uri(b"http://crl")))), "Full Name:\n  URI:http://crl")
    val("p-crldp", "two-names", CRLDP, seq(dp(full(gn_uri(b"http://a"), gn_dns(b"b")))),
        "Full Name:\n  URI:http://a\n  DNS:b")
    val("p-crldp", "two-points", CRLDP, seq(dp(full(gn_uri(b"a"))), dp(full(gn_uri(b"b")))),
        "Full Name:\n  URI:a\nFull Name:\n  URI:b")
    val("p-crldp", "relative", CRLDP, seq(dp(rel((CN, utf8("x")), ("2.5.4.10", utf8("y"))))),
        "Relative Name:\n  CN = x + O = y\n")
    val("p-crldp", "reasons", CRLDP, seq(dp(reasons=b"\x07\x60\x80")),
        "Reasons:\n  Key Compromise, CA Compromise, AA Compromise\n")
    val("p-crldp", "reasons-none", CRLDP, seq(dp(reasons=b"\x00\x00")), "Reasons:\n  <EMPTY>\n")
    val("p-crldp", "crl-issuer", CRLDP, seq(dp(issuer=gn_email(b"e"))), "CRL Issuer:\n  email:e")
    val("p-crldp", "all", CRLDP, seq(dp(full(gn_uri(b"u")), b"\x06\x40", gn_dns(b"d"))),
        "Full Name:\n  URI:uReasons:\n  Key Compromise\nCRL Issuer:\n  DNS:d")
    val("p-crldp", "empty-point", CRLDP, seq(seq()), "")
    val("p-crldp", "empty", CRLDP, seq(), "")
    val("p-crldp", "dirname-oneline", CRLDP,
        seq(dp(full(gn_dir(name((CN, utf8(" lead")), ("2.5.4.10", utf8("a,b")), ("1.2.3.4", utf8("#x"))))))),
        "Full Name:\n  DirName:CN = \" lead\", O = \"a,b\", 1.2.3.4 = \"#x\"")
    val("p-crldp", "dirname-escapes", CRLDP,
        seq(dp(full(gn_dir(name((CN, utf8("q\"b\\c\x01")), (CN, tlv(0x13, b"\xe9")), (CN, utf8("#"))))))),
        "Full Name:\n  DirName:CN = q\\\"b\\\\c\\01, CN = \\C3\\A9, CN = #")
    val("p-crldp", "dirname-bmp", CRLDP, seq(dp(full(gn_dir(name((CN, tlv(0x1E, b"\x00A\x20\xac"))))))),
        "Full Name:\n  DirName:CN = A\\E2\\82\\AC")
    val("p-crldp", "dirname-bitstring", CRLDP, seq(dp(full(gn_dir(name((CN, bits(b"\xf0", 4))))))),
        "Full Name:\n  DirName:CN = #030204F0")
    val("p-crldp", "dirname-trailing-space", CRLDP, seq(dp(full(gn_dir(name((CN, utf8("a "))))))),
        "Full Name:\n  DirName:CN = \"a \"")
    val("p-crldp", "dirname-empty-value", CRLDP, seq(dp(full(gn_dir(name((CN, utf8(""))))))),
        "Full Name:\n  DirName:CN = ")
    val("p-crldp", "x400-print", CRLDP, seq(dp(full(tlv(0xA3, b"")))), "Full Name:\n  X400Name:<unsupported>")
    val("p-crldp", "other-print", CRLDP, seq(dp(full(gn_other("1.3.6.1.4.1.311.20.2.3", utf8("u\x00v"))))),
        "Full Name:\n  othername:UPN:u")
    val("p-crldp", "other-print-unknown", CRLDP, seq(dp(full(gn_other("1.2.3.4", utf8("u"))))),
        "Full Name:\n  othername:<unsupported>")
    val("p-crldp", "rid-print", CRLDP, seq(dp(full(gn_rid("1.2.3.4")))), "Full Name:\n  Registered ID:1.2.3.4")
    val("p-crldp", "ip-print", CRLDP, seq(dp(full(gn_ip(b"\x01\x02\x03\x04")))), "Full Name:\n  IP Address:1.2.3.4")
    val("p-crldp", "uri-unprintable", CRLDP, seq(dp(full(gn_uri(b"a\x00\n\x7f\xff")))),
        "Full Name:\n  URI:a.\n..")
    val("p-crldp", "freshest", FRESHEST, seq(dp(full(gn_uri(b"f")))), "Full Name:\n  URI:f")
    nokey("p-crldp", "name-not-choice", NO_CHOICE, ext(CRLDP, seq(dp(tlv(0xA2, b"")))))

    # Extended key usage, OCSP acceptable responses.
    EKU = "2.5.29.37"
    val("p-eku", "server-client-unknown", EKU,
        seq(oid("1.3.6.1.5.5.7.3.1"), oid("1.3.6.1.5.5.7.3.2"), oid("1.2.3.4")),
        "TLS Web Server Authentication, TLS Web Client Authentication, 1.2.3.4")
    val("p-eku", "long-oid-79", EKU, seq(oid(long_oid)), long_oid[:79])
    err("p-eku", "empty", EKU, seq())
    val("p-eku", "ocsp-accresp", "1.3.6.1.5.5.7.48.1.4", seq(oid("1.3.6.1.5.5.7.48.1.1")), "Basic OCSP Response")

    # CRL reason (ENUMERATED, table else i2s).
    RS = "2.5.29.21"
    for n, t in ((0, "Unspecified"), (1, "Key Compromise"), (6, "Certificate Hold"), (8, "Remove From CRL"),
                 (10, "AA Compromise"), (7, "7"), (-1, "-1")):
        val("p-reason", "reason-%d" % n, RS, tlv(0x0A, integer(n)[2:]), t)
    val("p-reason", "nine-octets", RS, tlv(0x0A, b"\x01" + b"\x00" * 8), str(1 << 64))
    nokey("p-reason", "eight-octets-big", TOO_LARGE, ext(RS, tlv(0x0A, b"\x00" + b"\xff" * 8)))
    nokey("p-reason", "integer-tag", WRONG_TAG, ext(RS, integer(1)))

    # The printers that always fail at indent 0 (their value still decoded).
    err("p-fail", "invalidity-date", "2.5.29.24", gtime(b"20200101000000Z"))
    nokey("p-fail", "invalidity-date-utc", WRONG_TAG, ext("2.5.29.24", tlv(0x17, b"200101000000Z")))
    err("p-fail", "archive-cutoff", "1.3.6.1.5.5.7.48.1.6", gtime(b"20200101000000Z"))
    err("p-fail", "hold-instruction", "2.5.29.23", oid("1.2.840.10040.2.1"))
    nokey("p-fail", "hold-instruction-int", WRONG_TAG, ext("2.5.29.23", integer(1)))
    err("p-fail", "ocsp-nonce", "1.3.6.1.5.5.7.48.1.2", octet(b"\x01\x02"))
    nokey("p-fail", "ocsp-nonce-anything", DECODE, ext("1.3.6.1.5.5.7.48.1.2", b"\xff"))
    err("p-fail", "unknown-oid", "1.2.3.4", b"")
    nokey("p-fail", "unknown-oid-no-raise", DECODE, ext("1.2.3.4", b"\x30"))

    # Strong Extranet ID.
    SX = "1.3.101.1.4.1"
    val("p-sxnet", "one-id", SX, seq(integer(0), seq(seq(integer(1), octet(b"u1")))),
        "Version: 1 (0x0)\nZone: 1, User: u1")
    val("p-sxnet", "negative-version", SX, seq(integer(-1), seq()), "Version: 0 (0xFFFFFFFFFFFFFFFF)")
    val("p-sxnet", "version-long-max", SX, seq(integer((1 << 63) - 1), seq()), "Version: <unsupported>")
    val("p-sxnet", "version-too-large", SX, seq(integer(1 << 63), seq()), "Version: <unsupported>")
    nokey("p-sxnet", "version-too-large-raises", TOO_LARGE, ext(SX, seq(integer(1 << 63), seq())))
    val("p-sxnet", "user-unprintable", SX, seq(integer(2), seq(seq(integer(-5), octet(b"a\x00\xffb")))),
        "Version: 3 (0x2)\nZone: -5, User: a..b")

    # Authority and subject information access (multiline).
    AIA, SIA = "1.3.6.1.5.5.7.1.1", "1.3.6.1.5.5.7.1.11"
    val("p-aia", "ocsp-ca", AIA, seq(seq(oid("1.3.6.1.5.5.7.48.1"), gn_uri(b"http://o")),
                                     seq(oid("1.3.6.1.5.5.7.48.2"), gn_uri(b"http://c"))),
        "OCSP - URI:http://o\nCA Issuers - URI:http://c")
    val("p-aia", "unknown-method", AIA, seq(seq(oid("1.2.3.4"), gn_dns(b"d"))), "1.2.3.4 - DNS:d")
    val("p-aia", "long-method", AIA, seq(seq(oid(long_oid), gn_dns(b"d"))), long_oid[:79] + " - DNS:d")
    val("p-aia", "empty", AIA, seq(), "<EMPTY>\n")
    val("p-aia", "sia", SIA, seq(seq(oid("1.3.6.1.5.5.7.48.5"), gn_uri(b"r"))), "CA Repository - URI:r")
    nokey("p-aia", "dns-nul", X509V3_MALLOC, ext(AIA, seq(seq(oid("1.2.3.4"), gn_dns(b"\x00")))))
    nokey("p-aia", "upn-wrong-type", X509V3_MALLOC,
          ext(AIA, seq(seq(oid("1.2.3.4"), gn_other("1.3.6.1.4.1.311.20.2.3", integer(1))))))

    # RFC 3779 IP address blocks and AS identifiers.
    IPB, ASID = "1.3.6.1.5.5.7.1.7", "1.3.6.1.5.5.7.1.8"

    def fam(afi, choice):
        return seq(octet(afi), choice)

    val("p-addr", "v4-prefixes", IPB, seq(fam(b"\x00\x01", seq(bits(b"\x0a"), bits(b"\xc0\xa8\x80", 1)))),
        "IPv4:\n  10.0.0.0/8\n  192.168.128.0/23\n")
    val("p-addr", "v4-range", IPB, seq(fam(b"\x00\x01", seq(seq(bits(b"\x0a\x00", 0), bits(b"\x0a\x10", 4))))),
        "IPv4:\n  10.0.0.0-10.31.255.255\n")
    val("p-addr", "v4-inherit-safi", IPB, seq(fam(b"\x00\x01\x01", NULL)), "IPv4 (Unicast): inherit\n")
    val("p-addr", "v6-prefix", IPB, seq(fam(b"\x00\x02", seq(bits(b"\x20\x01\x0d\xb8")))), "IPv6:\n  2001:db8::/32\n")
    val("p-addr", "v6-zero", IPB, seq(fam(b"\x00\x02", seq(bits(b"")))), "IPv6:\n  ::/0\n")
    val("p-addr", "v6-full", IPB, seq(fam(b"\x00\x02", seq(bits(bytes(range(1, 17)))))),
        "IPv6:\n  102:304:506:708:90a:b0c:d0e:f10/128\n")
    val("p-addr", "unknown-afi", IPB, seq(fam(b"\x00\x03\x80", seq(bits(b"\x01\x0f", 3)))),
        "Unknown AFI 3 (MPLS-labeled VPN):\n  01:08[3]/13\n")
    val("p-addr", "short-afi", IPB, seq(fam(b"\x01", NULL)), "Unknown AFI 0: inherit\n")
    val("p-addr", "safis", IPB, seq(fam(b"\x00\x01\x02", NULL), fam(b"\x00\x01\x03", NULL),
                                    fam(b"\x00\x01\x04", NULL), fam(b"\x00\x01\x40", NULL),
                                    fam(b"\x00\x01\x41", NULL), fam(b"\x00\x01\x42", NULL),
                                    fam(b"\x00\x01\x07", NULL)),
        "IPv4 (Multicast): inherit\nIPv4 (Unicast/Multicast): inherit\nIPv4 (MPLS): inherit\n"
        "IPv4 (Tunnel): inherit\nIPv4 (VPLS): inherit\nIPv4 (BGP MDT): inherit\nIPv4 (Unknown SAFI 7): inherit\n")
    val("p-addr", "empty-bits-prefix-unused", IPB, seq(fam(b"\x00\x01", seq(bits(b"", 3)))),
        "IPv4:\n  0.0.0.0/-3\n")
    err("p-addr", "v4-too-long", IPB, seq(fam(b"\x00\x01", seq(bits(b"\x01\x02\x03\x04\x05")))))
    val("p-addr", "empty", IPB, seq(), "")
    nokey("p-addr", "choice-int", NO_CHOICE, ext(IPB, seq(fam(b"\x00\x01", integer(1)))))
    val("p-asid", "ids-and-inherit", ASID,
        seq(explicit(0, seq(integer(1), seq(integer(5), integer(10)))), explicit(1, NULL)),
        "Autonomous System Numbers:\n  1\n  5-10\nRouting Domain Identifiers:\n  inherit\n")
    val("p-asid", "rdi-only", ASID, seq(explicit(1, seq(integer(1 << 140)))),
        "Routing Domain Identifiers:\n  0x1" + "0" * 35 + "\n")
    val("p-asid", "empty", ASID, seq(), "")

    # OCSP: CRL ID, no check, service locator.
    CRLID, NOCHECK, SLOC = "1.3.6.1.5.5.7.48.1.3", "1.3.6.1.5.5.7.48.1.5", "1.3.6.1.5.5.7.48.1.7"
    val("p-ocsp", "crlid-all", CRLID,
        seq(explicit(0, ia5(b"http://x\x01")), explicit(1, integer(-0x1234)), explicit(2, gtime(b"20200101000000Z"))),
        "crlUrl: http://x.\ncrlNum: -1234\ncrlTime: Jan  1 00:00:00 2020 GMT\n")
    val("p-ocsp", "crlid-empty", CRLID, seq(), "")
    val("p-ocsp", "crlid-num-long", CRLID, seq(explicit(1, integer(1 << 300))),
        "crlNum: 10" + "00" * 34 + "\\\n" + "00" * 3 + "\n")
    val("p-ocsp", "nocheck", NOCHECK, NULL, "")
    nokey("p-ocsp", "nocheck-not-null", asn1("NULL_IS_WRONG_LENGTH"), ext(NOCHECK, tlv(0x05, b"\x00")))
    val("p-ocsp", "serviceloc", SLOC, seq(name((CN, utf8("x"))), seq(seq(oid("1.3.6.1.5.5.7.48.1"), gn_uri(b"http://l")))),
        "Issuer: CN = x\nOCSP - URI:http://l")
    val("p-ocsp", "serviceloc-no-locator", SLOC, seq(name((CN, utf8("x")))), "Issuer: CN = x")
    err("p-ocsp", "serviceloc-empty-issuer", SLOC, seq(seq()))

    # Policy constraints, policy mappings, TLS feature.
    PC, PM, TLSF = "2.5.29.36", "2.5.29.33", "1.3.6.1.5.5.7.1.24"
    val("p-pc", "both", PC, seq(tlv(0x80, b"\x00"), tlv(0x81, b"\x02")),
        "Require Explicit Policy:0, Inhibit Policy Mapping:2")
    val("p-pc", "inhibit-only", PC, seq(tlv(0x81, b"\xff")), "Inhibit Policy Mapping:-1")
    err("p-pc", "empty", PC, seq())
    val("p-pm", "two", PM, seq(seq(oid("2.5.29.32.0"), oid("1.2.3")), seq(oid("1.2.4"), oid(long_oid))),
        "X509v3 Any Policy:1.2.3, 1.2.4:" + long_oid[:79])
    err("p-pm", "empty", PM, seq())
    val("p-tlsf", "known-and-not", TLSF, seq(integer(5), integer(17), integer(3), integer(-5)),
        "status_request, status_request_v2, 3, -5")
    val("p-tlsf", "big", TLSF, seq(integer(1 << 64)), str(1 << 64))
    nokey("p-tlsf", "big-raises", TOO_LARGE, ext(TLSF, seq(integer(1 << 64))))
    err("p-tlsf", "empty", TLSF, seq())

    # Proxy certificate info.
    PCI = "1.3.6.1.5.5.7.1.14"
    val("p-pci", "pathlen-text", PCI, seq(integer(5), seq(oid("1.3.6.1.5.5.7.21.0"), octet(b"text\x00more"))),
        "Path Length Constraint: 05\nPolicy Language: Any language\nPolicy Text: text")
    val("p-pci", "infinite", PCI, seq(seq(oid("1.2.3.4"))), "Path Length Constraint: infinite\nPolicy Language: 1.2.3.4")
    val("p-pci", "negative", PCI, seq(integer(-1), seq(oid("1.2.3.4"))),
        "Path Length Constraint: -01\nPolicy Language: 1.2.3.4")

    # Name constraints.
    NC = "2.5.29.30"

    def subtrees(tag_, *gens):
        return tlv(tag_, b"".join(seq(g) for g in gens))

    val("p-nc", "permitted-excluded", NC,
        seq(subtrees(0xA0, gn_dns(b"ok.example")), subtrees(0xA1, gn_ip(b"\x0a\x00\x00\x00\xff\x00\x00\x00"))),
        "Permitted:\n  DNS:ok.example\nExcluded:\n  IP:10.0.0.0/255.0.0.0")
    val("p-nc", "ipv6", NC, seq(subtrees(0xA0, gn_ip(bytes(16) + b"\xff" * 16))),
        "Permitted:\n  IP:0:0:0:0:0:0:0:0/FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF:FFFF")
    val("p-nc", "ip-odd", NC, seq(subtrees(0xA0, gn_ip(b"\x01\x02\x03\x04\x05"), gn_ip(b"\x01\x02"))),
        "Permitted:\n  IP:1.2.3.4/<invalid length=1>\n  IP:<invalid length=2>/<invalid length=0>")
    val("p-nc", "empty", NC, seq(), "")
    val("p-nc", "empty-permitted", NC, seq(tlv(0xA0, b""), subtrees(0xA1, gn_dns(b"x"))), "\nExcluded:\n  DNS:x")
    val("p-nc", "min-max", NC, seq(subtrees(0xA0, gn_email(b"e") + tlv(0x80, b"\x00") + tlv(0x81, b"\x05"))),
        "Permitted:\n  email:e")

    # Issuing distribution point (multiline, i2r).
    IDP = "2.5.29.28"
    val("p-idp", "empty", IDP, seq(), "<EMPTY>\n")
    val("p-idp", "flags", IDP, seq(tlv(0x81, b"\xff"), tlv(0x82, b"\x01"), tlv(0x83, b"\x07\x80"),
                                   tlv(0x84, b"\x01"), tlv(0x85, b"\x01")),
        "Only User Certificates\nOnly CA Certificates\nIndirect CRL\nOnly Some Reasons:\n  Unused\n"
        "Only Attribute Certificates\n")
    val("p-idp", "false-flags", IDP, seq(tlv(0x81, b"\x00")), "<EMPTY>\n")
    val("p-idp", "name", IDP, seq(explicit(0, full(gn_uri(b"u")))), "Full Name:\n  URI:u")

    # Certificate Transparency.
    SCTS, POISON, CSCTS = "1.3.6.1.4.1.11129.2.4.2", "1.3.6.1.4.1.11129.2.4.3", "1.3.6.1.4.1.11129.2.4.5"

    def sct(version=0, log_id=bytes(range(32)), ts=1577836800123, ext_=b"", hash_sig=(4, 3), sig=b"\xde\xad"):
        if version != 0:
            return bytes([version]) + log_id
        return (bytes([0]) + log_id + ts.to_bytes(8, "big") + len(ext_).to_bytes(2, "big") + ext_
                + bytes(hash_sig) + len(sig).to_bytes(2, "big") + sig)

    def sct_list(*scts):
        body = b"".join(len(s).to_bytes(2, "big") + s for s in scts)
        return octet(len(body).to_bytes(2, "big") + body)

    def sct_text(log_id=bytes(range(32)), ts="Jan  1 00:00:00.123 2020 GMT", ext_=b"", alg="ecdsa-with-SHA256",
                 sig=b"\xde\xad"):
        return ("Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n    Log ID    : " + hex_string(log_id)
                + "\n    Timestamp : " + ts + "\n    Extensions: " + (hex_string(ext_) if ext_ else "none")
                + "\n    Signature : " + alg + "\n                " + hex_string(sig))

    val("p-ct", "one-sct", SCTS, sct_list(sct()), sct_text())
    val("p-ct", "two-scts", SCTS, sct_list(sct(), sct(hash_sig=(4, 1), ext_=b"\x01\x02", ts=0)),
        sct_text() + "\n" + sct_text(ts="Jan  1 00:00:00.000 1970 GMT", ext_=b"\x01\x02",
                                     alg="sha256WithRSAEncryption"))
    val("p-ct", "unknown-version", SCTS, sct_list(sct(version=1)),
        "Signed Certificate Timestamp:\n    Version   : unknown\n" + " " * 16
        + hex_string(bytes([1]) + bytes(range(32))))
    val("p-ct", "timestamp-past-9999", SCTS, sct_list(sct(ts=(1 << 64) - 1)), sct_text(ts=""))
    val("p-ct", "long-signature", SCTS, sct_list(sct(sig=bytes(range(40)))), sct_text(sig=bytes(range(40))))
    val("p-ct", "trailing-in-sct", SCTS, sct_list(sct() + b"\x99"), sct_text())
    val("p-ct", "empty-list", SCTS, octet(b"\x00\x00"), "")
    val("p-ct", "ocsp-scts", CSCTS, sct_list(sct()), sct_text())
    nokey("p-ct", "list-length", codes["CT_R_SCT_LIST_INVALID"], ext(SCTS, octet(b"\x00\x05\x00")))
    nokey("p-ct", "short-sct", codes["CT_R_SCT_INVALID"], ext(SCTS, sct_list(bytes(10))))
    nokey("p-ct", "bad-hash", codes["CT_R_SCT_INVALID_SIGNATURE"], ext(SCTS, sct_list(sct(hash_sig=(2, 3)))))
    nokey("p-ct", "not-octet", WRONG_TAG, ext(SCTS, seq()))
    val("p-ct", "poison", POISON, NULL, "NULL")
    nokey("p-ct", "poison-not-null", WRONG_TAG, ext(POISON, integer(0)))

    # The Russian sign tools.
    SST, IST = "1.2.643.100.111", "1.2.643.100.112"
    val("p-sign", "subject-tool", SST, utf8("tool"), "tool")
    val("p-sign", "subject-tool-nul", SST, utf8(b"to\x00ol"), "to")
    err("p-sign", "subject-tool-empty", SST, utf8(""))
    nokey("p-sign", "subject-tool-empty-raises", X509V3_NULL_PARAM, ext(SST, utf8("")))
    val("p-sign", "issuer-tool", IST, seq(utf8("a"), utf8("b"), utf8("c"), utf8(b"d\x00e")),
        b"signTool    : a\ncATool      : b\nsignToolCert: c\ncAToolCert  : d\x00e")
    nokey("p-sign", "issuer-tool-three", FIELD_MISSING, ext(IST, seq(utf8("a"), utf8("b"), utf8("c"))))

    # Admission (common PKI).
    ADM = "1.3.36.8.3.3"
    na = seq(oid("1.2.3.4"), ia5(b"http://na"), utf8("text"))
    pinfo = seq(explicit(0, seq(ia5(b"u2"))), seq(utf8("item1"), tlv(0x13, b"item\x012")),
                seq(oid("2.5.4.3"), oid("1.2.5")), tlv(0x13, b"reg"), octet(b"x"))
    val("p-adm", "full", ADM,
        seq(gn_dns(b"auth"), seq(seq(explicit(0, gn_email(b"e")), explicit(1, na), seq(pinfo)))),
        "admissionAuthority:\n  DNS:auth\nEntry 1:\n  admissionAuthority:\n    email:e\n"
        "namingAuthority:   admissionAuthorityId: undefined (1.2.3.4)\n  namingAuthorityText: text\n"
        "  namingAuthorityUrl: http://na\n  Profession Info Entry 1:\n    registrationNumber: reg\n"
        "  namingAuthority:     namingAuthorityUrl: u2\n    Info Entries:\n      item1\n      item.2\n"
        "    Profession OIDs:\n      commonName (2.5.4.3)\n      undefined (1.2.5)\n")
    val("p-adm", "minimal", ADM, seq(seq(seq(seq(seq(seq()))))),
        "Entry 1:\n  Profession Info Entry 1:\n    Info Entries:\n")
    err("p-adm", "empty-naming-authority", ADM, seq(seq(seq(explicit(1, seq()), seq()))))

    # The error queue: the first error raised wins, from any extension.
    nokey("p-queue", "first-of-two", WRONG_TAG, ext(KU, octet(b"x")), ext(SAN, seq(gn_dns(b"\x00"))))
    nokey("p-queue", "second-after-ok", X509V3_MALLOC, ext(KU, bits(b"\x80", 7)), ext(SAN, seq(gn_dns(b"\x00"))))
    nokey("p-queue", "raised-by-a-success", TOO_LARGE, ext(TLSF, seq(integer(1 << 64))), ext(KU, octet(b"x")))
    nokey("p-queue", "none-raised", DECODE, ext(KU, bits(b"\x80", 7)), ext("1.2.3.4", b""))
    return out


def k_rows():
    return (["k%05d\t%s %s\t%s" % (i + 1, fam, note, der.hex()) for i, (fam, note, der) in enumerate(rows())]
            + ["p%05d\t%s %s\t%s" % (i + 1, fam, note, der.hex())
               for i, (fam, note, der) in enumerate(printer_rows())])


def read_certs():
    head, xb, k = [], [], []
    for line in open(CERTS, encoding="ascii"):
        line = line.rstrip("\n")
        if line.startswith("#"):
            head.append(line)
        elif line.startswith(("k", "p")):
            k.append(line)
        elif line:
            xb.append(line)
    return head, xb, k


HEADER_K = ("# Rows k*: oracle/gen_m65_x509.py (step e: key types, Name values, extension"
            " framing; deterministic, the note ends with the row's expected outcome).")
HEADER_P = ("# Rows p*: oracle/gen_m65_x509.py (step e: the extension printers, one or two"
            " extensions a row; the note ends with the expected value, in hex, or outcome).")


def write():
    head, xb, _ = read_certs()
    head = [h for h in head if not h.startswith(("# Rows k*", "# Rows p*"))] + [HEADER_K, HEADER_P]
    # Everything is built before the file is opened, so a generator error
    # leaves the corpus as it was.
    rows_ = k_rows()
    text = "\n".join(head + xb + rows_) + "\n"
    with open(CERTS, "w", encoding="ascii") as fh:
        fh.write(text)
    print("m65_certs.txt: %d k rows, %d p rows" % (sum(r[0] == "k" for r in rows_),
                                                   sum(r[0] == "p" for r in rows_)))


def check():
    _, _, k = read_certs()
    if k != k_rows():
        sys.exit("FAIL: m65_certs.txt's k and p rows are not what gen_m65_x509.py writes; run it")
    print("m65_certs.txt: %d k and p rows current" % len(k))


def lua_str(b):
    """oracle/m65_core.lua's `str`: \\xHH for control bytes, `"`, `\\` and
    bytes past 0x7f; over 256 bytes, #LEN:FNV1A64."""
    if len(b) > 256:
        h = 0xCBF29CE484222325
        for c in b:
            h = ((h ^ c) * 1099511628211) & 0xFFFFFFFFFFFFFFFF
        return "#%d:%016x" % (len(b), h)
    return '"' + "".join("\\x%02x" % c if c < 0x20 or c == 0x7F or c >= 0x80 or c in b'"\\' else chr(c)
                         for c in b) + '"'


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
        if len(f) >= 5 and f[3] == "parse_ssl_certificate" and f[4].startswith(("der:k", "der:p")):
            case_of[f[0]] = f[4][4:]
    bad = 0
    for line in open(GOLDEN, encoding="utf-8", errors="replace"):
        f = line.rstrip("\n").split("\t")
        if f[0] not in case_of:
            continue
        cid = case_of[f[0]]
        want, note = expect[cid]
        got = f[2] if len(f) > 2 else ""
        if want.startswith("value:"):
            ok = got.startswith("cert<") and ('"value"=%s}' % lua_str(bytes.fromhex(want[6:]))) in got
        elif want == "error":
            ok = got.startswith("cert<") and '"error"=true' in got
        elif want.startswith("nokey:"):
            ok = got.startswith('nil "Error parsing cert: error:%s:' % want[6:])
        elif want == "reject":
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
        sys.exit("FAIL: %d k and p rows differ from what they expect" % bad)
    print("m65 golden: every k and p row as it expects (%d)" % len(expect))


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
