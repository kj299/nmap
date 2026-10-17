#!/usr/bin/python3.12
"""Prototype: a corpus of DER certificates for nmap.socket.parse_ssl_certificate.

    /usr/bin/python3.12 gen_m65_certs.py OUT.tsv OBJECTS.txt

Rows: ID <TAB> hex(DER). Three kinds:
  * raw: a hand-rolled DER builder (no signature check happens in d2i_X509,
    so the signature is junk) with every OID OpenSSL names as a subject
    attribute and as an extension, odd string types, odd times, bad SPKIs;
  * lib: certificates built and signed by python-cryptography with every key
    type and the extension types it can build;
  * mut: truncations and byte flips of a valid certificate.
"""
import datetime
import random
import re
import sys

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import dsa, ec, ed448, ed25519, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

R = random.Random(0x6D65)


# --- a minimal DER encoder ------------------------------------------------------
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        b = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(b)]) + b
    return bytes([tag]) + ln + body


def seq(*xs):
    return tlv(0x30, b"".join(xs))


def set_(*xs):
    return tlv(0x31, b"".join(xs))


def oid(dotted):
    p = [int(x) for x in dotted.split(".")]
    out = bytearray()
    for v in ([40 * p[0] + p[1]] + p[2:]):
        enc = [v & 0x7F]
        v >>= 7
        while v:
            enc.append(0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(reversed(enc))
    return tlv(0x06, bytes(out))


def integer(v):
    b = v.to_bytes((v.bit_length() + 8) // 8 or 1, "big", signed=True)
    return tlv(0x02, b)


def name(*rdns):  # rdns: list of [(oid, tag, bytes)]
    return seq(*[set_(*[seq(oid(o), tlv(t, v)) for (o, t, v) in rdn]) for rdn in rdns])


KEY = rsa.generate_private_key(public_exponent=65537, key_size=2048)
SPKI_RSA = KEY.public_key().public_bytes(serialization.Encoding.DER,
                                         serialization.PublicFormat.SubjectPublicKeyInfo)
SHA256RSA = seq(oid("1.2.840.113549.1.1.11"), tlv(0x05, b""))
UTC = lambda s: tlv(0x17, s.encode())
GEN = lambda s: tlv(0x18, s.encode())
STD_NAME = name([("2.5.4.3", 0x0C, b"m65")])


def cert(subject=STD_NAME, issuer=STD_NAME, nb=UTC("200101000000Z"), na=UTC("300101000000Z"),
         spki=SPKI_RSA, exts=None, sigalg=SHA256RSA, version=2, serial=1):
    tbs = []
    if version is not None:
        tbs.append(tlv(0xA0, integer(version)))
    tbs += [integer(serial), sigalg, issuer, seq(nb, na), subject, spki]
    if exts is not None:
        tbs.append(tlv(0xA3, seq(*exts)))
    return seq(seq(*tbs), sigalg, tlv(0x03, b"\0" + bytes(64)))


def ext(o, value, critical=False):
    return seq(oid(o), *([tlv(0x01, b"\xff")] if critical else []), tlv(0x04, value))


rows = []


def add(kind, der):
    rows.append((kind, der))


# 1. every named OID as a subject attribute, and as an extension
objs = []
for line in open(sys.argv[2]):
    m = re.search(r"[=,] ([0-2](\.\d+)+)$", line.strip())
    if m:
        objs.append(m.group(1))
for o in sorted(set(objs)):
    add("attr " + o, cert(subject=name([(o, 0x0C, b"v")])))
    add("ext " + o, cert(exts=[ext(o, tlv(0x05, b""))]))
# 2. string types, multi-valued RDNs, duplicates, unknown OIDs, long values
for tag in (0x0C, 0x13, 0x16, 0x14, 0x1E, 0x1C, 0x12, 0x1A, 0x04, 0x02, 0x05):
    for v in (b"", b"abc", b"\x00a\x00b", "é€😀".encode("utf-8"), b"\xff\xfe", bytes(range(256))):
        add("strtype %02x" % tag, cert(subject=name([("2.5.4.3", tag, v)])))
add("dup-cn", cert(subject=name([("2.5.4.3", 0x0C, b"one")], [("2.5.4.3", 0x0C, b"two")])))
add("multi-rdn", cert(subject=name([("2.5.4.3", 0x0C, b"a"), ("2.5.4.10", 0x0C, b"b")])))
add("unknown-oids", cert(subject=name([("1.2.3.4.5", 0x0C, b"x")], [("1.2.3.4.5", 0x0C, b"y")],
                                      [("2.999.1", 0x0C, b"z")], [("1.3.6.1.4.1.99999.1.2.3", 0x0C, b"w")])))
add("empty-name", cert(subject=seq(), issuer=seq()))
for n in (64, 1000, 65535, 200000):
    add("long-cn %d" % n, cert(subject=name([("2.5.4.3", 0x0C, b"A" * n)])))
add("many-rdns", cert(subject=name(*[[("2.5.4.11", 0x0C, b"ou%d" % i)] for i in range(300)])))
# 3. times
TIMES = ["200101000000Z", "491231235959Z", "500101000000Z", "000101000000Z", "991231235959Z",
         "2001010000Z", "200101000000+0100", "200101000000", "201301000000Z", "200100000000Z",
         "200132000000Z", "200101240000Z", "200101006000Z", "200101000060Z", "2x0101000000Z", "", "Z"]
GTIMES = ["20500101000000Z", "19500101000000Z", "00010101000000Z", "99991231235959Z",
          "20200101000000.5Z", "20200101000000.123456Z", "20200101000000+0000", "202001010000Z",
          "20200229000000Z", "20210229000000Z", "20200101000000z", "2020010100000Z"]
for t in TIMES:
    add("utc " + t, cert(nb=UTC(t), na=UTC(t)))
for t in GTIMES:
    add("gen " + t, cert(nb=GEN(t), na=GEN(t)))
add("time-wrongtag", cert(nb=tlv(0x04, b"200101000000Z")))
# 4. versions, serials, sig algs, SPKIs
for v in (None, 0, 1, 2, 3, 255):
    add("version %s" % v, cert(version=v))
for s in (0, -1, 2**159, -(2**159), 2**200):
    add("serial %d" % s, cert(serial=s))
for so in ("1.2.840.113549.1.1.5", "1.2.840.113549.1.1.4", "1.2.840.10045.4.3.2",
           "1.3.101.112", "1.2.840.113549.1.1.10", "1.2.3.4", "1.2.840.10040.4.3"):
    add("sigalg " + so, cert(sigalg=seq(oid(so), tlv(0x05, b""))))
add("spki-unknown-alg", cert(spki=seq(seq(oid("1.2.3.4")), tlv(0x03, b"\0abc"))))
add("spki-rsa-garbage", cert(spki=seq(seq(oid("1.2.840.113549.1.1.1"), tlv(0x05, b"")), tlv(0x03, b"\0abc"))))
add("spki-ec-explicit-junk", cert(spki=seq(seq(oid("1.2.840.10045.2.1"), seq(integer(1))), tlv(0x03, b"\0\x04"))))
for e in (1, 3, 2**64 + 1):
    n = R.getrandbits(1024) | (1 << 1023) | 1
    add("rsa-e %d" % e, cert(spki=seq(seq(oid("1.2.840.113549.1.1.1"), tlv(0x05, b"")),
                                      tlv(0x03, b"\0" + seq(integer(n), integer(e))))))
# 5. certificates built by python-cryptography: every key type, real extensions
now = datetime.datetime(2024, 1, 1)
keys = [("rsa1024", rsa.generate_private_key(65537, 1024)), ("rsa2048", KEY),
        ("rsa4096", rsa.generate_private_key(65537, 4096)),
        ("dsa1024", dsa.generate_private_key(1024)), ("dsa2048", dsa.generate_private_key(2048)),
        ("ed25519", ed25519.Ed25519PrivateKey.generate()), ("ed448", ed448.Ed448PrivateKey.generate())]
for c in (ec.SECP256R1, ec.SECP384R1, ec.SECP521R1, ec.SECP256K1, ec.SECP224R1, ec.SECP192R1,
          ec.BrainpoolP256R1, ec.BrainpoolP384R1, ec.BrainpoolP512R1, ec.SECT283K1, ec.SECT571R1):
    keys.append(("ec-" + c.name, ec.generate_private_key(c())))
EXTS = [
    x509.SubjectAlternativeName([x509.DNSName("a.example"), x509.DNSName("*.b.example"),
                                 x509.IPAddress(__import__("ipaddress").ip_address("10.0.0.1")),
                                 x509.IPAddress(__import__("ipaddress").ip_address("::1")),
                                 x509.RFC822Name("x@y.example"),
                                 x509.UniformResourceIdentifier("http://u.example/p?q"),
                                 x509.RegisteredID(x509.ObjectIdentifier("1.2.3.4")),
                                 x509.DirectoryName(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "dn")])),
                                 x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x03upn")]),
    x509.BasicConstraints(ca=True, path_length=3),
    x509.KeyUsage(True, True, True, True, True, True, True, True, True),
    x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH,
                           x509.ObjectIdentifier("1.2.3.4.5")]),
    x509.NameConstraints(permitted_subtrees=[x509.DNSName("ok.example")],
                         excluded_subtrees=[x509.IPAddress(__import__("ipaddress").ip_network("10.0.0.0/8"))]),
    x509.CRLDistributionPoints([x509.DistributionPoint([x509.UniformResourceIdentifier("http://crl")], None, None, None)]),
    x509.AuthorityInformationAccess([x509.AccessDescription(x509.oid.AuthorityInformationAccessOID.OCSP,
                                                            x509.UniformResourceIdentifier("http://ocsp"))]),
    x509.CertificatePolicies([x509.PolicyInformation(x509.ObjectIdentifier("2.23.140.1.2.1"),
                                                     ["http://cps", x509.UserNotice(None, "notice text")])]),
    x509.PolicyConstraints(require_explicit_policy=1, inhibit_policy_mapping=2),
    x509.InhibitAnyPolicy(5),
    x509.TLSFeature([x509.TLSFeatureType.status_request]),
    x509.OCSPNoCheck(),
    x509.UnrecognizedExtension(x509.ObjectIdentifier("1.2.3.4.5.6"), b"\x04\x03abc"),
]
for kn, k in keys:
    b = (x509.CertificateBuilder()
         .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, kn),
                                  x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
                                  x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Ünïcødé Org")]))
         .issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "issuer")]))
         .public_key(k.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + datetime.timedelta(days=36500)))
    for i, e in enumerate(EXTS):
        b = b.add_extension(e, critical=(i % 3 == 0))
    algo = None if kn.startswith("ed") else hashes.SHA256()
    add("lib " + kn, b.sign(k, algo).public_bytes(serialization.Encoding.DER))
# 6. mutations of a valid certificate (robustness: nil vs table must match)
base = rows[-1][1]
for i in range(len(base)):
    if i % 7 == 0:
        add("trunc %d" % i, base[:i])
for _ in range(400):
    m = bytearray(base)
    for _ in range(R.randint(1, 4)):
        m[R.randrange(len(m))] = R.randrange(256)
    add("flip", bytes(m))
add("trailing", base + b"\0\0")
add("empty", b"")

with open(sys.argv[1], "w") as fh:
    for i, (kind, der) in enumerate(rows, 1):
        fh.write("x%05d\t%s\t%s\n" % (i, kind.replace("\t", " "), der.hex()))
print(len(rows), file=sys.stderr)
