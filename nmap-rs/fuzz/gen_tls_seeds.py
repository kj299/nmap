#!/usr/bin/env python3
"""Seeds for the TLS fuzz targets of M6.5 step f1, from the step-f1 fixtures
(tests/differential/m6/m65_tls/) and the verification vectors
(crates/sys/src/tls/testdata/vectors.txt). Re-run to regenerate:

    python3 fuzz/gen_tls_seeds.py

nse_tls_server_flight: what a server sends after a ClientHello. Each fixture
server (`openssl s_server` with a TLS 1.2 or 1.3 suite, a certificate type
or a long chain; the fake TLS 1.2 server in each mode) is sent the
ClientHello of Python's `ssl` (OpenSSL, offering every suite), and everything it sends back within
a second is the seed.

nse_tls_kx_aead (M6.7 step a): a selector byte, then a peer's key share
(X448's base point and a real share and the range edges 0, 1, p - 1 of each
FFDHE group, in both TLS versions' forms) or a TLS 1.2 record (each AEAD,
lengths about the nonce-and-tag minimum).

nse_tls_verifier: flags, scheme, then length-prefixed certificates (leaf
first, an empty one ends them), message and signature, as the target reads
them: each vector, and the fixture certificates with a byte appended, cut
short, or chained.
"""
import os
import socket
import ssl
import struct
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
M65 = os.path.join(HERE, "..", "tests", "differential", "m6", "m65_tls")
CERTS = os.path.join(M65, "certs")
VECTORS = os.path.join(HERE, "..", "crates", "sys", "src", "tls", "testdata", "vectors.txt")
FLIGHT = os.path.join(HERE, "seeds", "nse_tls_server_flight")
VERIFIER = os.path.join(HERE, "seeds", "nse_tls_verifier")
KX_AEAD = os.path.join(HERE, "seeds", "nse_tls_kx_aead")
PORT = 47399


def client_hello():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    # Every suite OpenSSL has, so each fixture server finds its forced one
    # (CCM-8 and ARIA-GCM are not in Python's default list).
    ctx.set_ciphers("ALL:@SECLEVEL=0")
    inc, out = ssl.MemoryBIO(), ssl.MemoryBIO()
    obj = ctx.wrap_bio(inc, out, server_hostname="fuzz.test")
    try:
        obj.do_handshake()
    except ssl.SSLWantReadError:
        pass
    return out.read()


def flight(cmd):
    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        for _ in range(100):
            try:
                s = socket.create_connection(("127.0.0.1", PORT), timeout=0.2)
                break
            except OSError:
                time.sleep(0.05)
        else:
            raise SystemExit("server did not come up: %s" % cmd)
        s.settimeout(1.0)
        s.sendall(client_hello())
        got = b""
        try:
            while True:
                d = s.recv(65536)
                if not d:
                    break
                got += d
        except socket.timeout:
            pass
        s.close()
        return got
    finally:
        proc.terminate()
        proc.wait()


def s_server(cert, *args):
    return ["openssl", "s_server", "-accept", str(PORT), "-cert", os.path.join(CERTS, cert + ".crt"),
            "-key", os.path.join(CERTS, cert + ".key"), "-quiet"] + list(args)


def fake(mode, *subst):
    return [sys.executable, os.path.join(M65, "fakesrv.py"), str(PORT), mode,
            os.path.join(CERTS, "rsa2048.der"), os.path.join(CERTS, "rsa2048.key")] + \
           [os.path.join(CERTS, s) for s in subst]


FLIGHTS = {
    "tls12-ecdhe-rsa": s_server("rsa2048", "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256"),
    "tls12-ecdhe-ecdsa": s_server("ecp256", "-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"),
    "tls12-ecdsa-p384": s_server("ecp384", "-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"),
    "tls12-ecdsa-p521": s_server("ecp521", "-tls1_2", "-cipher", "ECDHE-ECDSA-AES256-GCM-SHA384"),
    "tls12-pkcs1": s_server("rsa2048", "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
                            "-sigalgs", "rsa_pkcs1_sha256"),
    "tls12-group-p521": s_server("rsa2048", "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
                                 "-named_curve", "secp521r1"),
    "tls12-chain": s_server("rsa2048", "-tls1_2", "-cipher", "ECDHE-RSA-AES128-GCM-SHA256",
                            "-cert_chain", os.path.join(CERTS, "chain_over64k.pem")),
    "tls13-rsa": s_server("rsa2048", "-tls1_3"),
    "tls13-p256-hrr": s_server("rsa2048", "-tls1_3", "-groups", "P-256"),
    "tls13-ed25519": s_server("ed25519", "-tls1_3"),
    # M6.7 step a: DHE (an RFC 7919 group and one of the server's own), CCM-8,
    # ARIA-GCM, and TLS 1.3 HelloRetryRequests for X448 and FFDHE.
    "tls12-dhe-ffdhe2048": s_server("rsa2048", "-tls1_2", "-cipher", "DHE-RSA-AES128-GCM-SHA256",
                                    "-dhparam", os.path.join(CERTS, "ffdhe2048.pem")),
    "tls12-dhe-own2048": s_server("rsa2048", "-tls1_2", "-cipher", "DHE-RSA-AES128-GCM-SHA256",
                                  "-dhparam", os.path.join(CERTS, "dh2048.pem")),
    "tls12-ccm8": s_server("ecp256", "-tls1_2", "-cipher", "ECDHE-ECDSA-AES128-CCM8"),
    "tls12-aria": s_server("rsa2048", "-tls1_2", "-cipher", "ECDHE-ARIA128-GCM-SHA256"),
    "tls13-x448-hrr": s_server("rsa2048", "-tls1_3", "-groups", "X448"),
    # M6.7 step c: RSA key exchange, a TLS 1.2 flight with no ServerKeyExchange.
    "tls12-rsa-kx": s_server("rsa2048", "-tls1_2", "-cipher", "AES128-GCM-SHA256:@SECLEVEL=0"),
    "tls13-ffdhe2048-hrr": s_server("rsa2048", "-tls1_3", "-groups", "ffdhe2048"),
    "fake-ok": fake("ok"),
    "fake-badsig": fake("badsig"),
    "fake-trail": fake("trail"),
    "fake-garbage": fake("garbage"),
    "fake-noreneg": fake("noreneg"),
    "fake-ecdsa": fake("subst", "ecp256.der"),
    "fake-ed25519": fake("subst", "ed25519.der"),
    "fake-x25519": fake("subst", "x25519.der"),
    "fake-dh": fake("subst", "dh.der"),
    "fake-unknownoid": fake("subst", "unknownoid.der"),
}

SCHEMES = {
    "RSA_PKCS1_SHA256": 0x0401, "RSA_PKCS1_SHA384": 0x0501, "RSA_PKCS1_SHA512": 0x0601,
    "RSA_PSS_SHA256": 0x0804, "RSA_PSS_SHA384": 0x0805, "RSA_PSS_SHA512": 0x0806,
    "ECDSA_NISTP256_SHA256": 0x0403, "ECDSA_NISTP384_SHA384": 0x0503,
    "ECDSA_NISTP521_SHA512": 0x0603, "ED25519": 0x0807,
}


def lp(b):
    return struct.pack(">H", len(b)) + b


def verifier_seed(flags, scheme, chain, msg, sig):
    return bytes([flags]) + struct.pack(">H", scheme) + b"".join(lp(c) for c in chain) + \
        lp(b"") + lp(msg) + lp(sig)


def ffdhe_prime(bits):
    """The RFC 7919 prime of a group: the first INTEGER of the DHParameter
    OpenSSL writes for it."""
    import base64
    pem = subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt",
                          "group:ffdhe%d" % bits], capture_output=True, text=True, check=True).stdout
    der = base64.b64decode("".join(l for l in pem.splitlines() if not l.startswith("-----")))

    def tlv(b, at):
        tag, ln = b[at], b[at + 1]
        at += 2
        if ln & 0x80:
            k = ln & 0x7f
            ln = int.from_bytes(b[at:at + k], "big")
            at += k
        return tag, b[at:at + ln], at + ln

    tag, body, _ = tlv(der, 0)
    assert tag == 0x30
    tag, p, _ = tlv(body, 0)
    assert tag == 0x02
    return int.from_bytes(p, "big")


def kx_aead_seeds():
    five = bytes([5]) + bytes(55)
    write(KX_AEAD, "x448-base", bytes([0]) + five)
    write(KX_AEAD, "x448-zero", bytes([0]) + bytes(56))
    for i, bits in enumerate((2048, 3072, 4096, 6144, 8192), 1):
        p = ffdhe_prime(bits)
        n = bits // 8
        for tag, y in (("share", pow(2, 0x1234567, p)), ("zero", 0), ("one", 1), ("pm1", p - 1)):
            yb = y.to_bytes(n, "big")
            write(KX_AEAD, "ffdhe%d-%s-13" % (bits, tag), bytes([i]) + yb)
            write(KX_AEAD, "ffdhe%d-%s-12" % (bits, tag), bytes([i | 8]) + yb.lstrip(b"\0"))
    for sel in range(6):
        for n in (0, 15, 16, 24, 64):
            write(KX_AEAD, "aead%d-len%d" % (sel, n), bytes([0x80 | sel]) + bytes(range(n)))


def write(d, name, data):
    os.makedirs(d, exist_ok=True)
    with open(os.path.join(d, name), "wb") as fh:
        fh.write(data)


def main():
    for name, cmd in FLIGHTS.items():
        data = flight(cmd)
        if not data:
            raise SystemExit("%s: the server sent nothing" % name)
        write(FLIGHT, name, data)
    der = lambda n: open(os.path.join(CERTS, n), "rb").read()
    with open(VECTORS) as fh:
        for line in fh:
            if line.startswith("#"):
                continue
            name, scheme, cert, msg, sig, _ = line.split()
            for flags in (0, 1):
                write(VERIFIER, "%s-%d" % (name, flags),
                      verifier_seed(flags, SCHEMES[scheme], [bytes.fromhex(cert)],
                                    bytes.fromhex(msg), bytes.fromhex(sig)))
    rsa = der("rsa2048.der")
    write(VERIFIER, "trailing-byte", verifier_seed(0, 0x0804, [rsa + b"\0"], b"m", b"s"))
    write(VERIFIER, "cut-short", verifier_seed(0, 0x0804, [rsa[:-1]], b"m", b"s"))
    write(VERIFIER, "chain", verifier_seed(0, 0x0403, [der("ecp256.der"), rsa, der("ed25519.der")], b"m", b"s"))
    for c in ("x25519.der", "dh.der", "unknownoid.der", "ecp256.der", "ed25519.der"):
        write(VERIFIER, "key-" + c[:-4], verifier_seed(1, 0x0807, [der(c)], b"m", b"\0" * 64))
    kx_aead_seeds()
    print("seeds: %d flights, %d verifier inputs, %d kx/aead inputs"
          % (len(os.listdir(FLIGHT)), len(os.listdir(VERIFIER)), len(os.listdir(KX_AEAD))))


if __name__ == "__main__":
    main()
