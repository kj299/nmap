#!/usr/bin/env python3
"""Seeds for the TLS fuzz targets of M6.5 step f1, from the step-f1 fixtures
(tests/differential/m6/m65_tls/) and the verification vectors
(crates/sys/src/tls/testdata/vectors.txt). Re-run to regenerate:

    python3 fuzz/gen_tls_seeds.py

nse_tls_server_flight: what a server sends after a ClientHello. Each fixture
server (`openssl s_server` with a TLS 1.2 or 1.3 suite, a certificate type
or a long chain; the fake TLS 1.2 server in each mode) is sent the
ClientHello of Python's `ssl` (OpenSSL), and everything it sends back within
a second is the seed.

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
PORT = 47399


def client_hello():
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
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
    print("seeds: %d flights, %d verifier inputs" % (len(os.listdir(FLIGHT)), len(os.listdir(VERIFIER))))


if __name__ == "__main__":
    main()
