#!/usr/bin/env python3
"""A TLS 1.2 server that sends ServerHello, Certificate, ServerKeyExchange and
ServerHelloDone for TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 (0xc02f) and then
records what the client does next: a ClientKeyExchange means the client
accepted everything so far, an alert means it rejected something. Modes
mutate one thing each, as docs/M6.5-ANALYSIS.md §1.3 measured against 7.94:

    ok        nothing mutated (the control)
    badsig    one bit of the ServerKeyExchange signature flipped
    trail     one byte appended inside the certificate entry
    garbage   the certificate replaced by five bytes of nonsense
    noreneg   no renegotiation_info extension in the ServerHello
    subst     the certificate replaced by SUBST.der (signature still made
              with RSAKEY: a key-type mismatch, or a rejected key type)

usage: fakesrv.py PORT MODE CERT.der RSAKEY.pem [SUBST.der]
Serves connections one after another until killed; prints one line each. A
connection that never sends a ClientHello (a port probe, the generator's own
readiness check, a connect scan) prints a line starting "noise:"; one that
does prints a line starting "client ", which is what the generator records:

    client ClientKeyExchange   the client accepted the server's flight
    client alert N             the client sent fatal alert N
    client closed              the client closed without a record
    client reset               the client reset the connection
    client record type N       anything else

Copied from spikes/m65-tls-provider/fixtures/fakesrv.py (M6.5 step 0) for the
oracle of step a; only the reporting changed.
"""
import os
import socket
import struct
import subprocess
import sys

port = int(sys.argv[1])
mode = sys.argv[2]
der = open(sys.argv[3], "rb").read()
key = sys.argv[4]
subst = open(sys.argv[5], "rb").read() if len(sys.argv) > 5 else None


def rec(ct, body):
    return bytes([ct, 3, 3]) + struct.pack(">H", len(body)) + body


def hs(t, body):
    return bytes([t]) + len(body).to_bytes(3, "big") + body


def readrec(c):
    h = b""
    while len(h) < 5:
        d = c.recv(5 - len(h))
        if not d:
            return None, None
        h += d
    n = struct.unpack(">H", h[3:5])[0]
    b = b""
    while len(b) < n:
        d = c.recv(n - len(b))
        if not d:
            break
        b += d
    return h[0], b


def handle(c):
    try:
        ct, ch = readrec(c)
    except OSError as e:
        print("noise: error before ClientHello:", e.__class__.__name__, flush=True)
        return
    if ct != 22 or not ch or ch[0] != 1:
        print("noise: no ClientHello", flush=True)
        return
    crand = ch[6:38]
    sid_len = ch[38]
    p = 39 + sid_len
    cs_len = struct.unpack(">H", ch[p:p + 2])[0]
    suites = [ch[p + 2 + i:p + 4 + i] for i in range(0, cs_len, 2)]
    suite = b"\xc0\x2f"
    if suite not in suites:
        print("client did not offer c02f", flush=True)
        return
    srand = os.urandom(32)
    ext = b"" if mode == "noreneg" else b"\xff\x01\x00\x01\x00"
    sh = b"\x03\x03" + srand + b"\x00" + suite + b"\x00" + struct.pack(">H", len(ext)) + ext
    certbytes = subst if subst is not None else der
    if mode == "trail":
        certbytes = certbytes + b"\x00"
    if mode == "garbage":
        certbytes = b"\x30\x03\x02\x01\x01"
    centry = len(certbytes).to_bytes(3, "big") + certbytes
    cert = len(centry).to_bytes(3, "big") + centry
    pub = os.urandom(32)
    params = b"\x03\x00\x1d" + bytes([len(pub)]) + pub
    sig = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key], input=crand + srand + params, capture_output=True
    ).stdout
    if mode == "badsig":
        sig = bytes([sig[0] ^ 1]) + sig[1:]
    ske = params + b"\x04\x01" + struct.pack(">H", len(sig)) + sig
    try:
        c.sendall(rec(22, hs(2, sh) + hs(11, cert) + hs(12, ske) + hs(14, b"")))
        ct, b = readrec(c)
    except ConnectionResetError:
        print("client reset", flush=True)
        return
    if ct is None:
        print("client closed", flush=True)
    elif ct == 21:
        print("client alert %d" % b[1] + ("" if b[0] == 2 else " level=%d" % b[0]), flush=True)
    elif ct == 22 and b and b[0] == 16:
        print("client ClientKeyExchange", flush=True)
    elif ct == 22:
        print("client handshake type %d" % (b[0] if b else -1), flush=True)
    else:
        print("client record type %d" % ct, flush=True)


srv = socket.socket()
srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
srv.bind(("127.0.0.1", port))
srv.listen(5)
print("listening", flush=True)
while True:
    c, _ = srv.accept()
    c.settimeout(5)
    try:
        handle(c)
    except Exception as e:  # noqa: BLE001 - a fixture reports and carries on
        print("client error", e.__class__.__name__, flush=True)
    finally:
        c.close()
