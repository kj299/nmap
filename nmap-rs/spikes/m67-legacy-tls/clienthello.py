#!/usr/bin/env python3
"""M6.7 step 0: the ClientHello nmap 7.94 and the port send, side by side
(docs/M6.7-ANALYSIS.md D3, §13).

    python3 spikes/m67-legacy-tls/clienthello.py [OUTDIR]

A listener on 127.0.0.1 reads the first TLS record of each connection that
sends one, parses the ClientHello in it and closes. Each program connects once
through the M6.5 probe script (`m65_tls/s0probe.nse`, mode host), which then
fails, as it should. What is printed is the part of the hello that does not
change between runs: the record and client versions, the cipher suites in
order, the compression methods, the extensions in order (by name or number),
and the contents of supported_versions, supported_groups,
signature_algorithms, ec_point_formats, psk_key_exchange_modes and the groups
of key_share. The random, the session id, the key shares themselves and the
SNI are left out. With OUTDIR, each program's lines go to
OUTDIR/clienthello_<program>.txt.
"""
import os
import socket
import struct
import subprocess
import sys
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
NMAP_RS = os.path.abspath(os.path.join(HERE, "..", ".."))
REPO = os.path.dirname(NMAP_RS)
PROBE = os.path.join(NMAP_RS, "tests", "differential", "m6", "m65_tls", "s0probe.nse")
PORT = int(os.environ.get("M67_HELLO_PORT", "52990"))

EXT = {0: "server_name", 5: "status_request", 10: "supported_groups", 11: "ec_point_formats",
       13: "signature_algorithms", 16: "alpn", 18: "signed_certificate_timestamp",
       21: "padding", 22: "encrypt_then_mac", 23: "extended_master_secret",
       35: "session_ticket", 43: "supported_versions", 45: "psk_key_exchange_modes",
       49: "post_handshake_auth", 50: "signature_algorithms_cert", 51: "key_share",
       0xff01: "renegotiation_info"}
GROUP = {23: "secp256r1", 24: "secp384r1", 25: "secp521r1", 29: "x25519", 30: "x448",
         256: "ffdhe2048", 257: "ffdhe3072", 258: "ffdhe4096", 259: "ffdhe6144",
         260: "ffdhe8192"}
SIG = {0x0401: "rsa_pkcs1_sha256", 0x0501: "rsa_pkcs1_sha384", 0x0601: "rsa_pkcs1_sha512",
       0x0403: "ecdsa_secp256r1_sha256", 0x0503: "ecdsa_secp384r1_sha384",
       0x0603: "ecdsa_secp521r1_sha512", 0x0804: "rsa_pss_rsae_sha256",
       0x0805: "rsa_pss_rsae_sha384", 0x0806: "rsa_pss_rsae_sha512", 0x0807: "ed25519",
       0x0808: "ed448", 0x0809: "rsa_pss_pss_sha256", 0x080a: "rsa_pss_pss_sha384",
       0x080b: "rsa_pss_pss_sha512", 0x0201: "rsa_pkcs1_sha1", 0x0203: "ecdsa_sha1",
       0x0202: "dsa_sha1", 0x0302: "dsa_sha224", 0x0402: "dsa_sha256",
       0x0502: "dsa_sha384", 0x0602: "dsa_sha512", 0x0301: "rsa_pkcs1_sha224",
       0x0303: "ecdsa_sha224", 0x081a: "ecdsa_brainpoolP256r1tls13_sha256",
       0x081b: "ecdsa_brainpoolP384r1tls13_sha384",
       0x081c: "ecdsa_brainpoolP512r1tls13_sha512"}


def u16s(b):
    return [struct.unpack(">H", b[i:i + 2])[0] for i in range(0, len(b) - 1, 2)]


def name(table, v):
    return table.get(v, "0x%04x" % v)


def parse(rec):
    """The stable lines of a ClientHello record."""
    out = ["record_version 0x%04x" % struct.unpack(">H", rec[1:3])[0]]
    hs = rec[5:]
    body = hs[4:4 + int.from_bytes(hs[1:4], "big")]
    out.append("client_version 0x%04x" % struct.unpack(">H", body[0:2])[0])
    at = 2 + 32
    at += 1 + body[at]
    n = struct.unpack(">H", body[at:at + 2])[0]
    suites = u16s(body[at + 2:at + 2 + n])
    at += 2 + n
    out.append("suites %d" % len(suites))
    out += ["suite 0x%04x" % s for s in suites]
    nc = body[at]
    out.append("compression %s" % body[at + 1:at + 1 + nc].hex())
    at += 1 + nc
    end = at + 2 + struct.unpack(">H", body[at:at + 2])[0]
    at += 2
    while at < end:
        t, ln = struct.unpack(">HH", body[at:at + 4])
        data = body[at + 4:at + 4 + ln]
        at += 4 + ln
        out.append("ext %s" % name(EXT, t))
        if t == 43:
            out.append("  versions " + " ".join("0x%04x" % v for v in u16s(data[1:])))
        elif t == 10:
            out.append("  groups " + " ".join(name(GROUP, g) for g in u16s(data[2:])))
        elif t in (13, 50):
            out.append("  sigalgs " + " ".join(name(SIG, g) for g in u16s(data[2:])))
        elif t == 11:
            out.append("  formats " + data[1:].hex())
        elif t == 45:
            out.append("  modes " + data[1:].hex())
        elif t == 51:
            shares, i = [], 2
            while i + 4 <= len(data):
                g, kl = struct.unpack(">HH", data[i:i + 4])
                shares.append(name(GROUP, g))
                i += 4 + kl
            out.append("  shares " + " ".join(shares))
        elif t == 22 or t == 23:
            out.append("  empty %s" % (ln == 0))
    return out


def capture(binary):
    got = []
    srv = socket.socket()
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", PORT))
    srv.listen(8)
    srv.settimeout(0.5)
    stop = threading.Event()

    def loop():
        while not stop.is_set():
            try:
                c, _ = srv.accept()
            except OSError:
                continue
            c.settimeout(3)
            try:
                head = c.recv(5, socket.MSG_WAITALL)
                if len(head) == 5 and head[0] == 22:
                    n = struct.unpack(">H", head[3:5])[0]
                    got.append(head + c.recv(n, socket.MSG_WAITALL))
            except OSError:
                pass
            c.close()
    t = threading.Thread(target=loop, daemon=True)
    t.start()
    subprocess.run([binary, "-Pn", "-sT", "-n", "-p", str(PORT), "127.0.0.1", "--datadir", REPO,
                    "--script", PROBE, "--script-args", "mode=host,timeout=2000"],
                   capture_output=True, timeout=120)
    stop.set()
    t.join()
    srv.close()
    return parse(got[0]) if got else ["no ClientHello"]


def main():
    progs = [("794", "nmap"), ("port", os.path.join(NMAP_RS, "target", "release", "nmap-rs"))]
    res = {k: capture(b) for k, b in progs}
    if len(sys.argv) > 1:
        for k, lines in res.items():
            with open(os.path.join(sys.argv[1], "clienthello_%s.txt" % k), "w") as fh:
                fh.write("\n".join(lines) + "\n")
    for k, lines in res.items():
        print("== %s (%d lines)" % (k, len(lines)))
        print("\n".join(lines))


if __name__ == "__main__":
    main()
