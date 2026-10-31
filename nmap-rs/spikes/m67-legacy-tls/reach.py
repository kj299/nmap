#!/usr/bin/env python3
"""M6.7 Phase 0: which legacy TLS families nmap 7.94 reaches and the port does
not (docs/M6.7-ANALYSIS.md §1, §13).

    python3 spikes/m67-legacy-tls/reach.py [NAME...]

Each row is an `openssl s_server` on loopback forced to one suite family; nmap
7.94 and the port's release binary (`target/release/nmap-rs`, built first)
each run the M6.5 probe script (`m65_tls/s0probe.nse`, mode host) against it
once, through gen_m65_tls.py's own server and client helpers, and the line
printed is "ok" (a handshake and a leaf) or the probe's failure, with what
the server saw. DH parameters are generated into a scratch directory: the
RFC 7919 groups, and a 1,024-bit group of the server's own. The SEED row
loads OpenSSL 3's legacy provider in the server.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
NMAP_RS = os.path.abspath(os.path.join(HERE, "..", ".."))
sys.path.insert(0, os.path.join(NMAP_RS, "tests", "differential", "m6", "oracle"))
import gen_m65_tls as g  # noqa: E402

BIN = os.path.join(NMAP_RS, "target", "release", "nmap-rs")
S = tempfile.mkdtemp(prefix="m67-reach-")
for grp in ("ffdhe2048", "ffdhe3072"):
    subprocess.run(["openssl", "genpkey", "-genparam", "-algorithm", "DH", "-pkeyopt",
                    "group:" + grp, "-out", os.path.join(S, grp + ".pem")], check=True,
                   capture_output=True)
subprocess.run(["openssl", "dhparam", "-out", os.path.join(S, "dh1024.pem"), "1024"],
               check=True, capture_output=True)
R = "rsa2048 -tls1_2 -cipher %s:@SECLEVEL=0"
E = "ecp256 -tls1_2 -cipher %s:@SECLEVEL=0"
D = "dsa2048 -tls1_2 -cipher %s:@SECLEVEL=0 -dhparam " + S + "/%s"
ROWS = [
 # RSA key exchange, every record protection 7.94 offers with it
 ("rsa-kx-aes128-gcm", R % "AES128-GCM-SHA256"),
 ("rsa-kx-aes128-cbc-sha", R % "AES128-SHA"),
 ("rsa-kx-aes256-cbc-sha256", R % "AES256-SHA256"),
 ("rsa-kx-aes128-ccm", R % "AES128-CCM"),
 ("rsa-kx-aria128-gcm", R % "ARIA128-GCM-SHA256"),
 ("rsa-kx-camellia128-sha", R % "CAMELLIA128-SHA"),
 ("rsa-kx-seed-sha", R % "SEED-SHA" + " -provider legacy -provider default"),
 ("rsa-kx-3des", R % "DES-CBC3-SHA"),
 # ECDHE with record protections the port lacks
 ("ecdhe-rsa-aes128-cbc-sha", R % "ECDHE-RSA-AES128-SHA"),
 ("ecdhe-rsa-aes256-cbc-sha384", R % "ECDHE-RSA-AES256-SHA384"),
 ("ecdhe-rsa-aria128-gcm", R % "ECDHE-ARIA128-GCM-SHA256"),
 ("ecdhe-rsa-camellia128-sha256", R % "ECDHE-RSA-CAMELLIA128-SHA256"),
 ("ecdhe-ecdsa-aes128-ccm", E % "ECDHE-ECDSA-AES128-CCM"),
 ("ecdhe-ecdsa-aes128-ccm8", E % "ECDHE-ECDSA-AES128-CCM8"),
 # DHE: RFC 7919 groups and a server's own parameters
 ("dhe-rsa-gcm-ffdhe2048", R % "DHE-RSA-AES128-GCM-SHA256" + " -dhparam " + S + "/ffdhe2048.pem"),
 ("dhe-rsa-gcm-ffdhe3072", R % "DHE-RSA-AES128-GCM-SHA256" + " -dhparam " + S + "/ffdhe3072.pem"),
 ("dhe-rsa-gcm-own2048", R % "DHE-RSA-AES128-GCM-SHA256" + " -dhparam CERTS/dh2048.pem"),
 ("dhe-rsa-gcm-own1024", R % "DHE-RSA-AES128-GCM-SHA256" + " -dhparam " + S + "/dh1024.pem"),
 ("dhe-rsa-cbc-ffdhe2048", R % "DHE-RSA-AES128-SHA" + " -dhparam " + S + "/ffdhe2048.pem"),
 ("dhe-rsa-chacha-ffdhe2048", R % "DHE-RSA-CHACHA20-POLY1305" + " -dhparam " + S + "/ffdhe2048.pem"),
 ("dhe-dss-gcm-ffdhe2048", D % ("DHE-DSS-AES128-GCM-SHA256", "ffdhe2048.pem")),
 # TLS 1.3 groups
 ("tls13-x448", "rsa2048 -tls1_3 -groups X448"),
 ("tls13-ffdhe2048", "rsa2048 -tls1_3 -groups ffdhe2048"),
 ("tls13-ffdhe4096", "rsa2048 -tls1_3 -groups ffdhe4096"),
 # versions
 ("tls11-only", "rsa2048 -tls1_1 -cipher ALL:@SECLEVEL=0"),
 ("tls10-only", "rsa2048 -tls1 -cipher ALL:@SECLEVEL=0"),
 ("ssl3-only", "rsa2048 -ssl3 -cipher ALL:@SECLEVEL=0"),
]
d = tempfile.mkdtemp()
for idx, (name, args) in enumerate(ROWS, 1):
    port = 53000 + idx
    if len(sys.argv) > 1 and name not in sys.argv[1:]:
        continue
    try:
      with open(os.path.join(d, name + ".log"), "w") as log:
        a, sa = g.serve_once(name, "s_server", args, port, None, d, "o", lambda: g.oracle(port, "host", "", log))
        b, sb = g.serve_once(name, "s_server", args, port, None, d, "p", lambda: g.port_cli(BIN, port, "host", "", log))
    except SystemExit as e:
        print("%-30s server did not start: %s" % (name, str(e)[:80]), flush=True)
        continue
    short = lambda r: "ok" if r.startswith("ok leaf=") else r
    print("%-30s 7.94=%-12s port=%-12s | %s" % (name, short(a), short(b), sa[:110]), flush=True)
