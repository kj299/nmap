#!/usr/bin/env python3
"""The step-0 fixture run: every fixture server is started on loopback, nmap
7.94 (the oracle, through s0probe.nse) and then the spike's `tlsprobe` connect
to it, and what each saw is recorded, with the server's own observation where
the server is the thing measuring (the fake TLS 1.2 server, the TLS 1.3 server
with the corrupt CertificateVerify).

    run.py OUTDIR            writes OUTDIR/results.tsv, results.md, logs/

Environment: TLSPROBE and BADSERVER name the spike binaries (default: the
release build under $CARGO_TARGET_DIR or target/); NMAP (default
/usr/bin/nmap); DATADIR (default /home/user/nmap, this tree's nselib).
"""
import os
import re
import socket
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
CERTS = os.path.join(HERE, "certs")
TARGET = os.environ.get("CARGO_TARGET_DIR", os.path.join(HERE, "..", "target"))
PROBE = os.environ.get("TLSPROBE", os.path.join(TARGET, "release", "tlsprobe"))
BADSERVER = os.environ.get("BADSERVER", os.path.join(TARGET, "release", "badserver"))
NMAP = os.environ.get("NMAP", "/usr/bin/nmap")
DATADIR = os.environ.get("DATADIR", "/home/user/nmap")
OUT = sys.argv[1] if len(sys.argv) > 1 else os.path.join(HERE, "out")
ONLY = sys.argv[2:]  # fixture-name substrings, to run a subset
LOGS = os.path.join(OUT, "logs")
os.makedirs(LOGS, exist_ok=True)
BASE_PORT = 47100


def cert(name):
    return os.path.join(CERTS, name)


# (name, kind, server args, oracle mode, oracle extra args, probe args)
# kind: s_server | fake | bad13 | starttls | silent | none
FIXTURES = [
    # TLS 1.2 ECDHE with AEAD suites: what rustls can carry, forced one by one.
    ("tls12-ecdhe-rsa-aes128gcm", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", "host", "", ""),
    ("tls12-ecdhe-rsa-aes256gcm", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384", "host", "", ""),
    ("tls12-ecdhe-rsa-chacha", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305", "host", "", ""),
    ("tls12-ecdhe-ecdsa-aes128gcm", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256", "host", "", ""),
    ("tls12-ecdhe-ecdsa-aes256gcm", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", "host", "", ""),
    ("tls12-ecdhe-ecdsa-chacha", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305", "host", "", ""),
    ("tls12-ecdsa-p384-cert", "s_server", "ecp384 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", "host", "", ""),
    ("tls12-ecdsa-p521-cert", "s_server", "ecp521 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", "host", "", ""),
    ("tls12-group-p521", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384 -named_curve secp521r1", "host", "", ""),
    ("tls12-group-p384", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -named_curve secp384r1", "host", "", ""),
    ("tls12-group-p256", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -named_curve prime256v1", "host", "", ""),
    # ServerKeyExchange signature schemes, forced.
    ("tls12-sig-pss-sha256", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pss_rsae_sha256", "host", "", ""),
    ("tls12-sig-pss-sha512", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pss_rsae_sha512", "host", "", ""),
    ("tls12-sig-pkcs1-sha256", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pkcs1_sha256", "host", "", ""),
    ("tls12-sig-pkcs1-sha384", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pkcs1_sha384", "host", "", ""),
    ("tls12-sig-pkcs1-sha1", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0 -sigalgs rsa_pkcs1_sha1", "host", "", ""),
    # TLS 1.3: each suite and each group forced.
    ("tls13-aes128-x25519", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519", "host", "", ""),
    ("tls13-aes256-p256", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -groups P-256", "host", "", ""),
    ("tls13-chacha-p384", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups P-384", "host", "", ""),
    ("tls13-aes128-p521", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups P-521", "host", "", ""),
    ("tls13-x448", "s_server", "rsa2048 -tls1_3 -groups X448", "host", "", ""),
    ("tls13-ffdhe2048", "s_server", "rsa2048 -tls1_3 -groups ffdhe2048", "host", "", ""),
    ("tls13-ecdsa-p256", "s_server", "ecp256 -tls1_3", "host", "", ""),
    ("tls13-ecdsa-p384", "s_server", "ecp384 -tls1_3", "host", "", ""),
    ("tls13-ecdsa-p521", "s_server", "ecp521 -tls1_3", "host", "", ""),
    ("tls13-ed25519", "s_server", "ed25519 -tls1_3", "host", "", ""),
    ("tls13-sig-pss-sha384", "s_server", "rsa2048 -tls1_3 -sigalgs rsa_pss_rsae_sha384", "host", "", ""),
    # Dual certificates: which leaf each client gets.
    ("dual-tls12-clientpref", "s_server", "rsa2048 -dcert CERTS/ecp256.crt -dkey CERTS/ecp256.key -tls1_2", "host", "", ""),
    ("dual-tls12-serverpref", "s_server", "rsa2048 -dcert CERTS/ecp256.crt -dkey CERTS/ecp256.key -tls1_2 -serverpref", "host", "", ""),
    ("dual-tls13", "s_server", "rsa2048 -dcert CERTS/ecp256.crt -dkey CERTS/ecp256.key -tls1_3", "host", "", ""),
    # STARTTLS: legacy (RSA key exchange, CBC) and modern.
    ("starttls-legacy", "starttls", "AES128-SHA:@SECLEVEL=0 tls12", "starttls", "", "--starttls smtp"),
    ("starttls-modern", "starttls", "ECDHE-RSA-AES128-GCM-SHA256 tls12", "starttls", "", "--starttls smtp"),
    # Weak and odd certificates 7.94 accepts.
    ("rsa512", "s_server", "rsa512 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ""),
    ("rsa1024-md5cert", "s_server", "rsamd5 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ""),
    ("rsa-sha1-signed-cert", "s_server", "rsasha1 -tls1_3", "host", "", ""),
    ("secp256k1-cert", "s_server", "ecsecp256k1 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ""),
    ("dsa-dhe", "s_server", "dsa2048 -tls1_2 -cipher DHE-DSS-AES128-GCM-SHA256:@SECLEVEL=0 -dhparam CERTS/dh2048.pem", "host", "", ""),
    # Chains past rustls's 64 KiB handshake-message limit and OpenSSL's 100 KiB list limit.
    ("chain-over64k", "s_server", "rsa2048 -cert_chain CERTS/chain_over64k.pem -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", "host", "", ""),
    ("chain-over100k", "s_server", "rsa2048 -cert_chain CERTS/chain_over100k.pem -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", "host", "", ""),
    ("chain13-over64k", "s_server", "rsa2048 -cert_chain CERTS/chain_over64k.pem -tls1_3", "host", "", ""),
    # SNI: a host table sends none; a string sends it, IP literals included.
    ("sni-ip-string", "s_server", "rsa2048 -tls1_3", "ipstr", "", "--ip"),
    ("sni-name", "s_server", "rsa2048 -tls1_3", "name", "name=localhost", "--name localhost"),
    # Legacy reach, for the pins in both directions.
    ("tls10-only", "s_server", "rsa2048 -tls1 -cipher ALL:@SECLEVEL=0", "host", "", ""),
    ("tls11-only", "s_server", "rsa2048 -tls1_1 -cipher ALL:@SECLEVEL=0", "host", "", ""),
    ("tls12-rsa-kx-gcm", "s_server", "rsa2048 -tls1_2 -cipher AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ""),
    ("tls12-ecdhe-cbc", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-SHA", "host", "", ""),
    ("tls12-dhe2048", "s_server", "rsa2048 -tls1_2 -cipher DHE-RSA-AES128-GCM-SHA256 -dhparam CERTS/dh2048.pem", "host", "", ""),
    # The negative fixtures, TLS 1.2 (the fake server observes the client).
    ("fake-ok", "fake", "ok rsa2048.der rsa2048.key", "host", "", ""),
    ("fake-badsig", "fake", "badsig rsa2048.der rsa2048.key", "host", "", ""),
    ("fake-trail", "fake", "trail rsa2048.der rsa2048.key", "host", "", ""),
    ("fake-garbage", "fake", "garbage rsa2048.der rsa2048.key", "host", "", ""),
    ("fake-noreneg", "fake", "noreneg rsa2048.der rsa2048.key", "host", "", ""),
    ("fake-ecdsa-cert-rsa-suite", "fake", "subst rsa2048.der rsa2048.key ecp256.der", "host", "", ""),
    ("fake-ed25519-cert-rsa-suite", "fake", "subst rsa2048.der rsa2048.key ed25519.der", "host", "", ""),
    ("fake-x25519-cert", "fake", "subst rsa2048.der rsa2048.key x25519.der", "host", "", ""),
    ("fake-dh-cert", "fake", "subst rsa2048.der rsa2048.key dh.der", "host", "", ""),
    ("fake-unknownoid-cert", "fake", "subst rsa2048.der rsa2048.key unknownoid.der", "host", "", ""),
    # The negative fixture, TLS 1.3: a corrupt CertificateVerify.
    ("bad13-control", "bad13", "", "host", "", ""),
    ("bad13-corrupt-certverify", "bad13", "--corrupt", "host", "", ""),
    # Liveness: a server that never speaks, and no server at all.
    ("silent-server", "silent", "", "host", "timeout=3000", "--timeout 3"),
    ("connection-refused", "none", "", "host", "", ""),
]


def wait_port(port, seconds=5.0):
    end = time.time() + seconds
    while time.time() < end:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                return True
        except OSError:
            time.sleep(0.05)
    return False


def start(kind, args, port, log):
    if kind == "none":
        return None
    if kind == "s_server":
        parts = args.replace("CERTS/", CERTS + "/").split()
        certname, rest = parts[0], parts[1:]
        cmd = ["openssl", "s_server", "-accept", str(port), "-trace",
               "-cert", cert(certname + ".crt"), "-key", cert(certname + ".key")] + rest
    elif kind == "fake":
        parts = args.split()
        cmd = ["python3", os.path.join(HERE, "fakesrv.py"), str(port), parts[0], cert(parts[1]), cert(parts[2])]
        if len(parts) > 3:
            cmd.append(cert(parts[3]))
    elif kind == "bad13":
        cmd = [BADSERVER, str(port), cert("ecp256.der"), cert("ecp256.scalar")] + args.split()
    elif kind == "silent":
        cmd = ["python3", os.path.join(HERE, "silent.py"), str(port)]
    elif kind == "starttls":
        cmd = ["python3", os.path.join(HERE, "starttls_smtp.py"), str(port), cert("rsa2048.crt"), cert("rsa2048.key")] + args.split()
    else:
        raise ValueError(kind)
    p = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=log, stderr=subprocess.STDOUT)
    if not wait_port(port):
        raise RuntimeError(f"server for port {port} did not come up: {' '.join(cmd)}")
    return p


def oracle(port, mode, extra, log):
    sargs = f"mode={mode}" + (f",{extra}" if extra else "")
    cmd = [NMAP, "-Pn", "-sT", "-n", "-p", str(port), "127.0.0.1", "--datadir", DATADIR,
           "--script", os.path.join(HERE, "s0probe.nse"), "--script-args", sargs]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return "fail (nmap timed out after 90 s)"
    log.write(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    m = re.search(r"R: (.*)", r.stdout)
    if not m:
        state = re.search(r"\d+/tcp\s+(\S+)", r.stdout)
        return f"fail (no script result; port {state.group(1) if state else '?'})"
    return m.group(1).strip()


def probe(port, pargs, log):
    cmd = [PROBE, str(port)] + pargs.split()
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        return "FAIL (tlsprobe timed out after 60 s)"
    log.write(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    return (r.stdout.strip().splitlines() or ["(no output)"])[-1]


def server_lines(path):
    try:
        with open(path, errors="replace") as f:
            lines = [l.strip() for l in f if l.strip() and not l.startswith("listening")]
    except OSError:
        return []
    return lines


def sni_seen(path):
    """The server_name values in an s_server trace, one per ClientHello."""
    seen = []
    try:
        text = open(path, errors="replace").read()
    except OSError:
        return seen
    for m in re.finditer(r"extension_type=server_name\(0\), length=\d+\n(.*?)\n\s+extension_type", text, re.S):
        hn = re.search(r'"([^"]*)"', m.group(1)) or re.search(r"HostName:\s*(\S+)", m.group(1))
        seen.append(hn.group(1) if hn else m.group(1).strip().replace("\n", " ")[:60])
    hellos = len(re.findall(r"ClientHello,", text))
    return seen, hellos


def main():
    rows = []
    port = BASE_PORT
    for name, kind, args, omode, oextra, pargs in FIXTURES:
        port += 1
        if ONLY and not any(o in name for o in ONLY):
            continue
        slog_path = os.path.join(LOGS, f"{name}.server.log")
        clog_path = os.path.join(LOGS, f"{name}.clients.log")
        with open(slog_path, "w") as slog, open(clog_path, "w") as clog:
            try:
                srv = start(kind, args, port, slog)
            except RuntimeError as e:
                rows.append((name, f"(server failed: {e})", "", ""))
                print(f"{name:32s} SERVER FAILED: {e}"[:160], flush=True)
                continue
            o = oracle(port, omode, oextra, clog)
            time.sleep(0.2)
            p = probe(port, pargs, clog)
            time.sleep(0.3)
            if srv is not None:
                srv.terminate()
                try:
                    srv.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    srv.kill()
        side = ""
        if kind in ("fake", "bad13", "starttls"):
            side = " | ".join(server_lines(slog_path)[:4])
        elif name.startswith("sni-"):
            seen, hellos = sni_seen(slog_path)
            side = f"server_name seen in {len(seen)} of {hellos} ClientHellos: {seen}"
        rows.append((name, o, p, side))
        print(f"{name:32s} 7.94: {o[:60]:60s} spike: {p[:70]}", flush=True)
    with open(os.path.join(OUT, "results.tsv"), "w") as f:
        f.write("fixture\tnmap 7.94\tspike\tserver side\n")
        for r in rows:
            f.write("\t".join(r) + "\n")
    with open(os.path.join(OUT, "results.md"), "w") as f:
        f.write("| fixture | nmap 7.94 | spike (rustls + first-party provider) | server side |\n|---|---|---|---|\n")
        for r in rows:
            f.write("| " + " | ".join(x.replace("|", "\\|") for x in r) + " |\n")


if __name__ == "__main__":
    main()
