#!/usr/bin/env python3
"""nmap 7.94 on the M6.5 TLS fixtures (step a): the oracle side of step f1's
gate.

    python3 oracle/gen_m65_tls.py OUTDIR [--once] [--carry GOLDEN]
        -> OUTDIR/m65_tls_golden.txt, from the installed nmap (7.94)
    python3 oracle/gen_m65_tls.py --check-header GOLDEN
        -> compares this machine's environment with the golden's header;
           exit 1 on any difference
    python3 oracle/gen_m65_tls.py --check GOLDEN --client CMD
        -> step f1 adds the port's side; today it checks the header, then
           exits 2

The fixtures are step 0's (spikes/m65-tls-provider/fixtures/run.py, written
up in docs/M6.5-ANALYSIS.md 14.1), committed in ../m65_tls/: every row of
run.py is here, with the same name. Each fixture server is started on
127.0.0.1, port BASE_PORT + its row number (47301-47361; nothing else in the
M6 generators uses 47xxx), and nmap 7.94 connects to it once, through
m65_tls/s0probe.nse, with --datadir set to this repository (located from
this file, as every M6 generator does):

    s_server   `openssl s_server -trace` with a suite, group, signature
               scheme, certificate or protocol version forced
    starttls   m65_tls/starttls_smtp.py: SMTP, then TLS over Python's `ssl`
    fake       m65_tls/fakesrv.py: a TLS 1.2 server flight with one thing
               mutated, recording the client's next record
    bad13      the spike's badserver: TLS 1.3 with the CertificateVerify
               corrupted on request (see "needs-badserver" below)
    silent     m65_tls/silent.py: accepts, never speaks
    none       nothing listens

Golden: a header of `#` lines, then one row per fixture, TAB-separated:

    NAME  TAGS  RESULT  SERVER

RESULT is what 7.94 saw, from the probe's `R:` line: `ok leaf=<sha256 of the
leaf DER> len=<bytes> cn=<commonName>`, `fail <socket error>` (ERROR,
TIMEOUT, ...), or `fail closed` when the port scan found nothing listening.

SERVER is what the fixture server saw of 7.94's connection, only fields that
are the same on every run:
  - s_server: `hello=` the number of ClientHellos (2 after a
    HelloRetryRequest), `sni=` the server_name of each (`-`: none), and from
    the last ServerHello and the server's key exchange `version=`, `suite=`,
    `group=`, `sigalg=`; `alerts=` the fatal alerts, `sent:` or `rcvd:`;
    `error=` the server's OpenSSL error reason;
  - fake: `client alert N`, `client ClientKeyExchange`, `client closed`, ...;
  - starttls: `tls VERSION CIPHER` or `tls failed: REASON`;
  - bad13: `handshake completed` or `client: received fatal alert: X`;
  - `-` where the server has nothing to say (silent, none).

TAGS is `-` or a comma-separated list:
  - needs-badserver: the server is the spike's Rust binary
    (spikes/m65-tls-provider/src/bin/badserver.rs, found through $BADSERVER,
    $CARGO_TARGET_DIR/release/badserver or the spike's own target/). Python's
    `ssl` cannot corrupt a CertificateVerify and `s_server` refuses a key
    that does not match its certificate, so the row is recorded from the
    binary when it is there. Without it, the row is copied from --carry
    GOLDEN when given (the regen script passes the committed golden), else
    written with RESULT `skipped` and a message on stderr; a `skipped` row
    is never compared.
  - nondet:<reason>: the row differs between runs of 7.94 itself, and is
    not compared (NONDET below; none so far).

Determinism is asserted, not assumed: OUTDIR mode runs the whole matrix
twice (about a minute in all) and refuses to write a golden if any untagged row
differs between the two runs; --once skips the second run.

The header's `# env` lines pin what 7.94's TLS reach depends on
(docs/M6.5-ANALYSIS.md 2, "Pinning the CI environment"); --check-header
compares them, and --check does so before anything else. The security level
is measured, not inferred: a fresh SSL_CTX from TLS_client_method() in the
libssl nmap links, with nsock's cipher list (CIPHERS_SECURE,
nsock/src/nsock_ssl.c at 7.94) applied, the configuration file loaded as
libssl loads it for nmap; seclevel-compiled is the -DOPENSSL_TLS_SECURITY_LEVEL
of `openssl version -a` (Ubuntu's patch; upstream's default is 1).

Environment: NMAP (default nmap), BADSERVER, M65_TLS_LOGS (a directory to
keep each fixture's server and client logs in).
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
NMAP_RS = os.path.abspath(os.path.join(M6, "..", "..", ".."))
REPO = os.path.abspath(os.path.join(M6, "..", "..", "..", ".."))
FIXDIR = os.path.join(M6, "m65_tls")
CERTS = os.path.join(FIXDIR, "certs")
PROBE = os.path.join(FIXDIR, "s0probe.nse")
NMAP = os.environ.get("NMAP", "nmap")
GOLDEN_NAME = "m65_tls_golden.txt"
BASE_PORT = 47300

# nsock's cipher list for an ordinary (not max-speed) pool, 7.94.
CIPHERS_SECURE = "ALL:!aNULL:!eNULL:!LOW:!EXP:!RC4:!MD5:@STRENGTH"

# Rows whose result differs between two runs of 7.94 itself: name -> reason.
# Their result is written but never compared. None found: seven full runs
# of the matrix agreed on every row.
NONDET = {}

# (name, kind, server args, probe mode, probe extra args, tags)
# The rows, names and server arguments of spikes/m65-tls-provider/fixtures/run.py.
FIXTURES = [
    # TLS 1.2 ECDHE with AEAD suites: what rustls can carry, forced one by one.
    ("tls12-ecdhe-rsa-aes128gcm", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", "host", "", ()),
    ("tls12-ecdhe-rsa-aes256gcm", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES256-GCM-SHA384", "host", "", ()),
    ("tls12-ecdhe-rsa-chacha", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-CHACHA20-POLY1305", "host", "", ()),
    ("tls12-ecdhe-ecdsa-aes128gcm", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256", "host", "", ()),
    ("tls12-ecdhe-ecdsa-aes256gcm", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", "host", "", ()),
    ("tls12-ecdhe-ecdsa-chacha", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-CHACHA20-POLY1305", "host", "", ()),
    ("tls12-ecdsa-p384-cert", "s_server", "ecp384 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", "host", "", ()),
    ("tls12-ecdsa-p521-cert", "s_server", "ecp521 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384", "host", "", ()),
    ("tls12-group-p521", "s_server", "ecp256 -tls1_2 -cipher ECDHE-ECDSA-AES256-GCM-SHA384 -named_curve secp521r1", "host", "", ()),
    ("tls12-group-p384", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -named_curve secp384r1", "host", "", ()),
    ("tls12-group-p256", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -named_curve prime256v1", "host", "", ()),
    # ServerKeyExchange signature schemes, forced.
    ("tls12-sig-pss-sha256", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pss_rsae_sha256", "host", "", ()),
    ("tls12-sig-pss-sha512", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pss_rsae_sha512", "host", "", ()),
    ("tls12-sig-pkcs1-sha256", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pkcs1_sha256", "host", "", ()),
    ("tls12-sig-pkcs1-sha384", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256 -sigalgs rsa_pkcs1_sha384", "host", "", ()),
    ("tls12-sig-pkcs1-sha1", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0 -sigalgs rsa_pkcs1_sha1", "host", "", ()),
    # TLS 1.3: each suite and each group forced.
    ("tls13-aes128-x25519", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups X25519", "host", "", ()),
    ("tls13-aes256-p256", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_AES_256_GCM_SHA384 -groups P-256", "host", "", ()),
    ("tls13-chacha-p384", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_CHACHA20_POLY1305_SHA256 -groups P-384", "host", "", ()),
    ("tls13-aes128-p521", "s_server", "rsa2048 -tls1_3 -ciphersuites TLS_AES_128_GCM_SHA256 -groups P-521", "host", "", ()),
    ("tls13-x448", "s_server", "rsa2048 -tls1_3 -groups X448", "host", "", ()),
    ("tls13-ffdhe2048", "s_server", "rsa2048 -tls1_3 -groups ffdhe2048", "host", "", ()),
    ("tls13-ecdsa-p256", "s_server", "ecp256 -tls1_3", "host", "", ()),
    ("tls13-ecdsa-p384", "s_server", "ecp384 -tls1_3", "host", "", ()),
    ("tls13-ecdsa-p521", "s_server", "ecp521 -tls1_3", "host", "", ()),
    ("tls13-ed25519", "s_server", "ed25519 -tls1_3", "host", "", ()),
    ("tls13-sig-pss-sha384", "s_server", "rsa2048 -tls1_3 -sigalgs rsa_pss_rsae_sha384", "host", "", ()),
    # Dual certificates: which leaf each client gets.
    ("dual-tls12-clientpref", "s_server", "rsa2048 -dcert CERTS/ecp256.crt -dkey CERTS/ecp256.key -tls1_2", "host", "", ()),
    ("dual-tls12-serverpref", "s_server", "rsa2048 -dcert CERTS/ecp256.crt -dkey CERTS/ecp256.key -tls1_2 -serverpref", "host", "", ()),
    ("dual-tls13", "s_server", "rsa2048 -dcert CERTS/ecp256.crt -dkey CERTS/ecp256.key -tls1_3", "host", "", ()),
    # STARTTLS: legacy (RSA key exchange, CBC) and modern.
    ("starttls-legacy", "starttls", "AES128-SHA:@SECLEVEL=0 tls12", "starttls", "", ()),
    ("starttls-modern", "starttls", "ECDHE-RSA-AES128-GCM-SHA256 tls12", "starttls", "", ()),
    # Weak and odd certificates 7.94 accepts.
    ("rsa512", "s_server", "rsa512 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ()),
    ("rsa2048-md5cert", "s_server", "rsamd5 -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ()),
    ("rsa-sha1-signed-cert", "s_server", "rsasha1 -tls1_3", "host", "", ()),
    ("secp256k1-cert", "s_server", "ecsecp256k1 -tls1_2 -cipher ECDHE-ECDSA-AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ()),
    ("dsa-dhe", "s_server", "dsa2048 -tls1_2 -cipher DHE-DSS-AES128-GCM-SHA256:@SECLEVEL=0 -dhparam CERTS/dh2048.pem", "host", "", ()),
    # Chains past rustls's 64 KiB handshake-message limit and OpenSSL's 100 KiB list limit.
    ("chain-over64k", "s_server", "rsa2048 -cert_chain CERTS/chain_over64k.pem -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", "host", "", ()),
    ("chain-over100k", "s_server", "rsa2048 -cert_chain CERTS/chain_over100k.pem -tls1_2 -cipher ECDHE-RSA-AES128-GCM-SHA256", "host", "", ()),
    ("chain13-over64k", "s_server", "rsa2048 -cert_chain CERTS/chain_over64k.pem -tls1_3", "host", "", ()),
    # SNI: a host table sends none; a string sends it, IP literals included.
    ("sni-ip-string", "s_server", "rsa2048 -tls1_3", "ipstr", "", ()),
    ("sni-name", "s_server", "rsa2048 -tls1_3", "name", "name=localhost", ()),
    # Legacy reach, for the pins in both directions.
    ("tls10-only", "s_server", "rsa2048 -tls1 -cipher ALL:@SECLEVEL=0", "host", "", ()),
    ("tls11-only", "s_server", "rsa2048 -tls1_1 -cipher ALL:@SECLEVEL=0", "host", "", ()),
    ("tls12-rsa-kx-gcm", "s_server", "rsa2048 -tls1_2 -cipher AES128-GCM-SHA256:@SECLEVEL=0", "host", "", ()),
    ("tls12-ecdhe-cbc", "s_server", "rsa2048 -tls1_2 -cipher ECDHE-RSA-AES128-SHA", "host", "", ()),
    ("tls12-dhe2048", "s_server", "rsa2048 -tls1_2 -cipher DHE-RSA-AES128-GCM-SHA256 -dhparam CERTS/dh2048.pem", "host", "", ()),
    # The negative fixtures, TLS 1.2 (the fake server observes the client).
    ("fake-ok", "fake", "ok rsa2048.der rsa2048.key", "host", "", ()),
    ("fake-badsig", "fake", "badsig rsa2048.der rsa2048.key", "host", "", ()),
    ("fake-trail", "fake", "trail rsa2048.der rsa2048.key", "host", "", ()),
    ("fake-garbage", "fake", "garbage rsa2048.der rsa2048.key", "host", "", ()),
    ("fake-noreneg", "fake", "noreneg rsa2048.der rsa2048.key", "host", "", ()),
    ("fake-ecdsa-cert-rsa-suite", "fake", "subst rsa2048.der rsa2048.key ecp256.der", "host", "", ()),
    ("fake-ed25519-cert-rsa-suite", "fake", "subst rsa2048.der rsa2048.key ed25519.der", "host", "", ()),
    ("fake-x25519-cert", "fake", "subst rsa2048.der rsa2048.key x25519.der", "host", "", ()),
    ("fake-dh-cert", "fake", "subst rsa2048.der rsa2048.key dh.der", "host", "", ()),
    ("fake-unknownoid-cert", "fake", "subst rsa2048.der rsa2048.key unknownoid.der", "host", "", ()),
    # The negative fixture, TLS 1.3: a corrupt CertificateVerify.
    ("bad13-control", "bad13", "", "host", "", ("needs-badserver",)),
    ("bad13-corrupt-certverify", "bad13", "--corrupt", "host", "", ("needs-badserver",)),
    # Liveness: a server that never speaks, and no server at all.
    ("silent-server", "silent", "", "host", "timeout=3000", ()),
    ("connection-refused", "none", "", "host", "", ()),
]


def cert(name):
    return os.path.join(CERTS, name)


def find_badserver():
    cands = []
    if os.environ.get("BADSERVER"):
        cands.append(os.environ["BADSERVER"])
    if os.environ.get("CARGO_TARGET_DIR"):
        cands.append(os.path.join(os.environ["CARGO_TARGET_DIR"], "release", "badserver"))
    cands.append(os.path.join(NMAP_RS, "spikes", "m65-tls-provider", "target", "release", "badserver"))
    for c in cands:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    return None


# ---------------------------------------------------------------- the header

def _run(cmd, **kw):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=30, **kw)
    except (OSError, subprocess.TimeoutExpired) as e:
        return subprocess.CompletedProcess(cmd, 127, "", str(e))


def nmap_libssl():
    """The libssl the nmap binary links, by ldd; None if it cannot be told."""
    path = shutil.which(NMAP) or NMAP
    r = _run(["ldd", path])
    m = re.search(r"libssl\.so\S*\s+=>\s+(\S+)", r.stdout)
    return m.group(1) if m else None


SECLEVEL_PROBE = r"""
import ctypes, sys
ssl = ctypes.CDLL(sys.argv[1])
ssl.TLS_client_method.restype = ctypes.c_void_p
ssl.SSL_CTX_new.restype = ctypes.c_void_p
ssl.SSL_CTX_new.argtypes = [ctypes.c_void_p]
ssl.SSL_CTX_get_security_level.argtypes = [ctypes.c_void_p]
ssl.SSL_CTX_set_cipher_list.argtypes = [ctypes.c_void_p, ctypes.c_char_p]
ctx = ssl.SSL_CTX_new(ssl.TLS_client_method())
if not ctx:
    sys.exit("SSL_CTX_new failed")
if ssl.SSL_CTX_set_cipher_list(ctx, sys.argv[2].encode()) != 1:
    sys.exit("SSL_CTX_set_cipher_list failed")
print(ssl.SSL_CTX_get_security_level(ctx))
"""


def environment():
    """The pinned environment, as an ordered list of (key, value)."""
    env = []
    r = _run([NMAP, "--version"])
    lines = r.stdout.splitlines()
    env.append(("nmap", lines[0] if lines else "unavailable (rc=%d)" % r.returncode))
    m = re.search(r"Compiled with:.*?\b(openssl-\S+)", r.stdout)
    env.append(("nmap-openssl", m.group(1) if m else "none"))
    r = _run(["openssl", "version"])
    env.append(("openssl-version", r.stdout.strip() or "unavailable"))
    r = _run(["openssl", "version", "-d"])
    env.append(("openssl-dir", r.stdout.strip() or "unavailable"))
    env.append(("OPENSSL_CONF", os.environ.get("OPENSSL_CONF", "unset")))
    lib = nmap_libssl()
    if lib is None:
        env.append(("seclevel", "unknown (no libssl in ldd of nmap)"))
    else:
        r = _run([sys.executable, "-I", "-c", SECLEVEL_PROBE, lib, CIPHERS_SECURE])
        env.append(("seclevel", r.stdout.strip() if r.returncode == 0
                    else "unknown (%s)" % (r.stderr.strip().splitlines() or ["?"])[-1]))
    r = _run(["openssl", "version", "-a"])
    m = re.search(r"-DOPENSSL_TLS_SECURITY_LEVEL=(\d+)", r.stdout)
    env.append(("seclevel-compiled", m.group(1) if m else "default (not set at build)"))
    r = _run(["openssl", "list", "-providers", "-provider", "legacy"])
    env.append(("legacy-provider", "loads" if r.returncode == 0 else "fails (rc=%d)" % r.returncode))
    r = _run([sys.executable, "-I", "-c", "import ssl; print(ssl.OPENSSL_VERSION)"])
    env.append(("python-ssl", r.stdout.strip() or "unavailable"))
    return env


def header_lines(env):
    out = [
        "# m65_tls_golden.txt: nmap 7.94 on the M6.5 TLS fixtures (m65_tls/), the oracle side",
        "# of step f1's gate. Generated by oracle/gen_m65_tls.py (see its docstring and the",
        "# README, \"M6.5 step a\"). Do not edit by hand.",
        "# Rows, TAB-separated: FIXTURE TAGS RESULT SERVER. RESULT is what 7.94 saw",
        "# (m65_tls/s0probe.nse); SERVER is what the fixture server saw of 7.94's connection.",
        "# TAGS: '-', needs-badserver (served by the spike's badserver binary), nondet:REASON",
        "# (not compared). A RESULT of 'skipped' is never compared.",
        "# The env lines pin the environment; --check-header compares them. seclevel is",
        "# SSL_CTX_get_security_level of a fresh TLS_client_method() context in the libssl nmap",
        "# links, after nsock's CIPHERS_SECURE; seclevel-compiled is -DOPENSSL_TLS_SECURITY_LEVEL",
        "# in `openssl version -a`.",
    ]
    out += ["# env %s: %s" % (k, v) for k, v in env]
    return out


def read_header(path):
    env = []
    with open(path) as fh:
        for line in fh:
            if not line.startswith("#"):
                break
            m = re.match(r"# env ([^:]+): (.*)$", line.rstrip("\n"))
            if m:
                env.append((m.group(1), m.group(2)))
    return env


def compare_header(golden_path):
    """Prints every difference between the golden's env lines and this
    machine's; returns the number of differences."""
    want = dict(read_header(golden_path))
    got = environment()
    bad = 0
    for k, v in got:
        if k not in want:
            print("header: %s: not in the golden (here: %s)" % (k, v))
            bad += 1
        elif want[k] != v:
            print("header mismatch: %s:\n  golden: %s\n  here:   %s" % (k, want[k], v))
            bad += 1
    for k in want:
        if k not in dict(got):
            print("header: %s: in the golden only (%s)" % (k, want[k]))
            bad += 1
    return bad


# ---------------------------------------------------------------- the servers

def listening(port):
    """Whether something listens on TCP `port`, read from /proc/net/tcp{,6}
    rather than by connecting: a readiness probe that connects is one more
    connection the fixture server would see and log."""
    for table in ("/proc/net/tcp", "/proc/net/tcp6"):
        try:
            with open(table) as fh:
                next(fh)
                for line in fh:
                    f = line.split()
                    if f[3] == "0A" and int(f[1].rsplit(":", 1)[1], 16) == port:
                        return True
        except OSError:
            continue
    return False


def wait_port(port, proc, seconds=10.0):
    end = time.time() + seconds
    while time.time() < end:
        if proc.poll() is not None:
            return False
        if listening(port):
            return True
        time.sleep(0.05)
    return False


def server_cmd(kind, args, port, badserver):
    if kind == "s_server":
        parts = args.replace("CERTS/", CERTS + "/").split()
        return ["openssl", "s_server", "-accept", str(port), "-trace",
                "-cert", cert(parts[0] + ".crt"), "-key", cert(parts[0] + ".key")] + parts[1:]
    if kind == "fake":
        parts = args.split()
        return [sys.executable, os.path.join(FIXDIR, "fakesrv.py"), str(port), parts[0],
                cert(parts[1]), cert(parts[2])] + [cert(p) for p in parts[3:]]
    if kind == "bad13":
        return [badserver, str(port), cert("ecp256.der"), cert("ecp256.scalar")] + args.split()
    if kind == "silent":
        return [sys.executable, os.path.join(FIXDIR, "silent.py"), str(port)]
    if kind == "starttls":
        return [sys.executable, os.path.join(FIXDIR, "starttls_smtp.py"), str(port),
                cert("rsa2048.crt"), cert("rsa2048.key")] + args.split()
    raise ValueError(kind)


def stop(proc):
    if proc is None or proc.poll() is not None:
        return
    proc.terminate()
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        proc.kill()
        proc.wait()


# ---------------------------------------------------------------- the oracle

def oracle(port, mode, extra, log):
    sargs = "mode=%s" % mode + ("," + extra if extra else "")
    cmd = [NMAP, "-Pn", "-sT", "-n", "-p", str(port), "127.0.0.1", "--datadir", REPO,
           "--script", PROBE, "--script-args", sargs]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
    except subprocess.TimeoutExpired:
        return "fail nmap-timeout"
    log.write(" ".join(cmd) + "\n" + r.stdout + r.stderr)
    m = re.search(r"R: (.*)", r.stdout)
    if m:
        return m.group(1).strip()
    state = re.search(r"^%d/tcp\s+(\S+)" % port, r.stdout, re.M)
    st = state.group(1) if state else "?"
    return "fail closed" if st == "closed" else "fail no-result port=%s" % st


# ------------------------------------------------- what the servers observed

def _sni(block_lines):
    """The host name in a server_name extension's hex dump."""
    data = bytearray()
    for l in block_lines:
        m = re.match(r"\s*[0-9a-f]{4} - ((?:[0-9a-f]{2}[ -])+)", l)
        if not m:
            break
        data += bytes.fromhex(m.group(1).replace("-", " "))
    # list length (2), name type (1), name length (2), name
    if len(data) >= 5:
        n = int.from_bytes(data[3:5], "big")
        return data[5:5 + n].decode("latin-1")
    return "?"


def observe_s_server(trace, errtext):
    """Reads an `s_server -trace` log: each handshake message starts with a
    `    NAME, Length=N` line, inside a `Sent Record` or `Received Record`."""
    lines = trace.split("\n")
    # Keep only the connections that sent a ClientHello: s_server ends each
    # connection with "CONNECTION CLOSED", and nmap's connect scan is one
    # that sends nothing.
    conns, cur = [], []
    for l in lines:
        cur.append(l)
        if l.startswith("CONNECTION CLOSED"):
            conns.append(cur)
            cur = []
    conns.append(cur)
    lines = [l for c in conns if any(re.match(r"    ClientHello, Length=", x) for x in c) for l in c]
    hellos = []        # per ClientHello: its server_name, or "-"
    sh = None          # the last ServerHello
    group = sigalg = None
    alerts = []
    direction = msg = None
    for i, l in enumerate(lines):
        if l.startswith("Received Record"):
            direction, msg = "rcvd", None
        elif l.startswith("Sent Record"):
            direction, msg = "sent", None
        m = re.match(r"    (\w+), Length=\d+$", l)
        if m:
            msg = m.group(1)
            if msg == "ClientHello":
                hellos.append("-")
            elif msg == "ServerHello":
                sh = {"version": None, "suite": None, "group": None}
            continue
        s = l.strip()
        m = re.match(r"Level=fatal\(2\), description=(.*)$", s)
        if m:
            alerts.append("%s:%s" % (direction, m.group(1).replace(" ", "_")))
        if msg == "ClientHello" and s.startswith("extension_type=server_name(0)"):
            hellos[-1] = _sni(lines[i + 1:i + 8])
        elif msg == "ServerHello":
            m = re.match(r"server_version=0x[0-9a-f]+ \((TLS \S+)\)", s)
            if m and sh["version"] is None:
                sh["version"] = m.group(1)
            m = re.match(r"cipher_suite \{[^}]*\} (\S+)", s)
            if m:
                sh["suite"] = m.group(1)
            if s.startswith("extension_type=supported_versions"):
                m = re.match(r"(TLS \S+)", lines[i + 1].strip())
                if m:
                    sh["version"] = m.group(1)
            m = re.match(r"NamedGroup: (\S+)", s)
            if m:
                sh["group"] = m.group(1)
        elif msg in ("ServerKeyExchange", "CertificateVerify") and direction == "sent":
            m = re.match(r"named_curve: (\S+)", s)
            if m:
                group = m.group(1)
            if s.startswith("KeyExchangeAlgorithm=") and s != "KeyExchangeAlgorithm=ECDHE":
                group = s.split("=", 1)[1]
            m = re.match(r"Signature Algorithm: (\S+)", s)
            if m:
                sigalg = m.group(1)
    errors = []
    for m in re.finditer(r":error:[0-9A-F]+:SSL routines:([^:]*):([^:]*):", errtext):
        e = "%s:%s" % (m.group(1), m.group(2).replace(" ", "_"))
        if e not in errors:
            errors.append(e)
    out = ["hello=%d" % len(hellos), "sni=%s" % (",".join(hellos) if hellos else "-")]
    if sh is not None:
        out.append("version=%s" % (sh["version"] or "?").replace("TLS ", "TLSv"))
        out.append("suite=%s" % (sh["suite"] or "?"))
        g = sh["group"] if sh["group"] else group
        out.append("group=%s" % (g or "-"))
        out.append("sigalg=%s" % (sigalg or "-"))
    else:
        out.append("serverhello=none")
    out.append("alerts=%s" % (",".join(alerts) or "-"))
    out.append("error=%s" % (",".join(errors) or "-"))
    return " ".join(out)


BAD13_NOISE = ("unexpected end of file", "Connection reset by peer")


def observe(kind, out_text, err_text):
    lines = [l.strip() for l in out_text.split("\n") if l.strip()]
    if kind == "s_server":
        return observe_s_server(out_text, err_text)
    if kind == "fake":
        seen = [l for l in lines if l.startswith("client ")]
    elif kind == "starttls":
        seen = [l for l in lines if l.startswith("tls ")]
    elif kind == "bad13":
        seen = [l for l in lines if not l.startswith("listening")
                and not any(n in l for n in BAD13_NOISE)]
    else:
        return "-"
    return " | ".join(seen) if seen else "none"


# ---------------------------------------------------------------- the matrix

def run_matrix(badserver, logdir):
    rows = []
    for idx, (name, kind, args, mode, extra, tags) in enumerate(FIXTURES, 1):
        port = BASE_PORT + idx
        tags = list(tags)
        if name in NONDET:
            tags.append("nondet:" + NONDET[name])
        if kind == "bad13" and badserver is None:
            rows.append((name, tags, "skipped", "-"))
            continue
        if listening(port):
            raise SystemExit("port %d (%s) is in use: free 47301-47361 and re-run" % (port, name))
        out_p = os.path.join(logdir, name + ".server.out")
        err_p = os.path.join(logdir, name + ".server.err")
        cli_p = os.path.join(logdir, name + ".client.log")
        proc = None
        with open(out_p, "w") as out, open(err_p, "w") as err, open(cli_p, "w") as cli:
            try:
                if kind != "none":
                    cmd = server_cmd(kind, args, port, badserver)
                    proc = subprocess.Popen(cmd, stdin=subprocess.PIPE, stdout=out, stderr=err)
                    if not wait_port(port, proc):
                        raise SystemExit("%s: the server did not come up: %s" % (name, " ".join(cmd)))
                result = oracle(port, mode, extra, cli)
                time.sleep(0.3)  # let the server write what it saw
            finally:
                stop(proc)
        with open(out_p, errors="replace") as fh:
            out_text = fh.read()
        with open(err_p, errors="replace") as fh:
            err_text = fh.read()
        rows.append((name, tags, result, observe(kind, out_text, err_text)))
        print("%-30s %-60s %s" % (name, result[:60], rows[-1][3][:80]), file=sys.stderr, flush=True)
    return rows


def row_line(r):
    name, tags, result, server = r
    return "\t".join([name, ",".join(tags) or "-", result, server])


def read_rows(path):
    rows = {}
    with open(path) as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            f = line.rstrip("\n").split("\t")
            rows[f[0]] = (f[0], [] if f[1] == "-" else f[1].split(","), f[2], f[3])
    return rows


def compared(r):
    return r[2] != "skipped" and not any(t.startswith("nondet:") for t in r[1])


def generate(outdir, twice, carry):
    t0 = time.time()
    badserver = find_badserver()
    if badserver is None:
        names = [f[0] for f in FIXTURES if "needs-badserver" in f[5]]
        how = ("copied from %s" % carry) if carry else "written as 'skipped'"
        print("gen_m65_tls: no badserver binary (BADSERVER, $CARGO_TARGET_DIR/release/badserver, "
              "spikes/m65-tls-provider/target/release/badserver): the needs-badserver rows (%s) are %s. "
              "Build it with `cargo build --release --bin badserver` in spikes/m65-tls-provider "
              "to record them." % (", ".join(names), how), file=sys.stderr)
    keep = os.environ.get("M65_TLS_LOGS")
    runs = []
    for n in range(2 if twice else 1):
        if keep:
            logdir = os.path.join(keep, "run%d" % (n + 1))
            os.makedirs(logdir, exist_ok=True)
            runs.append(run_matrix(badserver, logdir))
        else:
            with tempfile.TemporaryDirectory(prefix="m65-tls-") as logdir:
                runs.append(run_matrix(badserver, logdir))
    rows = runs[0]
    if twice:
        bad = 0
        for a, b in zip(runs[0], runs[1]):
            if compared(a) and a != b:
                bad += 1
                print("nondeterministic, untagged: %s\n  run 1: %s\n  run 2: %s"
                      % (a[0], row_line(a), row_line(b)), file=sys.stderr)
        if bad:
            raise SystemExit("gen_m65_tls: %d untagged rows differ between two runs of 7.94; "
                             "no golden written (tag them in NONDET with a reason, or fix the "
                             "fixture)" % bad)
    if badserver is None and carry and os.path.exists(carry):
        old = read_rows(carry)
        rows = [old[r[0]] if (r[2] == "skipped" and r[0] in old) else r for r in rows]
    names = [r[0] for r in rows]
    assert names == [f[0] for f in FIXTURES] and len(set(names)) == len(names)
    lines = header_lines(environment()) + [row_line(r) for r in rows]
    with open(os.path.join(outdir, GOLDEN_NAME), "w") as fh:
        fh.write("\n".join(lines) + "\n")
    print("gen_m65_tls: %d rows, %s, %.0f s" % (len(rows), "two runs agree" if twice else "one run",
                                                 time.time() - t0), file=sys.stderr)


def main():
    argv = sys.argv[1:]
    if len(argv) == 2 and argv[0] == "--check-header":
        bad = compare_header(argv[1])
        if bad:
            print("%d header field(s) differ: this machine is not the golden's environment" % bad)
            sys.exit(1)
        print("header matches the golden's environment")
        sys.exit(0)
    if len(argv) == 4 and argv[0] == "--check" and argv[2] == "--client":
        if compare_header(argv[1]):
            print("header mismatch: the golden was not made in this environment; "
                  "nothing else is compared")
            sys.exit(1)
        print("step f1 adds the port's side")
        sys.exit(2)
    twice = True
    carry = None
    rest = []
    i = 0
    while i < len(argv):
        if argv[i] == "--once":
            twice = False
        elif argv[i] == "--twice":
            twice = True
        elif argv[i] == "--carry" and i + 1 < len(argv):
            carry = argv[i + 1]
            i += 1
        else:
            rest.append(argv[i])
        i += 1
    if len(rest) != 1 or rest[0].startswith("-"):
        sys.exit(__doc__)
    generate(rest[0], twice, carry)


if __name__ == "__main__":
    main()
