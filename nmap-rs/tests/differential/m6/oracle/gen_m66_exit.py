#!/usr/bin/env python3
"""M6.6's exit criterion (docs/M6.6-ANALYSIS.md §12): the shipped scripts
selected and loaded on the real data directory, and one executed script per
module, nmap and nmap-rs compared by one parser.

    python3 oracle/gen_m66_exit.py OUTDIR
        -> OUTDIR/m66_exit_golden.txt, from the installed nmap (7.94)
    python3 oracle/gen_m66_exit.py --check GOLDEN --binary PATH/TO/nmap-rs
        -> runs nmap-rs over the same scenarios; exit 1 on any difference

**Selection and load** (`load` blocks). Each runs
`BIN --datadir REPO -d2 -Pn -n -p 1 SEL 127.0.0.1` on this repository's own
data directory, never a fixture one, with SEL `-sC`, `--script default`,
`--script version`, `-A` or `--script safe`. `safe` runs its 334 scripts,
broadcast ones among them, so that block runs, for both programs, in a
network namespace of its own holding only loopback (`unshare -rn`, NETNS):
nothing it sends leaves the host. Without user namespaces the block fails;
it is never skipped. nmap 7.94 cannot run `-A` with this repository's
nmap-os-db (written for 7.94.2 and later: an assertion abort in
3be01efb1:osscan.cc:681), so its `-A` block is `-sC -sV`, which selects the same 158
scripts in the same order. From each program's output this keeps:

    selected  `NSE: Script X was selected by HOW[ and forced to run].` (stdout)
    loaded    `NSE: Loaded 'PATH'.` (stdout, debug level 2)
    loaded_n  `NSE: Loaded N scripts for scanning.` (stdout)
    quiet     `NSE: Failed to load 'PATH'.` (stdout: a stdnse.silent_require
              that failed, nse_main.lua:632)
    loud      `NSE: Failed to load PATH:` (stderr: a hard require that failed)
    init      `NSE: failed to initialize the script engine:` (stderr)
    quit      `QUITTING!` (stderr)

Every other line is ignored on purpose (Fetchfile lines, -d2 require
tracebacks, `NSE: table: 0x...`, the scan's own output). Every PATH must be
under DATADIR/scripts/, DATADIR the --datadir given, so no fixture data
directory can pass; it is then reduced to its file name.

The golden holds, per selection, 7.94's `selected` list and the `loaded` and
`quiet` lists nmap 7.94 gives with the C modules the port does not have yet
removed (gen_m66_scriptload.py's emulation, PORT_MISSING), which is what the
port must print. Generation checks that emulation against the real 7.94 run:
the same selection, its `loaded` list the real one less OPENSSL_QUIET[mode],
and its `quiet` list exactly OPENSSL_QUIET[mode]; and the selection counts
SELECTED. Two harness tolerances, each part of a ledger entry
(LESSONS #031), and nothing else:

    OPENSSL_QUIET   `nse-sc-openssl-quiet-drops` (expires with M6.5): per
                    selection, the scripts that reach `openssl` through
                    silent_require, dropped quietly by the port and loaded by
                    7.94: six of `default`, none of `version`, 18 of `safe`.
    SV_VERSION_ONLY `nse-sv-version-scripts-pending`: the port's -sV runs no
                    scripts yet, so its -A selects `default` alone. While
                    SV_PENDING, the port's -A is held to the `-sC` block and
                    must name none of these 31; 7.94's -A adds them.

The port's run must also end with rc 0 and print no loud, init or quit line.

**Categories that still stop at start-up** (`abort` blocks,
`nse-categories-abort-on-unported-modules`): `--script vuln`, `intrusive`,
`exploit` and `all`, with the same command line (`safe` stopped on `lfs`
until the lfs step, and is a `load` block since). The oracle is
nmap 7.94 without the port's missing modules alone (real 7.94 would run them
all): it quits at load, so nothing runs. The port must print the same
`selected`, `loaded` and `quiet` lists up to the script that stops it, that
script's `Failed to load` line and the same `file:line: module 'X' not found`,
and end with `QUITTING!` and rc 1. A category whose module has left
PORT_MISSING (ported) is not run — it would scan — and fails: the ledger entry
and this block must change with the module.

**Executed scripts** (`run` blocks), each one nmap run whose script results
are parsed from -oN and -oX by gen_m64_cli.py's parsers (`row`, `xml`), plus
its exit status (`rc`) and whether it printed a port table (`porttable`):

    address-info (nmapdb's mac2corp): -6 on an EUI-64 address with an empty
        port list (`-p 1 --exclude-ports 1`), so nothing is scanned or sent
        and the host script still runs.
    riak-http-info, bitcoinrpc-info (lpeg, through json.lua): against
        loopback listeners serving JSON with literal \\uXXXX escapes (json.lua
        decodes each with a match-time capture) and an array nested D deep.
        This document's ceiling is 29 / 30 for riak and 28 / 29 for
        bitcoinrpc: 7.94 fails one deeper with `too many pending
        calls/choices` (the backtrack ceiling, D2), end to end.
    http-affiliate-id (re, the one script that uses it): three pages, one per
        affiliate grammar, so that no table iteration order reaches the
        output; no amzn.to link, which the script would fetch from the net.

Nothing leaves 127.0.0.1. -sC's ms-sql hostrules send one SSRP datagram to
127.0.0.1:1434, as 7.94's do.
"""

import base64
import http.server
import os
import re
import shutil
import socketserver
import subprocess
import sys
import tempfile
import threading

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_m64_cli as cli  # noqa: E402
import gen_m66_scriptload as scriptload  # noqa: E402

REPO = scriptload.REPO

# `nse-sc-openssl-quiet-drops` (DIVERGENCES.md), expiring with M6.5: per
# selection, the scripts that reach `openssl` through stdnse.silent_require
# (measured, each module removed alone: all 18 of `safe`'s are `openssl`'s).
DEFAULT_QUIET = ["http-favicon.nse", "iscsi-info.nse", "mongodb-databases.nse",
                 "mongodb-info.nse", "sip-methods.nse", "ssh-hostkey.nse"]
OPENSSL_QUIET = {
    "sC": DEFAULT_QUIET,
    "default": DEFAULT_QUIET,
    "version": [],
    "A": DEFAULT_QUIET,
    "safe": ["bitcoin-getaddr.nse", "bitcoin-info.nse", "bittorrent-discovery.nse",
             "duplicates.nse", "http-cakephp-version.nse", "http-favicon.nse",
             "http-php-version.nse", "http-virustotal.nse", "iscsi-info.nse",
             "mongodb-databases.nse", "mongodb-info.nse", "rsa-vuln-roca.nse",
             "rsync-list-modules.nse", "shodan-api.nse", "sip-methods.nse", "smb-ls.nse",
             "ssh-hostkey.nse", "ssh2-enum-algos.nse"],
}

# `nse-sv-version-scripts-pending` (DIVERGENCES.md): while it is open, the
# port's -A selects `default` alone, and these, which 7.94's -A adds through
# -sV's `version` rule, must be absent. When it closes, set SV_PENDING False:
# the port's -A is then held to 7.94's whole -A block.
SV_PENDING = True
SV_VERSION_ONLY = [
    "allseeingeye-info.nse", "bacnet-info.nse", "cccam-version.nse", "db2-das-info.nse",
    "docker-version.nse", "drda-info.nse", "enip-info.nse", "fingerprint-strings.nse",
    "fox-info.nse", "http-server-header.nse", "http-trane-info.nse", "https-redirect.nse",
    "iax2-version.nse", "iec61850-mms.nse", "jdwp-version.nse", "mcafee-epo-agent.nse",
    "mqtt-subscribe.nse", "murmur-version.nse", "ndmp-version.nse", "netbus-version.nse",
    "omron-info.nse", "oracle-tns-version.nse", "ovs-agent-version.nse", "pptp-version.nse",
    "rfc868-time.nse", "rpc-grind.nse", "s7-info.nse", "skypev2-version.nse",
    "stun-version.nse", "teamspeak2-version.nse", "vmware-version.nse",
]

# Each selection's command line, the port's and the oracle's.
LOADS = [
    ("sC", ["-sC"], ["-sC"]),
    ("default", ["--script", "default"], ["--script", "default"]),
    ("version", ["--script", "version"], ["--script", "version"]),
    ("A", ["-A"], ["-sC", "-sV"]),
    ("safe", ["--script", "safe"], ["--script", "safe"]),
]

# The selections run in a loopback-only network namespace (see above).
NETNS = {"safe"}

# `nse-categories-abort-on-unported-modules`: the categories that stop at
# start-up for want of `openssl`.
ABORTS = ["vuln", "intrusive", "exploit", "all"]

# How many scripts each selects on this tree's scripts/ (the `selected` lines
# alone, as well as the lists, so a golden from a fixture data directory
# cannot pass): 127 `default`, 48 `version`, 158 for both, 352 `safe`.
SELECTED = {"sC": 127, "default": 127, "version": 48, "A": 158, "safe": 352}

# Run a command in a new user and network namespace with loopback up: the
# namespace has no other interface, so nothing can leave the host.
LO_UP = (
    "import fcntl, os, socket, struct, sys\n"
    "s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)\n"
    "req = struct.pack('16sH14s', b'lo', 0, b'')\n"
    "flags = struct.unpack('16sH14s', fcntl.ioctl(s, 0x8913, req))[1]\n"  # SIOCGIFFLAGS
    "fcntl.ioctl(s, 0x8914, struct.pack('16sH14s', b'lo', flags | 1, b''))\n"  # SIOCSIFFLAGS, IFF_UP
    "os.execvp(sys.argv[1], sys.argv[1:])\n"
)


def isolated(cmd):
    return ["unshare", "-rn", sys.executable, "-c", LO_UP] + cmd

RIAK_PORT, BITCOIN_PORT, HTTP_PORT = 8098, 8332, 8180
D = ["-sT", "-Pn", "-n"]
RUNS = [
    # name, listener (mode, depth), arguments after --datadir
    ("address-info", None,
     ["-6", "-Pn", "-n", "-sT", "-p", "1", "--exclude-ports", "1", "--script", "address-info",
      "2001:db8::211:22ff:fe33:4455"]),
    ("riak-29", ("ok", 29), D + ["-p", str(RIAK_PORT), "--script", "riak-http-info", "127.0.0.1"]),
    ("riak-30-d", ("ok", 30),
     D + ["-d", "-p", str(RIAK_PORT), "--script", "riak-http-info", "127.0.0.1"]),
    ("riak-bad-surrogate-d", ("bad-surrogate", 29),
     D + ["-d", "-p", str(RIAK_PORT), "--script", "riak-http-info", "127.0.0.1"]),
    ("bitcoinrpc-28", ("ok", 28),
     D + ["-p", str(BITCOIN_PORT), "--script", "bitcoinrpc-info", "--script-args",
          "creds.global=rpcuser:pw", "127.0.0.1"]),
    ("bitcoinrpc-29-d", ("ok", 29),
     D + ["-d", "-p", str(BITCOIN_PORT), "--script", "bitcoinrpc-info", "--script-args",
          "creds.global=rpcuser:pw", "127.0.0.1"]),
] + [
    ("affiliate-" + page, ("ok", 1),
     D + ["-p", str(HTTP_PORT), "--script", "http-affiliate-id", "--script-args",
          "http-affiliate-id.url-path=/" + page, "127.0.0.1"])
    for page in ("ga", "ad", "amz")
]

# ------------------------------------------------------------------ parsing

SEL = re.compile(r"^NSE: Script (\S+) was selected by "
                 r"(category|name|file path|directory|\(unknown\))( and forced to run)?\.$")
LOADED = re.compile(r"^NSE: Loaded '(.+)'\.$")
LOADED_N = re.compile(r"^NSE: Loaded (\d+) scripts for scanning\.$")
QUIET = re.compile(r"^NSE: Failed to load '(.+)'\.$")
LOUD = re.compile(r"^NSE: Failed to load (.+):$")
INIT = "NSE: failed to initialize the script engine:"
QUIT = "QUITTING!"
NOT_FOUND = re.compile(r"[a-zA-Z0-9_./-]*:[0-9]*: module '([^']*)' not found")


def parse(stdout, stderr, datadir):
    """The lines the exit criterion reads, from one program's output."""
    p = {"selected": [], "loaded": [], "loaded_n": [], "quiet": [], "loud": [],
         "notfound": [], "init": False, "quit": False, "outside": []}
    prefix = datadir.rstrip("/") + "/scripts/"

    def name(path):
        if not path.startswith(prefix):
            p["outside"].append(path)
        return path.rsplit("/", 1)[-1]

    for line in stdout.decode("latin-1").split("\n"):
        m = SEL.match(line)
        if m:
            p["selected"].append((m.group(1), m.group(2), "forced" if m.group(3) else "-"))
            continue
        m = LOADED.match(line)
        if m:
            p["loaded"].append(name(m.group(1)))
            continue
        m = LOADED_N.match(line)
        if m:
            p["loaded_n"].append(int(m.group(1)))
            continue
        m = QUIET.match(line)
        if m:
            p["quiet"].append(name(m.group(1)))
    for line in stderr.decode("latin-1").split("\n"):
        m = LOUD.match(line)
        if m:
            p["loud"].append(name(m.group(1)))
            continue
        m = NOT_FOUND.search(line)
        if m and p["loud"] and not p["notfound"]:
            # The loud failure's own `file:line: module 'X' not found`.
            p["notfound"].append((m.group(0).rsplit("/", 1)[-1], m.group(1)))
        elif line == INIT:
            p["init"] = True
        elif line == QUIT:
            p["quit"] = True
    return p


def load_run(binary, datadir, sel, netns=False):
    cmd = [binary, "--datadir", datadir, "-d2", "-Pn", "-n", "-p", "1"] + sel + ["127.0.0.1"]
    if netns:
        probe = subprocess.run(isolated(["true"]), capture_output=True)
        if probe.returncode != 0:
            sys.exit("FAIL: %s needs a loopback-only network namespace, and `unshare -rn` "
                     "failed: %s (on Ubuntu, sysctl kernel.apparmor_restrict_unprivileged_userns=0)"
                     % (" ".join(sel), probe.stderr.decode("latin-1").strip()))
        cmd = isolated(cmd)
    r = subprocess.run(cmd, capture_output=True, timeout=600)
    p = parse(r.stdout, r.stderr, datadir)
    p["rc"] = r.returncode
    return p


def clean(p, what):
    """The ways a load run must not end, for either program."""
    bad = []
    if p["rc"] != 0:
        bad.append("%s: exit status %d" % (what, p["rc"]))
    for k in ("loud", "outside"):
        if p[k]:
            bad.append("%s: %s %s" % (what, k, p[k]))
    for k in ("init", "quit"):
        if p[k]:
            bad.append("%s: printed the %s line" % (what, k))
    if p["loaded_n"] != [len(p["loaded"])]:
        bad.append("%s: `Loaded N scripts` %s for %d Loaded lines"
                   % (what, p["loaded_n"], len(p["loaded"])))
    return bad

# ------------------------------------------------------------ the listeners

BS = chr(92)


def u(*hexes):
    """JSON unicode escapes, built here so no tool decodes them on the way."""
    return "".join(BS + "u" + h for h in hexes)


# Each escape kind json.lua decodes differently: ASCII through its unicode16
# match-time capture; two- and three-byte UTF-8; a surrogate pair (four-byte);
# control bytes, which the output layer escapes; an embedded NUL; the short
# escapes; and backslash-q, the P[[\]]*C(1) fallback (json.lua:134).
STRINGS = {
    "nodename": "riak" + u("0040") + "127.0.0.1",
    "sys_system_architecture": ("x86_64 caf" + u("00e9") + " " + u("00e8") + " "
                                + u("4e2d", "6587") + " " + u("d83d", "de00")),
    "storage_backend": "riak_kv_" + u("0062") + "itcask_backend",
    "crypto_version": u("0031") + ".6." + u("0032"),
    "ssl_version": ("q" + BS + '"b' + BS + BS + "s" + BS + "/t" + BS + "tc"
                    + u("0001", "001f", "007f") + "z"),
    "kernel_version": "nul[" + u("0000") + "]end",
    "stdlib_version": "fallback " + BS + "q" + u("0021"),
}


def deep(depth):
    return "[" * depth + "1" + "]" * depth


def riak_body(mode, depth):
    # riak-http-info prints a fixed key order (tab.dump), so no pairs() order
    # reaches its output.
    parts = ['"%s": "%s"' % kv for kv in STRINGS.items()]
    parts += ['"mem_total": 1e3', '"sasl_version": 2.5', '"deep": %s' % deep(depth)]
    if mode == "bad-surrogate":
        parts.append('"bad": "%s"' % u("dc00"))   # unicode16 raises: parse fails
    return "{\n  " + ",\n  ".join(parts) + "\n}\n"


def rpc_body(depth):
    # bitcoinrpc-info sorts the result's keys, and its one nested value is an
    # array, so no pairs() order reaches its output either.
    result = ", ".join('"%s": "%s"' % kv for kv in STRINGS.items() if kv[0] != "kernel_version")
    result += ', "version": 31900, "blocks": 1e3, "deep": %s' % deep(depth)
    return '{"result": {%s}, "error": null, "id": 1}\n' % result


# One page per affiliate grammar of http-affiliate-id.nse: matches, near
# misses (one digit short, one too many), a repeat (printed once), all in
# markup. No other grammar's prefix appears on a page.
AFFILIATE = {
    "/ga": ("<html><head><script>var _gaq = []; _gaq.push(['_setAccount', 'UA-1234567-1']);"
            "</script></head><body><p>UA-12345-6 is a digit short; UA-7654321-123 has three "
            "after the dash; UA-1234567-1 again.</p><a href=\"/x?id=UA-222222-22\">x</a>"
            "</body></html>\n"),
    "/ad": ("<html><body><script>google_ad_client = \"pub-1234567890123456\";</script>"
            "<p>pub-123456789012345 is a digit short, pub-98765432109876543 one too long, "
            "pub-1234567890123456 a repeat.</p></body></html>\n"),
    "/amz": ("<html><body><a href=\"http://www.amazon.com/dp/B000TEST?tag=nmaptest-20&x=1\">a</a>"
             "<a href='http://rcm.amazon.com/e/cm?lt1=_blank&t=other-21&o=1'>b</a>"
             "<a href=\"http://www.amazon.com/gp/product/1?ie=UTF8&tag=bad_tag-1\">c</a>"
             "</body></html>\n"),
}


class Fixture:
    """What the listeners serve, changed between runs: they are bound once
    for a whole generation or check, as a rebind of a port a handler thread
    still holds a connection on can fail."""
    mode = "ok"
    depth = 1


def handler_for(fixture):
    class H(http.server.BaseHTTPRequestHandler):
        server_version = "MochiWeb/1.0"   # riak-http-info drops any other
        sys_version = ""
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):
            pass

        def reply(self, code, body, ctype="application/json"):
            data = body.encode("ascii")
            self.send_response(code)
            self.send_header("Content-Type", ctype)
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            if self.command != "HEAD":
                self.wfile.write(data)

        def do_GET(self):
            port = self.server.server_address[1]
            if port == RIAK_PORT and self.path == "/stats":
                self.reply(200, riak_body(fixture.mode, fixture.depth))
            elif port == HTTP_PORT and self.path in AFFILIATE:
                self.reply(200, AFFILIATE[self.path], "text/html")
            else:
                self.reply(404, "not found\n", "text/plain")

        do_HEAD = do_GET

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            auth = self.headers.get("Authorization") or ""
            if self.server.server_address[1] == BITCOIN_PORT and auth.startswith("Basic "):
                user = base64.b64decode(auth[6:]).decode("latin-1").split(":", 1)[0]
                if user == "rpcuser":
                    self.reply(200, rpc_body(fixture.depth))
                    return
            self.reply(401, "unauthorized\n", "text/plain")

        def handle(self):
            try:
                super().handle()
            except (ConnectionResetError, BrokenPipeError):
                pass
    return H


class Server(socketserver.ThreadingMixIn, http.server.HTTPServer):
    daemon_threads = True
    allow_reuse_address = True


def serve(stop, fixture):
    servers = []
    for port in (RIAK_PORT, BITCOIN_PORT, HTTP_PORT):
        s = Server(("127.0.0.1", port), handler_for(fixture))
        s.timeout = 0.2
        servers.append(s)

        def loop(s=s):
            while not stop.is_set():
                s.handle_request()
        threading.Thread(target=loop, daemon=True).start()
    return servers


def all_runs(binary):
    """Every executed scenario's rows, the listeners up throughout."""
    out = []
    tmp = tempfile.mkdtemp(prefix="m66-exit-")
    stop = threading.Event()
    fixture = Fixture()
    servers = serve(stop, fixture)
    try:
        for name, listener, args in RUNS:
            fixture.mode, fixture.depth = listener or ("ok", 1)
            out.append((name, args, exec_run(binary, tmp, args)))
    finally:
        stop.set()
        for s in servers:
            s.server_close()
        shutil.rmtree(tmp, ignore_errors=True)
    return out

# ---------------------------------------------------------------- the runs


def exec_run(binary, tmp, args):
    """One executed scenario: its script rows, exit status, port table."""
    out_n = os.path.join(tmp, "out.nmap")
    out_x = os.path.join(tmp, "out.xml")
    for f in (out_n, out_x):
        if os.path.exists(f):
            os.remove(f)
    r = subprocess.run([binary, "--datadir", REPO] + args + ["-oN", out_n, "-oX", out_x],
                       capture_output=True, timeout=300)
    norm = lambda s: s.replace(REPO, "DATADIR").replace(tmp, "TMP")
    normal = open(out_n, encoding="latin-1").read() if os.path.exists(out_n) else ""
    xml = open(out_x, encoding="latin-1").read() if os.path.exists(out_x) else ""
    rows = [("row",) + x for x in cli.normal_rows(norm(normal))]
    rows += [("xml",) + x for x in cli.xml_rows(norm(xml))]
    rows.sort(key=lambda x: (x[0], x[1], cli.script_id(x[2]), x[2]))
    rows.append(("rc", "-", str(r.returncode)))
    if re.search(r"^PORT\s+STATE", normal, re.M):
        rows.append(("porttable", "-", "printed"))
    return rows


def hexs(s):
    return s.encode("latin-1").hex()


def unhex(h):
    return bytes.fromhex(h).decode("latin-1")


def write_golden(outdir):
    version = subprocess.run(["nmap", "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    missing = sorted(m for m in scriptload.PORT_MISSING.split(",") if m)
    lines = ["# Generated by oracle/gen_m66_exit.py from %s. Do not edit by hand." % version,
             "# load blocks: 7.94's selection on --datadir REPO, and the loaded and quiet",
             "# lists of 7.94 without %s (the port's missing modules)." % ",".join(missing)]
    bad = []
    lists = {}
    with tempfile.TemporaryDirectory() as dd:
        scriptload.datadir(dd, missing)
        for mode, _port_sel, sel in LOADS:
            real = load_run("nmap", REPO, sel, mode in NETNS)
            emu = load_run("nmap", dd, sel, mode in NETNS)
            bad += clean(real, mode + " (7.94)") + clean(emu, mode + " (7.94 without modules)")
            names = [s[0] for s in real["selected"]]
            if len(names) != SELECTED[mode]:
                bad.append("%s: 7.94 selected %d, SELECTED says %d" % (mode, len(names), SELECTED[mode]))
            if emu["selected"] != real["selected"]:
                bad.append("%s: the emulation selected otherwise" % mode)
            if real["loaded"] != names or real["quiet"]:
                bad.append("%s: 7.94 did not load what it selected" % mode)
            quiet = OPENSSL_QUIET[mode]
            if emu["quiet"] != quiet:
                bad.append("%s: without the modules 7.94 drops %s, OPENSSL_QUIET says %s"
                           % (mode, emu["quiet"], quiet))
            if emu["loaded"] != [n for n in names if n not in quiet]:
                bad.append("%s: without the modules 7.94 loads other than all less OPENSSL_QUIET"
                           % mode)
            lists[mode] = names
            lines.append("load %s" % mode)
            lines += ["selected %s %s %s" % s for s in real["selected"]]
            lines += ["loaded %s" % n for n in emu["loaded"]]
            lines += ["quiet %s" % n for n in emu["quiet"]]
        for cat in ABORTS:
            emu = load_run("nmap", dd, ["--script", cat])
            if not (emu["rc"] == 1 and emu["quit"] and emu["init"] and len(emu["loud"]) == 1
                    and len(emu["notfound"]) == 1 and not emu["outside"]):
                bad.append("--script %s: 7.94 without the modules does not stop at load: %s"
                           % (cat, {k: emu[k] for k in ("rc", "loud", "notfound", "quit")}))
                continue
            lines.append("abort %s" % cat)
            lines += ["selected %s %s %s" % s for s in emu["selected"]]
            lines += ["loaded %s" % n for n in emu["loaded"]]
            lines += ["quiet %s" % n for n in emu["quiet"]]
            lines.append("loud %s" % emu["loud"][0])
            lines.append("notfound %s %s" % (emu["notfound"][0][1],
                                             hexs(emu["notfound"][0][0])))
    if lists.get("default") != lists.get("sC"):
        bad.append("--script default and -sC select differently")
    only = [n for n in lists.get("A", []) if n not in lists.get("sC", [])]
    if only != SV_VERSION_ONLY:
        bad.append("-sC -sV adds %s, SV_VERSION_ONLY says %s" % (only, SV_VERSION_ONLY))
    if bad:
        sys.exit("FAIL: the oracle disagrees with the harness:\n  " + "\n  ".join(bad))
    for name, args, rows in all_runs("nmap"):
        lines.append("run %s" % name)
        lines.append("args %s" % hexs("\0".join(args)))
        for kind, container, text in rows:
            lines.append("%s %s %s" % (kind, container, hexs(text)))
    with open(os.path.join(outdir, "m66_exit_golden.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def read_golden(path):
    loads, runs, order, aborts = {}, {}, [], {}
    cur = None
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            f = line.rstrip("\n").split(" ")
            if not f[0] or f[0].startswith("#"):
                continue
            if f[0] == "load":
                cur = loads.setdefault(f[1], {"selected": [], "loaded": [], "quiet": []})
            elif f[0] == "abort":
                cur = aborts.setdefault(f[1], {"selected": [], "loaded": [], "quiet": [],
                                               "loud": [], "notfound": []})
            elif f[0] == "loud":
                cur["loud"].append(f[1])
            elif f[0] == "notfound":
                cur["notfound"].append((unhex(f[2]), f[1]))
            elif f[0] == "run":
                cur = runs.setdefault(f[1], [])
                order.append(f[1])
            elif f[0] == "selected":
                cur["selected"].append((f[1], " ".join(f[2:-1]), f[-1]))
            elif f[0] in ("loaded", "quiet"):
                cur[f[0]].append(f[1])
            elif f[0] == "args":
                continue
            else:
                cur.append((f[0], f[1], unhex(f[2])))
    return loads, runs, order, aborts


def check(golden, binary):
    loads, runs, order, aborts = read_golden(golden)
    bad = 0
    total = 0
    for mode, port_sel, _oracle_sel in LOADS:
        total += 1
        want = loads[mode]
        names = [s[0] for s in want["selected"]]
        if mode == "A" and SV_PENDING:
            # nse-sv-version-scripts-pending: the port's -A is -sC's.
            only = [n for n in names if n not in [s[0] for s in loads["sC"]["selected"]]]
            want = loads["sC"]
            problems = [] if only == SV_VERSION_ONLY else [
                "the golden's -A adds %s, not SV_VERSION_ONLY" % only]
        else:
            problems = []
        got = load_run(binary, REPO, port_sel, mode in NETNS)
        problems += clean(got, mode)
        if len(got["selected"]) != SELECTED["sC" if mode == "A" and SV_PENDING else mode]:
            problems.append("%d selected" % len(got["selected"]))
        for k in ("selected", "loaded", "quiet"):
            if got[k] != want[k]:
                problems.append("%s differs:\n      nmap %s\n      port %s" % (k, want[k], got[k]))
        if mode == "A" and SV_PENDING:
            seen = set(s[0] for s in got["selected"]) | set(got["loaded"]) | set(got["quiet"])
            if seen & set(SV_VERSION_ONLY):
                problems.append("names version-only scripts %s" % sorted(seen & set(SV_VERSION_ONLY)))
        if problems:
            bad += 1
            print("load %s differs:\n  %s" % (mode, "\n  ".join(problems)))
        else:
            print("load %s: %d selected, %d loaded, %d quiet" % (
                mode, len(got["selected"]), len(got["loaded"]), len(got["quiet"])))
    missing = set(m for m in scriptload.PORT_MISSING.split(",") if m)
    if sorted(aborts) != sorted(ABORTS):
        bad += 1
        print("the golden's abort blocks are %s, not ABORTS" % sorted(aborts))
    for cat in ABORTS:
        want = aborts.get(cat)
        if want is None:
            continue
        total += 1
        module = want["notfound"][0][1] if want["notfound"] else "?"
        if module not in missing:
            # Ported: the category would now load, and run, every script.
            bad += 1
            print("abort %s: `%s` is ported (not in PORT_MISSING): retire this block and "
                  "nse-categories-abort-on-unported-modules for it" % (cat, module))
            continue
        got = load_run(binary, REPO, ["--script", cat])
        problems = []
        if got["rc"] != 1 or not got["quit"] or not got["init"] or got["outside"]:
            problems.append("rc %d, quit %s, init %s, outside %s"
                            % (got["rc"], got["quit"], got["init"], got["outside"]))
        for k in ("selected", "loaded", "quiet", "loud", "notfound"):
            if got[k] != want[k]:
                problems.append("%s differs:\n      nmap %s\n      port %s" % (k, want[k], got[k]))
        if problems:
            bad += 1
            print("abort %s differs:\n  %s" % (cat, "\n  ".join(problems)))
        else:
            print("abort %s: %d selected, %d loaded, stops on %s" % (
                cat, len(got["selected"]), len(got["loaded"]), got["notfound"][0][0]))
    for name, _args, got in all_runs(binary):
        total += 1
        want = runs.get(name)
        if got == want:
            print("run %s: %d rows" % (name, len(got)))
            continue
        bad += 1
        print("run %s differs:" % name)
        for r in want or []:
            if r not in got:
                print("  nmap  %s %s %r" % r)
        for r in got:
            if r not in (want or []):
                print("  port  %s %s %r" % r)
    if order != [n for n, _, _ in RUNS]:
        bad += 1
        print("the golden's runs are not RUNS: %s" % order)
    print("%d of %d scenarios differ" % (bad, total))
    return 1 if bad else 0


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--check" and sys.argv[3] == "--binary":
        sys.exit(check(sys.argv[2], sys.argv[4]))
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    write_golden(sys.argv[1])


if __name__ == "__main__":
    main()
