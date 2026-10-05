#!/usr/bin/env python3
"""NSE through the command line (M6.4e): nmap and nmap-rs, each run as a
whole program with --script, compared on what they print.

    python3 oracle/gen_m64_cli.py OUTDIR
        -> OUTDIR/m64_cli_golden.txt, from the installed nmap (7.94)
    python3 oracle/gen_m64_cli.py --check GOLDEN --binary PATH/TO/nmap-rs
        -> runs nmap-rs over the same scenarios; exit 1 on any difference

Both runs use one scratch data directory, given with --datadir: this
repository's data files and nselib/, and in scripts/ the fixture scripts of
nse_scripts/, nse_net/ and nse_cli/ and the shipped http-title and http-headers, with a
script.db listing them all. Each scenario is a connect scan of loopback
services (gen_m64_scripts.py's listeners, gen_m64_net.py's services), so
nothing leaves 127.0.0.1.

What is compared, per scenario, is parsed the same way from both programs'
output, by this file:

    row CONTAINER HEX   one script result in normal output (-oN): its lines,
                        or nmap's `Bug in ID: no string output.` line.
                        CONTAINER is pre, host, post, port:PROTO/NUMBER, or
                        port-table for a Bug line written before the table.
    xml CONTAINER HEX   one <script> element (-oX), re-serialised so that
                        attribute quoting and entity spelling do not matter.
    init_error HEX      the message after "NSE: failed to initialize the
                        script engine:", without nmap's `nse_main.lua:N: `.

Within a container, results are sorted by script id: nmap orders them by
address (`nse-results-sorted-by-id`). The data directory's path reads DATADIR. Each port's state (`xml PORT
"state STATE"`) is compared too, so a state a script set
(nmap.set_port_state) must reach the report.
"""

import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import gen_m64_scripts as scripts_gen  # noqa: E402
import gen_m64_net as net_gen  # noqa: E402

REPO = scripts_gen.REPO
SHIPPED = ["http-title.nse", "http-headers.nse"]
FIX = "46020,46021,46022"

SCENARIOS = [
    ("phases", ["-p", FIX, "--script", "s-allrules,s-empty,s-multiline,s-portinfo"]),
    ("shapes", ["-p", FIX, "--script", "shapes"]),
    ("errors", ["-p", FIX, "--script", "errors"]),
    ("workers", ["-p", FIX, "--script", "workers"]),
    ("default", ["-p", FIX, "-sC"]),
    ("args", ["-p", FIX, "--script", "s-args", "--script-args", "s-args.a=1,b={x,y}"]),
    ("args-file", ["-p", FIX, "--script", "s-args", "--script-args-file", "@ARGSFILE"]),
    ("args-both", ["-p", FIX, "--script", "s-args", "--script-args-file", "@ARGSFILE",
                   "--script-args", "s-args.a=3"]),
    ("net", ["-p", "46030,46031,46033", "--script", "n-echo,n-banner,n-refused,n-tables"]),
    ("shipped", ["-p", "8080", "--script", "http-title,http-headers"]),
    ("timeout", ["-p", "46030", "--script", "n-slow", "--script-timeout", "1"]),
    ("set-state", ["-p", FIX, "--script", "c-setstate,s-portinfo"]),
    ("no-match", ["-p", FIX, "--script", "no-such-script"]),
    ("bad-args", ["-p", FIX, "--script", "s-args", "--script-args", "{"]),
    ("missing-args-file", ["-p", FIX, "--script", "s-args", "--script-args-file",
                           "/nonexistent/m64-args"]),
]

ARGS_FILE_TEXT = "s-args.a=2,b={p,q},,\n"


def db_entries(path):
    with open(path) as fh:
        return [l for l in fh.read().splitlines() if l.startswith("Entry")]


def datadir(tmp):
    d = os.path.join(tmp, "data")
    os.mkdir(d)
    for name in os.listdir(REPO):
        if name == "nselib" or name == "nse_main.lua" or name.startswith("nmap-"):
            os.symlink(os.path.join(REPO, name), os.path.join(d, name))
    sd = os.path.join(d, "scripts")
    os.mkdir(sd)
    entries = []
    for fixtures in ("nse_scripts", "nse_net", "nse_cli"):
        src = os.path.join(M6, fixtures)
        for name in os.listdir(src):
            if name == "script.db":
                entries += db_entries(os.path.join(src, name))
            else:
                os.symlink(os.path.join(src, name), os.path.join(sd, name))
    shipped_db = db_entries(os.path.join(REPO, "scripts", "script.db"))
    for name in SHIPPED:
        os.symlink(os.path.join(REPO, "scripts", name), os.path.join(sd, name))
        entries += [e for e in shipped_db if '"%s"' % name in e]
    with open(os.path.join(sd, "script.db"), "w") as fh:
        fh.write("\n".join(sorted(entries)) + "\n")
    return d


ENTRY_ID = re.compile(r"^\|[ _]([^:]*):")
PORT_ROW = re.compile(r"^(\d+)/(tcp|udp|sctp)\s")


def normal_rows(text):
    """The script results in a normal output, as (container, text) rows."""
    rows = []
    container = None
    cur = None
    for line in text.split("\n"):
        if cur is not None:
            cur.append(line)
            if line.startswith("|_"):
                rows.append((container, "\n".join(cur)))
                cur = None
            continue
        if line in ("Pre-scan script results:", "Post-scan script results:",
                    "Host script results:"):
            container = {"P": "pre", "H": "host"}.get(line[0], "post")
            if line.startswith("Post"):
                container = "post"
            continue
        m = PORT_ROW.match(line)
        if m:
            container = "port:%s/%s" % (m.group(2), m.group(1))
            continue
        if line.startswith("Bug in "):
            rows.append((container or "port-table", line))
            continue
        if line.startswith("|") and container is not None:
            if line.startswith("|_"):
                rows.append((container, line))
            else:
                cur = [line]
            continue
        container = None
    return rows


def xml_rows(text):
    rows = []
    try:
        root = ET.fromstring(text)
    except ET.ParseError as e:
        return [("xml-error", str(e))]

    def add(container, parent):
        for s in parent.findall("script"):
            rows.append((container, ET.tostring(s, encoding="unicode").strip()))

    for tag, name in (("prescript", "pre"), ("postscript", "post")):
        for el in root.findall(tag):
            add(name, el)
    for host in root.findall("host"):
        for port in host.iter("port"):
            container = "port:%s/%s" % (port.get("protocol"), port.get("portid"))
            state = port.find("state")
            rows.append((container, "state " + (state.get("state") if state is not None else "?")))
            add(container, port)
        for hs in host.findall("hostscript"):
            add("host", hs)
    return rows


def script_id(text):
    m = ENTRY_ID.match(text) or re.match(r"^Bug in ([^:]*):", text)
    if not m:
        m = re.search(r'id="([^"]*)"', text)
    return m.group(1) if m else ""


INIT = "NSE: failed to initialize the script engine:"


def init_error(stderr):
    lines = stderr.split("\n")
    for i, l in enumerate(lines):
        if l.strip() == INIT and i + 1 < len(lines):
            msg = lines[i + 1]
            return re.sub(r"^.*?nse_main(\.lua)?:\d+: ", "", msg)
    return None


def run(binary, extra, tmp, data):
    args_file = os.path.join(tmp, "m64-args")
    with open(args_file, "w") as fh:
        fh.write(ARGS_FILE_TEXT)
    extra = [args_file if a == "@ARGSFILE" else a for a in extra]
    out_n = os.path.join(tmp, "out.nmap")
    out_x = os.path.join(tmp, "out.xml")
    for f in (out_n, out_x):
        if os.path.exists(f):
            os.remove(f)
    cmd = [binary, "--datadir", data, "-sT", "-Pn", "-n"] + extra + [
        "127.0.0.1", "-oN", out_n, "-oX", out_x]
    r = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    norm = lambda s: s.replace(data, "DATADIR").replace(tmp, "TMP")
    err = init_error(r.stderr)
    if err is not None:
        return [("init_error", "-", norm(err))]
    normal = open(out_n).read() if os.path.exists(out_n) else ""
    xml = open(out_x).read() if os.path.exists(out_x) else ""
    rows = [("row",) + r_ for r_ in normal_rows(norm(normal))]
    rows += [("xml",) + r_ for r_ in xml_rows(norm(xml))]
    rows.sort(key=lambda r_: (r_[0], r_[1], script_id(r_[2]), r_[2]))
    return rows


def hexs(s):
    return s.encode("utf-8", "surrogateescape").hex()


def all_rows(binary):
    out = []
    tmp = tempfile.mkdtemp(prefix="m64-cli-")
    stop = threading.Event()
    socks = scripts_gen.listeners(stop) + net_gen.serve(stop)
    try:
        data = datadir(tmp)
        for name, extra in SCENARIOS:
            out.append((name, extra, run(binary, extra, tmp, data)))
    finally:
        stop.set()
        for s in socks:
            s.close()
        shutil.rmtree(tmp, ignore_errors=True)
    return out


def write_golden(outdir):
    version = subprocess.run(["nmap", "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    lines = ["# Generated by oracle/gen_m64_cli.py from %s. Do not edit by hand." % version]
    for name, extra, rows in all_rows("nmap"):
        lines.append("scenario %s" % name)
        lines.append("args %s" % hexs("\0".join(extra)))
        for kind, container, text in rows:
            if kind == "init_error":
                lines.append("init_error %s" % hexs(text))
            else:
                lines.append("%s %s %s" % (kind, container, hexs(text)))
    with open(os.path.join(outdir, "m64_cli_golden.txt"), "w") as fh:
        fh.write("\n".join(lines) + "\n")


def read_golden(path):
    want = {}
    order = []
    name = None
    with open(path) as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("#") or not line:
                continue
            f = line.split(" ")
            if f[0] == "scenario":
                name = f[1]
                order.append(name)
                want[name] = []
            elif f[0] == "args":
                continue
            elif f[0] == "init_error":
                want[name].append(("init_error", "-", bytes.fromhex(f[1]).decode()))
            else:
                want[name].append((f[0], f[1], bytes.fromhex(f[2]).decode()))
    return order, want


def check(golden, binary):
    order, want = read_golden(golden)
    got = {name: rows for name, _extra, rows in all_rows(binary)}
    bad = 0
    for name in order:
        if got.get(name) == want[name]:
            continue
        bad += 1
        print("scenario %s differs:" % name)
        for r in want[name]:
            if r not in got.get(name, []):
                print("  nmap  %s %s %r" % r)
        for r in got.get(name, []):
            if r not in want[name]:
                print("  port  %s %s %r" % r)
    print("%d of %d scenarios differ" % (bad, len(order)))
    return 1 if bad else 0


def main():
    if len(sys.argv) == 5 and sys.argv[1] == "--check" and sys.argv[3] == "--binary":
        sys.exit(check(sys.argv[2], sys.argv[4]))
    if len(sys.argv) != 2:
        sys.exit(__doc__)
    write_golden(sys.argv[1])


if __name__ == "__main__":
    main()
