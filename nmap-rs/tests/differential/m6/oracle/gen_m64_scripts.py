#!/usr/bin/env python3
"""Run nmap itself over the fixture scripts in nse_scripts/ and record what
every script left: the golden for crates/core/tests/scripts_differential.rs.

    python3 oracle/gen_m64_scripts.py OUTDIR  ->  OUTDIR/m64_scripts_golden.txt

nmap is the installed one (7.94, as CI installs it), pointed with `--datadir` at
a scratch data directory: this repository's data files and nselib/, with
scripts/ holding the fixtures (their own script.db included) and the shipped
scripts in SHIPPED. Each scenario
is one nmap run, a connect scan of loopback listeners on fixed ports, with a
--script selection; nothing is sent beyond 127.0.0.1. Rows:

    scenario NAME
    args HEX              the nmap arguments after the fixed ones, NUL-separated
    port PROTO NUMBER STATE REASON TTL     the scan's facts, from -oX
    init_error HEX        when the engine failed to start: its message's
                          first line, with nmap's `nse_main.lua:N: ` dropped
    result CONTAINER ID NORMAL_HEX|- XML_HEX
                          CONTAINER is pre, host, post or port:PROTO/NUMBER;
                          NORMAL the lines formatScriptOutput printed, `-`
                          when it printed none; XML the <script> element.
                          Sorted by container, then id.

The data directory's path is written as DATADIR wherever it appears.
"""

import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(M6, "..", "..", "..", ".."))
FIXTURES = os.path.join(M6, "nse_scripts")

OPEN_PORTS = (46020, 46021)
CLOSED_PORT = 46022
PORTS = "%d,%d,%d" % (OPEN_PORTS + (CLOSED_PORT,))

# Shipped scripts run beside the fixtures, by name (they are not in the
# fixtures' script.db).
SHIPPED = ["unittest.nse"]

# The nselib/ test suites that pass under the port (nselib_differential.rs pins
# the other four on C modules not yet ported).
SUITES = ("asn1,base32,base64,bits,comm,dns,formulas,gps,http,idna,ipOps,mqtt,"
          "mssql,packet,punycode,sasl,smbauth,tls,unicode,unittest,url,vnc")

SCENARIOS = [
    ("shapes", ["--script", "shapes"]),
    ("rules", ["--script", "rules"]),
    ("errors", ["--script", "errors"]),
    ("forced", ["--script", "+forceme"]),
    ("not-forced", ["--script", "forceme"]),
    ("deps", ["--script", "deps"]),
    ("args", ["--script", "s-args", "--script-args", "s-args.a=1,b={x,y}"]),
    ("args-none", ["--script", "s-args"]),
    ("cats-and-not", ["--script", "testa and not testb"]),
    ("cats-or", ["--script", "testa or testb"]),
    ("cats-paren", ["--script", "(testa or testb) and not c-both"]),
    ("default", ["-sC"]),
    ("default-plus", ["-sC", "--script", "testb"]),
    ("glob", ["--script", "c-*"]),
    ("all-but", ["--script", "all and not (errors or shapes or rules or circular or deps or args)"]),
    ("directory", ["--script", "subdir/"]),
    ("bare-directory", ["--script", "subdir"]),
    ("no-match", ["--script", "no-such-script"]),
    ("no-match-expr", ["--script", "testa and testb and shapes"]),
    ("no-extension", ["--script", "n-noext.lua"]),
    ("with-extension", ["--script", "s-string.nse"]),
    ("duplicate", ["--script", "s-string,s-string.nse,shapes"]),
    ("multi", ["--script", "s-string,s-table,s-number,s-pair"]),
    ("e-noaction", ["--script", "e-noaction"]),
    ("e-badcats", ["--script", "e-badcats"]),
    ("e-norule", ["--script", "e-norule"]),
    ("e-badrule", ["--script", "e-badrule"]),
    ("e-badcatentry", ["--script", "e-badcatentry"]),
    ("e-toperror", ["--script", "e-toperror"]),
    ("e-silentrequire", ["--script", "e-silentrequire"]),
    ("circular", ["--script", "circular"]),
    ("shipped-unittest", ["--script", "unittest", "--script-args",
                          "unittest.run=1,unittest.tests={%s}" % SUITES]),
    ("shipped-unittest-off", ["--script", "unittest"]),
]


def listeners(stop):
    socks = []
    for port in OPEN_PORTS:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(64)
        s.settimeout(0.2)
        socks.append(s)

        def loop(s=s):
            while not stop.is_set():
                try:
                    c, _ = s.accept()
                    c.close()
                except OSError:
                    continue
        threading.Thread(target=loop, daemon=True).start()
    return socks


def datadir(tmp):
    d = os.path.join(tmp, "data")
    os.mkdir(d)
    for name in os.listdir(REPO):
        if name == "nselib" or name == "nse_main.lua" or name.startswith("nmap-"):
            os.symlink(os.path.join(REPO, name), os.path.join(d, name))
    scripts = os.path.join(d, "scripts")
    os.mkdir(scripts)
    for name in os.listdir(FIXTURES):
        os.symlink(os.path.join(FIXTURES, name), os.path.join(scripts, name))
    for name in SHIPPED:
        os.symlink(os.path.join(REPO, "scripts", name), os.path.join(scripts, name))
    return d


def results_of(xml_text, normal_text, data):
    """Per container, the (id, normal, xml) of each result."""
    out = []

    def scripts(fragment):
        return [(m.group(1), m.group(0)) for m in re.finditer(
            r'<script id="([^"]*)" output="[^"]*"(?:/>|>.*?</script>)', fragment, re.S)]

    def normals(lines):
        groups, cur = {}, []
        for l in lines:
            cur.append(l)
            if l.startswith("|_"):
                first = cur[0][2:]
                rid = first.split(": ", 1)[0]
                groups[rid] = "\n".join(cur)
                cur = []
        return groups

    def block(text, start):
        """The `|` lines after the line `start` matches."""
        lines = text.split("\n")
        for i, l in enumerate(lines):
            if re.match(start, l):
                got = []
                for m in lines[i + 1:]:
                    if m.startswith("|"):
                        got.append(m)
                    elif m.startswith("Bug in ") or m == "":
                        # nmap's error() for a result with no text lands in
                        # the normal output, between results.
                        continue
                    else:
                        break
                return got
        return []

    def add(container, xml_fragment, normal_lines):
        n = normals(normal_lines)
        for rid, x in sorted(scripts(xml_fragment)):
            out.append((container, rid, n.get(rid), x))

    for tag, cont, head in (("prescript", "pre", r"^Pre-scan script results:$"),
                            ("postscript", "post", r"^Post-scan script results:$"),
                            ("hostscript", "host", r"^Host script results:$")):
        m = re.search(r"<%s>(.*?)</%s>" % (tag, tag), xml_text, re.S)
        if m:
            add(cont, m.group(1), block(normal_text, head))
    for m in re.finditer(r'<port protocol="(\w+)" portid="(\d+)">(.*?)</port>', xml_text, re.S):
        proto, num, body = m.groups()
        add("port:%s/%s" % (proto, num), body, block(normal_text, r"^%s/%s\s" % (num, proto)))
    return sorted(out, key=lambda r: (r[0], r[1]))


def hexs(s):
    return s.encode("latin-1").hex()


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    stop = threading.Event()
    socks = listeners(stop)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        data = datadir(tmp)
        for name, extra in SCENARIOS:
            xml_path = os.path.join(tmp, name + ".xml")
            nml_path = os.path.join(tmp, name + ".nmap")
            cmd = ["nmap", "--datadir", data, "-sT", "-Pn", "-n", "-p", PORTS,
                   "-oX", xml_path, "-oN", nml_path] + extra + ["127.0.0.1"]
            p = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                               env=dict(os.environ, NMAPDIR=data))
            console = p.stdout.decode("latin-1").replace(data, "DATADIR")
            rows.append("scenario %s" % name)
            rows.append("args %s" % "\0".join(extra).encode().hex())
            m = re.search(r"failed to initialize the script engine:\n(.*)", console)
            if m:
                msg = re.sub(r"^.*?nse_main\.lua:\d+: ", "", m.group(1))
                rows.append("init_error %s" % hexs(msg))
                continue
            xml_text = open(xml_path, encoding="latin-1").read().replace(data, "DATADIR")
            normal_text = open(nml_path, encoding="latin-1").read().replace(data, "DATADIR")
            for port in ET.fromstring(xml_text.encode("latin-1")).iter("port"):
                st = port.find("state")
                rows.append("port %s %s %s %s %s" % (
                    port.get("protocol"), port.get("portid"), st.get("state"),
                    st.get("reason"), st.get("reason_ttl")))
            for cont, rid, normal, x in results_of(xml_text, normal_text, data):
                rows.append("result %s %s %s %s" % (
                    cont, hexs(rid), hexs(normal) if normal is not None else "-", hexs(x)))
    stop.set()
    for s in socks:
        s.close()
    version = subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE).stdout.decode().split("\n")[0]
    with open(os.path.join(outdir, "m64_scripts_golden.txt"), "w") as fh:
        fh.write("# Generated by oracle/gen_m64_scripts.py from %s. Do not edit by hand.\n" % version)
        fh.write("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
