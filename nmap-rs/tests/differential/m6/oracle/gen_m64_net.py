#!/usr/bin/env python3
"""Run nmap itself over the socket fixture scripts in nse_net/: the golden for
crates/sys/tests/nse_net_differential.rs (M6.4d).

    python3 oracle/gen_m64_net.py OUTDIR  ->  OUTDIR/m64_net_golden.txt

As gen_m64_scripts.py, with nse_net/ as the scripts directory and a set of
loopback services the scripts talk to:

    46030/tcp  echo: sends back whatever it receives
    46031/tcp  banner: "line1\\nline2\\r\\nline3", then closes
    46032/tcp  silent: accepts, never sends, holds the connection 10s
    46033/tcp  closed: nothing listens
    46034/udp  echo
    46035/tcp  drip: "ab", "c\\nd", "e\\n", "fgh" 200ms apart, then closes
    46036/udp  nothing listens

Rows are gen_m64_scripts.py's.
"""

import importlib.util
import os
import socket
import subprocess
import sys
import tempfile
import threading
import time

HERE = os.path.dirname(os.path.abspath(__file__))
spec = importlib.util.spec_from_file_location("gen_m64_scripts", os.path.join(HERE, "gen_m64_scripts.py"))
base = importlib.util.module_from_spec(spec)
spec.loader.exec_module(base)

M6 = os.path.dirname(HERE)
REPO = base.REPO
FIXTURES = os.path.join(M6, "nse_net")
PORTS = "46030,46033"

SCENARIOS = [
    ("net", ["--script", "net"]),
    ("script-timeout", ["--script", "slow", "--script-timeout", "1"]),
]


def serve(stop):
    socks = []

    def tcp(port, handler):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind(("127.0.0.1", port))
        s.listen(64)
        s.settimeout(0.2)
        socks.append(s)

        def loop():
            while not stop.is_set():
                try:
                    c, _ = s.accept()
                except OSError:
                    continue
                threading.Thread(target=handler, args=(c,), daemon=True).start()
        threading.Thread(target=loop, daemon=True).start()

    def echo(c):
        c.settimeout(10)
        try:
            while True:
                d = c.recv(4096)
                if not d:
                    break
                c.sendall(d)
        except OSError:
            pass
        c.close()

    def banner(c):
        c.sendall(b"line1\nline2\r\nline3")
        time.sleep(0.1)
        c.close()

    def silent(c):
        time.sleep(10)
        c.close()

    def drip(c):
        for piece in (b"ab", b"c\nd", b"e\n", b"fgh"):
            c.sendall(piece)
            time.sleep(0.2)
        c.close()

    tcp(46030, echo)
    tcp(46031, banner)
    tcp(46032, silent)
    tcp(46035, drip)
    u = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    u.bind(("127.0.0.1", 46034))
    u.settimeout(0.2)
    socks.append(u)

    def uloop():
        while not stop.is_set():
            try:
                d, a = u.recvfrom(65535)
                u.sendto(d, a)
            except OSError:
                continue
    threading.Thread(target=uloop, daemon=True).start()
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
    return d


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    stop = threading.Event()
    socks = serve(stop)
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        data = datadir(tmp)
        for name, extra in SCENARIOS:
            xml_path = os.path.join(tmp, name + ".xml")
            nml_path = os.path.join(tmp, name + ".nmap")
            cmd = ["nmap", "--datadir", data, "-sT", "-Pn", "-n", "-p", PORTS,
                   "-oX", xml_path, "-oN", nml_path] + extra + ["127.0.0.1"]
            subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                           env=dict(os.environ, NMAPDIR=data))
            rows.append("scenario %s" % name)
            rows.append("args %s" % "\0".join(extra).encode().hex())
            xml_text = open(xml_path, encoding="latin-1").read().replace(data, "DATADIR")
            normal_text = open(nml_path, encoding="latin-1").read().replace(data, "DATADIR")
            import xml.etree.ElementTree as ET
            for port in ET.fromstring(xml_text.encode("latin-1")).iter("port"):
                st = port.find("state")
                rows.append("port %s %s %s %s %s" % (
                    port.get("protocol"), port.get("portid"), st.get("state"),
                    st.get("reason"), st.get("reason_ttl")))
            for cont, rid, normal, x in base.results_of(xml_text, normal_text, data):
                rows.append("result %s %s %s %s" % (
                    cont, base.hexs(rid), base.hexs(normal) if normal is not None else "-", base.hexs(x)))
    stop.set()
    for s in socks:
        s.close()
    version = subprocess.run(["nmap", "--version"], stdout=subprocess.PIPE).stdout.decode().split("\n")[0]
    with open(os.path.join(outdir, "m64_net_golden.txt"), "w") as fh:
        fh.write("# Generated by oracle/gen_m64_net.py from %s. Do not edit by hand.\n" % version)
        fh.write("\n".join(rows) + "\n")


if __name__ == "__main__":
    main()
