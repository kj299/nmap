#!/usr/bin/env python3
"""M7 cutover step c: `--host-timeout` in the port scans, against 7.94 itself.

Runs each case under the installed nmap 7.94 and the port's binary, and compares
the verdicts, not the times, which vary (`docs/M7-CUTOVER-ANALYSIS.md` §5.2):

* normal output: each reported host, and whether it is "Skipping host X due to
  host timeout" or its port lines; the "N hosts up" count;
* grepable: each host's `Status:` records, and its `Ports:` entries;
* XML: each `<host>`'s `timedout`, its status, and its `<port>` elements;
* the exit status.

The port's ledgered differences are left out of what is compared: latency, the
blank line before a port table, and XML attributes it does not write.

Loopback only, as root (the raw cases need it); it sends nothing off the machine.
Usage: sudo python3 host_timeout_diff.py --port PATH [--nmap nmap]
"""
import argparse
import os
import re
import socket
import subprocess
import sys
import tempfile
import threading
import xml.etree.ElementTree as ET

SLOW = ["-p", "1-3000", "--scan-delay", "20ms", "--host-timeout", "1s"]


def listener():
    """A loopback port that accepts, for the case whose host finishes in time."""
    s = socket.socket()
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0))
    s.listen(16)

    def serve():
        while True:
            try:
                c, _ = s.accept()
                c.close()
            except OSError:
                return

    threading.Thread(target=serve, daemon=True).start()
    return s, s.getsockname()[1]


def cases(open_port):
    two = ["127.0.0.1", "127.0.0.2"]
    return [
        ("connect, two hosts out of time", ["-sT", "-Pn", "-n", *SLOW, *two]),
        ("SYN, two hosts out of time", ["-sS", "-Pn", "-n", *SLOW, *two]),
        ("connect, routed (no -Pn)", ["-sT", "-n", *SLOW, "127.0.0.1"]),
        ("one host per group", ["-sT", "-Pn", "-n", *SLOW, "--max-hostgroup", "1", *two]),
        ("--open does not drop them", ["-sT", "-Pn", "-n", "--open", *SLOW, *two]),
        ("-v --reason", ["-sT", "-Pn", "-n", "-v", "--reason", *SLOW, "127.0.0.1"]),
        # Q4: a host that finishes inside its budget is kept, however small.
        (
            "a 1 ms budget that is met",
            ["-sT", "-Pn", "-n", "-p", str(open_port), "--host-timeout", "1ms", "127.0.0.1"],
        ),
        (
            "no budget",
            ["-sT", "-Pn", "-n", "-p", str(open_port), "--host-timeout", "0", "127.0.0.1"],
        ),
    ]


def run(binary, args, tmp):
    base = os.path.join(tmp, "out")
    for ext in ("n", "g", "x"):
        try:
            os.unlink(f"{base}.{ext}")
        except FileNotFoundError:
            pass
    p = subprocess.run(
        [binary, *args, "-oN", base + ".n", "-oG", base + ".g", "-oX", base + ".x"],
        capture_output=True,
        text=True,
        timeout=120,
    )
    read = lambda ext: open(f"{base}.{ext}").read()
    return p.returncode, read("n"), read("g"), read("x")


def normal_verdicts(text):
    hosts, cur = [], None
    for line in text.splitlines():
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            cur = [m.group(1), "ports", []]
            hosts.append(cur)
        elif cur and line.startswith("Skipping host "):
            cur[1] = "timed out"
        elif cur and re.match(r"\d+/(tcp|udp)\s", line):
            cur[2].append(" ".join(line.split()[:2]))
    up = re.search(r"\((\d+) hosts? up\)", text)
    return [tuple([h[0], h[1], tuple(h[2])]) for h in hosts], up and up.group(1)


def grepable_verdicts(text):
    out = []
    for line in text.splitlines():
        if line.startswith("#"):
            continue
        m = re.match(r"Host: (\S+) \(.*?\)\t(Status|Ports): (.*)", line)
        if m:
            what = m.group(3) if m.group(2) == "Status" else "ports " + " ".join(
                e.split("/")[0] + "/" + e.split("/")[1] for e in m.group(3).split("\t")[0].split(", ")
            )
            out.append((m.group(1), m.group(2), what))
    return out


def xml_verdicts(text):
    root = ET.fromstring(text)
    out = []
    for h in root.findall("host"):
        addr = h.find("address").get("addr")
        status = h.find("status").get("state")
        ports = tuple(
            f"{p.get('portid')}/{p.find('state').get('state')}" for p in h.iter("port")
        )
        out.append((addr, h.get("timedout") == "true", status, ports))
    return out


def verdicts(result):
    rc, n, g, x = result
    return {
        "exit": rc,
        "normal": normal_verdicts(n),
        "grepable": grepable_verdicts(g),
        "xml": xml_verdicts(x),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", required=True, help="the port's nmap-rs binary")
    ap.add_argument("--nmap", default="nmap")
    args = ap.parse_args()
    if os.geteuid() != 0:
        print("SKIP: the raw cases need root")
        return 0
    sock, open_port = listener()
    bad = 0
    with tempfile.TemporaryDirectory() as tmp:
        for name, argv in cases(open_port):
            want = verdicts(run(args.nmap, argv, tmp))
            got = verdicts(run(args.port, argv, tmp))
            if want == got:
                print(f"ok    {name}")
            else:
                bad += 1
                print(f"FAIL  {name}: {' '.join(argv)}")
                for k in want:
                    if want[k] != got[k]:
                        print(f"  {k}: 7.94 {want[k]}\n  {' ' * len(k)}  port {got[k]}")
    sock.close()
    print(f"host timeout: {len(cases(open_port)) - bad} of {len(cases(open_port))} cases match 7.94")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
