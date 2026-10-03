#!/usr/bin/env python3
"""Generate the M6.3 differential golden: the `nmap` module against nmap itself.

The oracle is an installed nmap 7.94 (the distribution's package, which CI also
installs), whose `nse_nmaplib.cc` differs from this repository's only inside
`nmap.resolve` -- an I/O function outside M6.3. Each scenario scans loopback
fixtures twice:

  1. without scripts, `-oX`: the scan's own facts -- every port's state,
     reason, TTL and service record, and the host's names and reason -- taken
     before any script can change them;
  2. with `oracle/m63_probe.nse`: what the module said, as the probe printed
     it, and the lines it logged.

The golden records the command line, the facts, the probe's output and the
log lines. `crates/core/tests/nmaplib_differential.rs` rebuilds the host from
the facts, the options from the command line, runs the same probe through the
port, and compares everything.

A few host facts have no source but the probe itself -- the interface name and
MTU, the source address, `directly_connected`, the timing estimates -- because
`-oX` does not record them. Those are passed through: the comparison checks how
the port renders them, not where they come from.

Must run as root (UDP and IPv6 scans of loopback). Usage:

  sudo python3 gen_m63_nmap.py OUTDIR
"""

import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET

HERE = os.path.dirname(os.path.abspath(__file__))
PROBE = os.path.join(HERE, "m63_probe.nse")
SERVICES = "/usr/share/nmap/nmap-services"

TCP_OPEN_BANNER = 46001   # speaks SSH, so -sV hard-matches it
TCP_OPEN_SILENT = 46002   # accepts and says nothing
TCP_CLOSED = 46003
UDP_OPEN = 46001          # answers any datagram


def fixtures(stop):
    socks = []

    def tcp(family, addr, port, banner):
        s = socket.socket(family, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((addr, port))
        s.listen(64)
        s.settimeout(0.2)
        socks.append(s)

        def loop():
            while not stop.is_set():
                try:
                    c, _ = s.accept()
                except OSError:
                    continue
                try:
                    if banner:
                        c.sendall(banner)
                    time.sleep(0.3)
                except OSError:
                    pass
                c.close()
        threading.Thread(target=loop, daemon=True).start()

    def udp(addr, port):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.bind((addr, port))
        s.settimeout(0.2)
        socks.append(s)

        def loop():
            while not stop.is_set():
                try:
                    data, peer = s.recvfrom(4096)
                except OSError:
                    continue
                s.sendto(b"m63\n", peer)
        threading.Thread(target=loop, daemon=True).start()

    banner = b"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\r\n"
    families = [(socket.AF_INET, "127.0.0.1")] + ([(socket.AF_INET6, "::1")] if HAVE_IPV6 else [])
    for fam, addr in families:
        tcp(fam, addr, TCP_OPEN_BANNER, banner)
        tcp(fam, addr, TCP_OPEN_SILENT, None)
    udp("127.0.0.1", UDP_OPEN)
    return socks


def have_ipv6():
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


# A host without IPv6 loopback (some containers) skips the `ipv6` scenario;
# CI's runners have it, and CI regenerates the golden before testing.
HAVE_IPV6 = have_ipv6()

TCP_PORTS = "1,7,%d-%d" % (TCP_OPEN_BANNER, TCP_CLOSED)

# (name, scan arguments, how the probe is selected, extra NSE arguments)
# `by_name` selects the probe by its path; otherwise by its category, through
# a --datadir whose script.db lists it.
SCENARIOS = [
    ("basic", ["-sT", "-Pn", "-n", "-p", TCP_PORTS, "127.0.0.1"], True, []),
    ("category", ["-sT", "-Pn", "-n", "-p", TCP_PORTS, "127.0.0.1"], False, []),
    ("options", ["-sT", "-Pn", "-n", "-v", "-d", "-T4", "--ttl", "33", "--data-length", "20",
                 "-e", "lo", "-p", TCP_PORTS, "127.0.0.1"], False,
     ["--script-args", "script-intensity=5,foo={a,\"b c\"},k=v"]),
    ("intensity_bad", ["-sT", "-Pn", "-n", "--version-intensity", "3", "-p", TCP_PORTS, "127.0.0.1"],
     False, ["--script-args", "script-intensity=12"]),
    ("intensity_default", ["-sT", "-Pn", "-n", "--version-intensity", "4", "-p", TCP_PORTS,
                           "127.0.0.1"], False, []),
    ("ttl_out_of_range", ["-sT", "-Pn", "-n", "-d2", "-p", TCP_PORTS, "127.0.0.1"], True,
     ["--script-args", "a=1"]),
    ("version_scan", ["-sV", "-Pn", "-n", "-p", TCP_PORTS + ",9100", "127.0.0.1"], True, []),
    ("version_allports", ["-sV", "--allports", "-Pn", "-n", "-p", TCP_PORTS + ",9100", "127.0.0.1"],
     True, []),
    ("ipv6", ["-6", "-sT", "-Pn", "-n", "-p", TCP_PORTS, "::1"], True, []),
    ("udp", ["-sT", "-sU", "-Pn", "-n", "-p", "T:1,7,%d,%d,U:7,9,%d" % (TCP_OPEN_BANNER, TCP_CLOSED, UDP_OPEN),
             "127.0.0.1"], True, []),
]


def run(args):
    r = subprocess.run(["nmap"] + args, capture_output=True, timeout=300)
    return r.returncode, r.stdout.decode("latin-1"), r.stderr.decode("latin-1")


def target_host(xml_path):
    root = ET.parse(xml_path).getroot()
    for host in root.findall("host"):
        for a in host.findall("address"):
            if a.get("addr") in ("127.0.0.1", "::1"):
                return host
    raise SystemExit("no loopback host in " + xml_path)


def hx(s):
    return (s if isinstance(s, bytes) else s.encode("latin-1")).hex()


def service_table():
    names = {}
    with open(SERVICES, encoding="latin-1") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            f = line.split()
            if len(f) >= 2 and "/" in f[1]:
                port, proto = f[1].split("/", 1)
                names.setdefault((int(port), proto), f[0])
    return names


# What the probe logs, and what nmap logs on its behalf. Applied identically
# to the port's log.
LOG_LINE = re.compile(
    r"^(NSE: m63-log|NSE: 63$|finalizing a non-conforming|ERROR: (adding targets|new target)"
    r"|Warning: Valid values of script arg|EXCLUDING |New Targets: |Discovered \S+ port \S+ on (127\.0\.0\.1|::1)$)"
)


def log_lines(text, after_marker):
    lines = text.splitlines()
    if after_marker:
        idx = [i for i, l in enumerate(lines) if l == "NSE: m63-log begin"]
        if not idx:
            raise SystemExit("the probe never logged its marker")
        lines = lines[idx[0]:]
    return [l for l in lines if LOG_LINE.match(l)]


def main():
    out_dir = sys.argv[1] if len(sys.argv) > 1 else "."
    if os.geteuid() != 0:
        raise SystemExit("run as root: the UDP and IPv6 scenarios need raw sockets")
    stop = threading.Event()
    socks = fixtures(stop)
    work = tempfile.mkdtemp()
    services = service_table()
    try:
        datadir = os.path.join(work, "datadir")
        os.makedirs(os.path.join(datadir, "scripts"))
        shutil.copy(PROBE, os.path.join(datadir, "scripts", "m63_probe.nse"))
        with open(os.path.join(datadir, "scripts", "script.db"), "w") as fh:
            fh.write('Entry { filename = "m63_probe.nse", categories = { "m63probe", } }\n')
        blocks = []
        for name, scan, by_name, nse in SCENARIOS:
            if "-6" in scan and not HAVE_IPV6:
                print("%s: skipped, no IPv6 loopback here" % name, file=sys.stderr)
                continue
            facts_xml = os.path.join(work, name + "-facts.xml")
            rc, _, err = run(scan + ["-oX", facts_xml])
            if rc != 0:
                raise SystemExit("%s: fact scan failed: %s" % (name, err[-500:]))
            probe_xml = os.path.join(work, name + "-probe.xml")
            sel = ["--script", PROBE] if by_name else ["--datadir", datadir, "--script", "m63probe"]
            rc, stdout, stderr = run(scan + sel + nse + ["-oX", probe_xml])
            if rc != 0:
                raise SystemExit("%s: probe scan failed: %s" % (name, stderr[-500:]))
            fh = target_host(facts_xml)
            ph = target_host(probe_xml)
            output = None
            for s in ph.iter("script"):
                if s.get("id") == "m63_probe":
                    output = s.get("output")
            if output is None:
                raise SystemExit("%s: the probe did not run" % name)

            b = ["scenario " + name, "by_name %d" % int(by_name)]
            b += ["arg " + hx(a) for a in scan + nse]
            ip = [a.get("addr") for a in ph.findall("address") if a.get("addrtype") in ("ipv4", "ipv6")][0]
            b.append("host ip " + hx(ip))
            for hn in ph.findall("hostnames/hostname"):
                b.append("host %s %s" % ("targetname" if hn.get("type") == "user" else "hostname",
                                         hx(hn.get("name"))))
            st = ph.find("status")
            b.append("host reason %s %s" % (hx(st.get("reason")), st.get("reason_ttl")))
            for a in ph.findall("address"):
                if a.get("addrtype") == "mac":
                    b.append("host mac " + hx(bytes.fromhex(a.get("addr").replace(":", ""))))
            for p in fh.findall("ports/port"):
                s = p.find("state")
                line = "port %s %s %s %s %s" % (p.get("portid"), p.get("protocol"), s.get("state"),
                                                hx(s.get("reason")), s.get("reason_ttl"))
                b.append(line)
                svc = p.find("service")
                if svc is not None and (svc.get("method") == "probed" or svc.get("servicefp")):
                    for k in ("name", "product", "version", "extrainfo", "hostname", "ostype",
                              "devicetype", "tunnel", "servicefp", "method", "conf"):
                        if svc.get(k) is not None:
                            b.append("svc %s %s %s %s" % (p.get("portid"), p.get("protocol"), k, hx(svc.get(k))))
                    for c in svc.findall("cpe"):
                        b.append("svc %s %s cpe %s" % (p.get("portid"), p.get("protocol"), hx(c.text or "")))
                    b.append("svc %s %s record 00" % (p.get("portid"), p.get("protocol")))
            ports = {(int(p.get("portid")), p.get("protocol")) for p in fh.findall("ports/port")}
            for (num, proto) in sorted(ports | {(59999, "tcp")}):
                if (num, proto) in services:
                    b.append("svcname %d %s %s" % (num, proto, hx(services[(num, proto)])))
            b.append("output " + hx(output))
            b += ["stdout " + hx(l) for l in log_lines(stdout, True)]
            b += ["stderr " + hx(l) for l in log_lines(stderr, False)]
            b.append("end")
            blocks.append("\n".join(b))
            print("%s: %d output lines" % (name, output.count("\n") + 1), file=sys.stderr)
    finally:
        stop.set()
        for s in socks:
            s.close()
        shutil.rmtree(work, ignore_errors=True)
    with open(os.path.join(out_dir, "m63_nmap_golden.txt"), "w") as fh:
        fh.write("# Generated by oracle/gen_m63_nmap.py from nmap 7.94; see that file.\n")
        fh.write("\n".join(blocks) + "\n")


if __name__ == "__main__":
    main()
