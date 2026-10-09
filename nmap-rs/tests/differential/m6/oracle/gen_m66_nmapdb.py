#!/usr/bin/env python3
"""Run nmap itself through every function of its C module `nmapdb`
(nse_db.cc), over this repository's data files: the golden for M6.6's
`nmapdb` port.

    python3 oracle/gen_m66_nmapdb.py OUTDIR  ->  OUTDIR/m66_nmapdb_golden.txt
                                                 OUTDIR/m66_nmapdb_quarantine.txt

nmap is the installed one (7.94, as CI installs it), pointed at this repository
with `--datadir`, so that `nmapdb` reads the nmap-mac-prefixes, nmap-services
and nmap-protocols this tree ships, which are not the installed ones. The probe
(oracle/m66_probe_nmapdb.nse) runs as a prerule with -sn against 127.0.0.1, so
nothing is sent anywhere. The golden holds its lines, `tag|call|outcome`, in
the order it wrote them; the two data files' paths are written as their names.

The generator checks that the probe read this tree's files, not the installed
ones: the paths `nmap.fetchfile` gave it, and that the counts it saw (every
prefix found, every protocol name known, the services per protocol) are this
tree's.

The quarantine file lists the calls the probe does not make, because they
abort or are undefined in 7.94 (LESSONS #033), each with its defect's ledger id.
"""

import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
PROBE = os.path.join(HERE, "m66_probe_nmapdb.nse")
DATA_FILES = ("nmap-mac-prefixes", "nmap-protocols")


def run_probe(out, mode):
    subprocess.run(
        ["nmap", "--datadir", REPO, "-sn", "-n", "--script", PROBE,
         "--script-args", "out=%s,mode=%s" % (out, mode), "127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL)
    with open(out, encoding="latin-1") as fh:
        lines = fh.read().splitlines()
    if not lines or lines[-1] != "done":
        sys.exit("FAIL: the %s probe did not finish (last line %r)" % (mode, lines[-1:]))
    return lines[:-1]


def tree_prefixes():
    """The prefixes in this tree's nmap-mac-prefixes, as the probe reads them."""
    n = 0
    with open(os.path.join(REPO, "nmap-mac-prefixes"), encoding="latin-1") as fh:
        for line in fh:
            m = re.match(r"([0-9A-Fa-f]+)\s", line)
            if m and len(m.group(1)) in (6, 7, 9):
                n += 1
    return n


def tree_protocols():
    """The names in this tree's nmap-protocols, as the probe reads them."""
    with open(os.path.join(REPO, "nmap-protocols"), encoding="latin-1") as fh:
        return sum(1 for line in fh if re.match(r"\s*[^\s#]+\s+\d+", line))


def tree_services():
    """Per protocol, the ports this tree's nmap-services names other than
    `unknown`: the first line for a port wins (services.cc:240-247), and C
    stores `unknown` as no name (services.cc:228-232)."""
    seen = {}
    with open(os.path.join(REPO, "nmap-services"), encoding="latin-1") as fh:
        for line in fh:
            if line.lstrip().startswith("#"):
                continue
            m = re.match(r"(\S+)\s+(\d+)/(tcp|udp|sctp)\b", line)
            if m:
                seen.setdefault((m.group(3), int(m.group(2))), m.group(1))
    count = {"tcp": 0, "udp": 0, "sctp": 0}
    for (proto, _), name in seen.items():
        if name != "unknown":
            count[proto] += 1
    return count


def check_tree_data(lines):
    """Fail unless the probe read this repository's data files."""
    def field(tag):
        rows = [l for l in lines if l.startswith(tag + "|")]
        if len(rows) != 1:
            sys.exit("FAIL: %d %s lines" % (len(rows), tag))
        return rows[0].split("|")
    for tag, name in (("macfile", "nmap-mac-prefixes"), ("protofile", "nmap-protocols")):
        got = field(tag)[1]
        if os.path.realpath(got) != os.path.realpath(os.path.join(REPO, name)):
            sys.exit("FAIL: the probe read %s, not this tree's %s" % (got, name))
    want = "mac_pfx_count|%d|mismatch=0|nil=0" % tree_prefixes()
    if "|".join(field("mac_pfx_count")) != want:
        sys.exit("FAIL: %s, want %s" % ("|".join(field("mac_pfx_count")), want))
    gpna = [l for l in lines if l.startswith("gpna|")]
    if len(gpna) != tree_protocols() or not all(l.split("|")[2].startswith("i:") for l in gpna):
        sys.exit("FAIL: nmapdb does not know this tree's %d protocol names" % tree_protocols())
    for proto, n in tree_services().items():
        if "gsp_count|%s|%d" % (proto, n) not in lines:
            sys.exit("FAIL: nmapdb's %s services are not this tree's %d" % (proto, n))


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    with tempfile.TemporaryDirectory() as tmp:
        lines = run_probe(os.path.join(tmp, "main.out"), "main")
        quarantine = run_probe(os.path.join(tmp, "quarantine.out"), "quarantine")
    check_tree_data(lines)
    shown = {}
    for name in DATA_FILES:
        shown[os.path.join(REPO, name)] = name
    rows = []
    for l in lines:
        tag, _, rest = l.partition("|")
        if tag in ("macfile", "protofile"):
            l = tag + "|" + shown.get(rest, rest)
        rows.append(l)
    leak = [l for l in rows if REPO in l]
    if leak:
        sys.exit("FAIL: the repository's path is in the golden: %r" % leak[0])
    version = subprocess.run(["nmap", "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    with open(os.path.join(outdir, "m66_nmapdb_golden.txt"), "w", encoding="latin-1") as fh:
        fh.write("# tag|call|outcome, as oracle/m66_probe_nmapdb.nse wrote them\n")
        fh.write("# %s, `nmapdb` over this repository's data files (--datadir).\n" % version)
        fh.write("# Regenerate with bash tests/differential/m6/regen_m66_nmapdb.sh\n")
        for r in rows:
            fh.write(r + "\n")
    with open(os.path.join(outdir, "m66_nmapdb_quarantine.txt"), "w", encoding="latin-1") as fh:
        fh.write("# quarantine|call|ledger id: calls oracle/m66_probe_nmapdb.nse does not make,\n")
        fh.write("# because they abort or are undefined in %s.\n" % version.split(" (")[0])
        fh.write("# Each is pinned in the port by a unit test instead (LESSONS #033).\n")
        fh.write("# Regenerate with bash tests/differential/m6/regen_m66_nmapdb.sh\n")
        for r in quarantine:
            fh.write(r + "\n")


if __name__ == "__main__":
    main()
