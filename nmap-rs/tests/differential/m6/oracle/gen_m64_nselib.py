#!/usr/bin/env python3
"""Run nmap itself over this repository's nselib/ and record, for each
library, whether it loads, and for each library with a test suite, whether its
unit tests pass: the golden for crates/core/tests/nselib_differential.rs.

    python3 oracle/gen_m64_nselib.py OUTDIR   ->  OUTDIR/m64_nselib_golden.txt

nmap is the installed one, pointed at this repository's data directory with
`--datadir`, so that it loads exactly the nselib/ the port loads. Each probe
script (oracle/m64_probe_*.nse) runs as a prerule against 127.0.0.1 with no
port scan (-sn), so nothing is sent anywhere. Rows:

    require<TAB>LIB<TAB>ok | error<TAB>MESSAGE
    unittest<TAB>LIB<TAB>pass | fail<TAB>DETAIL | error<TAB>MESSAGE
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
NSELIB = os.path.join(REPO, "nselib")


def run_probe(probe, libs, out):
    subprocess.run(
        ["nmap", "--datadir", REPO, "-sn", "-n", "--script", os.path.join(HERE, probe),
         "--script-args", "out=%s,libs=%s" % (out, libs), "127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL)
    with open(out, encoding="latin-1") as fh:
        return fh.read().splitlines()


def main():
    outdir = sys.argv[1] if len(sys.argv) > 1 else "."
    libs = sorted(f[:-4] for f in os.listdir(NSELIB) if f.endswith(".lua"))
    tests = [l for l in libs
             if "test_suite" in open(os.path.join(NSELIB, l + ".lua"), encoding="latin-1").read()]
    rows = []
    with tempfile.TemporaryDirectory() as tmp:
        for kind, probe, names in [("require", "m64_probe_require.nse", libs),
                                   ("unittest", "m64_probe_unittest.nse", tests)]:
            listing = os.path.join(tmp, kind + ".txt")
            with open(listing, "w") as fh:
                fh.write("\n".join(names) + "\n")
            for line in run_probe(probe, listing, os.path.join(tmp, kind + ".out")):
                rows.append(kind + "\t" + line)
    version = subprocess.run(["nmap", "--version"], capture_output=True, text=True).stdout.splitlines()[0]
    with open(os.path.join(outdir, "m64_nselib_golden.txt"), "w", encoding="latin-1") as fh:
        fh.write("# kind\tlibrary\toutcome\t[detail]\n")
        fh.write("# %s over this repository's nselib/ (--datadir). Regenerate with\n" % version)
        fh.write("# python3 oracle/gen_m64_nselib.py tests/differential/m6\n")
        for r in rows:
            fh.write(r + "\n")


if __name__ == "__main__":
    main()
