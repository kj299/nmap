#!/usr/bin/env python3
"""Run nmap itself through the base and coroutine libraries as an NSE script
meets them: the golden for the first-party `core::nse::stdlib::base`.

    python3 oracle/gen_m6_base.py OUTDIR   ->  OUTDIR/m6_base_golden.txt
    python3 oracle/gen_m6_base.py --check      FAIL unless the committed golden
                                               is what this nmap gives now

nmap is the installed one (7.94, as CI installs it), with --datadir set to this
repository, running oracle/m6_base_probe.nse as a prerule with -sn against
127.0.0.1, so nothing is sent anywhere. The golden holds nmap's version, then
the probe's lines, `row|name|values`, in the order it wrote them, then what
`warn` wrote to nmap's standard error, `warn|line`, in order. Nothing else may
reach standard error.

The port runs the same probe through its engine
(crates/core/tests/base_differential.rs) and must write the same lines but for
the rows it pins, each with its ledger id.
"""

import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
PROBE = os.path.join(HERE, "m6_base_probe.nse")
GOLDEN = os.path.join(M6, "m6_base_golden.txt")
WARNING = "Lua warning: "


def generate(work):
    out = os.path.join(work, "base.out")
    p = subprocess.run(
        ["nmap", "--datadir", REPO, "-sn", "-n", "--script", PROBE,
         "--script-args", "out=%s" % out, "127.0.0.1"],
        capture_output=True)
    if p.returncode != 0:
        sys.exit("FAIL: nmap exited %d:\n%s" % (p.returncode, p.stderr.decode("latin-1")[-2000:]))
    with open(out, encoding="latin-1") as fh:
        lines = fh.read().splitlines()
    if not lines or lines[-1] != "done":
        sys.exit("FAIL: the probe did not finish (last line %r)" % lines[-1:])
    err = p.stderr.decode("latin-1").splitlines()
    stray = [l for l in err if not l.startswith(WARNING)]
    if stray:
        sys.exit("FAIL: nmap wrote to standard error what is not a warning: %r" % stray[:5])
    version = subprocess.run(["nmap", "--version"], capture_output=True, text=True,
                             check=True).stdout.splitlines()[0]
    head = [
        "# The base and coroutine libraries as an NSE script meets them, by nmap itself:",
        "# oracle/m6_base_probe.nse as a prerule, through oracle/gen_m6_base.py.",
        "# row|name|values, then warn|what warn wrote to standard error.",
        "# %s" % version,
    ]
    return "\n".join(head + lines[:-1] + ["warn|" + l for l in err]) + "\n"


def main():
    with tempfile.TemporaryDirectory(prefix="m6base-") as work:
        text = generate(work)
    if sys.argv[1:] == ["--check"]:
        old = open(GOLDEN, encoding="latin-1").read() if os.path.exists(GOLDEN) else ""
        if old != text:
            sys.stderr.write("".join(
                __import__("difflib").unified_diff(old.splitlines(True), text.splitlines(True),
                                                   "committed", "live", n=0)))
            sys.exit("FAIL: m6_base_golden.txt is not what this nmap gives; run ./regen_m6_base.sh")
        print("m6 base: golden is current (%d rows)" % sum(1 for l in text.splitlines() if l.startswith("row|")))
        return
    if len(sys.argv) != 2 or sys.argv[1].startswith("-"):
        sys.exit(__doc__)
    path = os.path.join(sys.argv[1], "m6_base_golden.txt")
    with open(path, "w", encoding="latin-1") as fh:
        fh.write(text)


if __name__ == "__main__":
    main()
