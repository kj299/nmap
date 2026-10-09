#!/usr/bin/env python3
"""Load every shipped script in nmap 7.94 with some of nmap's C modules taken
away, and record how each load ends: the golden for
crates/core/tests/scriptload_differential.rs.

    python3 oracle/gen_m66_scriptload.py OUTDIR [--missing a,b,...] [--jobs N]
        ->  OUTDIR/m66_scriptload_golden.txt

Every nmap build registers its C modules (nse_main.cc:564-581), so nmap itself
cannot show what a script does without one. This emulates that: a scratch data
directory holds symlinks to this repository's data files, nselib/ and scripts/,
and a copy of its nse_main.lua with one line added just before
`local REQUIRE_ERROR = {};`, which removes the missing modules from
package.loaded and _G before any script loads. nse_main.lua itself requires
`lpeg` and `lpeg-utility` (nse_main.lua:150-151), so taking `lpeg` away takes
`lpeg-utility` with it. The missing set defaults to the C modules the port does
not have yet; it must be the port's set, which the test checks.

Each script is loaded alone, `nmap --datadir DD -v --script-help DD/scripts/
NAME.nse`, and its load is one of:

    OK      it loaded (`--script-help` printed its name; nmap logged
            `Loaded 1 scripts for scanning.`)
    LOUD    a hard `require` failed and nmap quit (`QUITTING!`); the detail is
            the first `file:line: module 'X' not found`, the file's path
            stripped to its name, or else the line after `Failed to load`
    QUIET   `stdnse.silent_require` failed and the script was dropped
            (`Failed to load '...'.`, `Loaded 0 scripts for scanning.`)

Rows are `NAME<TAB>OUTCOME<TAB>DETAIL`, sorted by name. The header records
the missing set, which the test reads, and the totals.
"""

import argparse
import concurrent.futures
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))

# The C modules nmap registers that the port does not have yet
# (DIVERGENCES.md, `nse-c-modules-pending`). CI regenerates with this set, and
# scriptload_differential fails unless it is the port's: a module leaves it in
# the change that ports it (`nmapdb` left in M6.6 step a).
PORT_MISSING = "openssl,lpeg,lfs,libssh2,zlib"

ANCHOR = "local REQUIRE_ERROR = {};\n"
NOT_FOUND = re.compile(r"[a-zA-Z0-9_./-]*:[0-9]*: module '[^']*' not found")


def datadir(dd, missing):
    """Lay out a data directory whose nse_main.lua drops `missing`."""
    for name in sorted(os.listdir(REPO)):
        if name in ("nselib", "scripts") or (name.startswith("nmap-") and
                                             os.path.isfile(os.path.join(REPO, name))):
            os.symlink(os.path.join(REPO, name), os.path.join(dd, name))
    with open(os.path.join(REPO, "nse_main.lua"), encoding="latin-1") as fh:
        src = fh.read()
    if src.count(ANCHOR) != 1:
        sys.exit("FAIL: nse_main.lua has %d copies of the anchor %r" % (src.count(ANCHOR), ANCHOR))
    block = ("do local MISSING = {%s}; for _, m in ipairs(MISSING) do package.loaded[m] = nil; "
             "rawset(_G, m, nil); if m == \"lpeg\" then package.loaded[\"lpeg-utility\"] = nil end "
             "end end -- M6.6 load emulation\n") % "".join('"%s",' % m for m in missing)
    with open(os.path.join(dd, "nse_main.lua"), "w", encoding="latin-1") as fh:
        fh.write(src.replace(ANCHOR, block + ANCHOR, 1))


def basename(s):
    return s.rsplit("/", 1)[-1]


def classify(name, out):
    """How the load ended, from what nmap printed: (outcome, detail)."""
    lines = out.splitlines()
    if "QUITTING!" in out:
        for line in lines:
            m = NOT_FOUND.search(line)
            if m:
                return "LOUD", basename(m.group(0))
        for i, line in enumerate(lines):
            if "Failed to load" in line:
                return "LOUD", basename(lines[i + 1]) if i + 1 < len(lines) else ""
        return "LOUD", ""
    if "Failed to load '" in out and "Loaded 0 scripts for scanning." in out:
        return "QUIET", ""
    if name in lines and "Loaded 1 scripts for scanning." in out:
        return "OK", ""
    sys.exit("FAIL: %s: cannot classify nmap's output:\n%s" % (name, out[:2000]))


def load(dd, name):
    r = subprocess.run(["nmap", "--datadir", dd, "-v", "--script-help",
                        os.path.join(dd, "scripts", name + ".nse")],
                       capture_output=True, timeout=120)
    out = (r.stdout + r.stderr).decode("latin-1")
    outcome, detail = classify(name, out)
    if (outcome == "LOUD") != (r.returncode != 0):
        sys.exit("FAIL: %s: %s with exit status %d" % (name, outcome, r.returncode))
    return name, outcome, detail


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("outdir")
    ap.add_argument("--missing", default=PORT_MISSING)
    ap.add_argument("--jobs", type=int, default=min(8, os.cpu_count() or 1))
    args = ap.parse_args()
    missing = sorted(m for m in args.missing.split(",") if m)
    scripts = sorted(f[:-4] for f in os.listdir(os.path.join(REPO, "scripts")) if f.endswith(".nse"))
    with tempfile.TemporaryDirectory() as dd:
        datadir(dd, missing)
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.jobs) as pool:
            rows = list(pool.map(lambda s: load(dd, s), scripts))
    totals = {k: sum(1 for r in rows if r[1] == k) for k in ("OK", "LOUD", "QUIET")}
    version = subprocess.run(["nmap", "--version"], capture_output=True,
                             text=True).stdout.splitlines()[0]
    with open(os.path.join(args.outdir, "m66_scriptload_golden.txt"), "w", encoding="latin-1") as fh:
        fh.write("# script\toutcome\tdetail: how each shipped script loads, alone, under\n")
        fh.write("# %s with these C modules removed (--datadir this repository).\n" % version)
        fh.write("# missing: %s\n" % ",".join(missing))
        fh.write("# totals: %d OK, %d LOUD, %d QUIET\n" % (totals["OK"], totals["LOUD"], totals["QUIET"]))
        fh.write("# Regenerate from nmap-rs/ with\n")
        fh.write("# python3 tests/differential/m6/oracle/gen_m66_scriptload.py tests/differential/m6\n")
        for r in rows:
            fh.write("\t".join(r) + "\n")
    print("m6.6 script load: %d scripts, %d OK, %d LOUD, %d QUIET (missing %s)"
          % (len(rows), totals["OK"], totals["LOUD"], totals["QUIET"], ",".join(missing)))


if __name__ == "__main__":
    main()
