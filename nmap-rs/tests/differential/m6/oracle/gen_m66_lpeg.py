#!/usr/bin/env python3
"""M6.6 step 0b: derive the LPeg corpus, its golden and its step map, and check
nmap 7.94 against them. Driven by ../regen_m66_lpeg.sh.

    gen_m66_lpeg.py build OUTDIR [--with-794]
        writes OUTDIR/m66_lpeg_cases.txt, m66_lpeg_golden.txt, m66_lpeg_steps.txt
    gen_m66_lpeg.py agree
        runs the committed cases under nmap 7.94 against the committed golden

`build`:
  1. generates every row (gen_m66_lpeg_cases.py) and requires the committed
     quarantine (m66_lpeg_quarantine.txt) to have screened exactly this corpus
     (its SHA-256), then drops the quarantined rows: they never reach an oracle;
  2. runs this tree's standalone Lua + LPeg over the rest TWICE; a row that
     differs between the runs must fall in a class allowed run to run
     (`hashorder` only), or the build fails;
  3. writes the golden with the hash-order mask applied (`canon`), so it is
     byte-stable, and fails on any `loaderr` row (a generator bug);
  4. runs the census (a debug-hooked run, oracle/m66_lpeg_core.lua) and maps
     every row to the first step that can run it (classify_m66_lpeg.steps);
  5. with --with-794, runs nmap 7.94 over the same cases and classifies every
     row that differs from run 1 (see `agree`).

`agree` (and step 5): every row where 7.94 differs from the tree must fall in a
named class (hashorder, cdepth, drift794, path, position, argname); untagged
drift fails.
Counts per class are printed. nmap runs the prerule probe
oracle/m66_lpeg_probe.nse with --datadir set to this repository.
"""

import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
sys.path.insert(0, HERE)
import classify_m66_lpeg as cl  # noqa: E402

LUA = os.path.join(HERE, "lua")
DRIVER = os.path.join(HERE, "m66_lpeg_driver.lua")
CORE = os.path.join(HERE, "m66_lpeg_core.lua")
PROBE = os.path.join(HERE, "m66_lpeg_probe.nse")
QUARANTINE = os.path.join(M6, "m66_lpeg_quarantine.txt")
DRIFT_CLASSES = {"hashorder", "cdepth", "drift794", "path", "position", "argname"}

GOLDEN_HEAD = """\
# M6.6 step 0b LPeg golden: what this tree's liblua/ + lpeg.c (oracle/build_lua_oracle.sh)
# gives for every row of m66_lpeg_cases.txt, through oracle/m66_lpeg_driver.lua.
# The spec (M6.5 D1(c)); nmap 7.94 is checked against it by ./regen_m66_lpeg.sh --check-794.
# Rule names in LPeg's four hash-ordered grammar errors are masked to '?' (hashorder).
# id<TAB>status<TAB>values<TAB>log -- see oracle/m66_lpeg_core.lua for the rendering.
"""


def fail(msg):
    sys.stderr.write("FAIL: " + msg + "\n")
    sys.exit(1)


def run_driver(cases, out, *opts):
    p = subprocess.run([LUA, DRIVER, cases, out] + list(opts), capture_output=True, text=True)
    if p.returncode != 0:
        fail("the standalone oracle died (rc %d) after %s rows: a row the quarantine misses? "
             "re-run oracle/screen_m66_lpeg.py locally.\n%s"
             % (p.returncode, sum(1 for _ in open(out)) if os.path.exists(out) else 0, p.stderr[-2000:]))
    return p.stderr.strip()


def run_794(cases, out):
    if not shutil.which("nmap"):
        fail("nmap 7.94 is not installed: the agreement check needs it")
    args = "core=%s,cases=%s,out=%s" % (CORE, cases, out)
    p = subprocess.run(["nmap", "--datadir", REPO, "-sn", "-n", "--script", PROBE, "--script-args", args, "127.0.0.1"],
                       capture_output=True, text=True)
    lines = open(out, encoding="latin-1").read().splitlines() if os.path.exists(out) else []
    if p.returncode != 0 or not lines or lines[-1] != "done":
        fail("the nmap 7.94 probe did not finish (rc %d, last line %r): a row the quarantine misses?\n%s"
             % (p.returncode, lines[-1:] if lines else None, (p.stdout + p.stderr)[-2000:]))


def agree_report(tree_rows, nmap_rows, cases, label):
    cls = cl.compare(tree_rows, nmap_rows, cases)
    agree = len(tree_rows) - sum(len(v) for k, v in cls.items() if k != "extra")
    print("m6.6 lpeg vs nmap 7.94 (%s): %d rows, %d agree (%.3f%%); drift by class: %s"
          % (label, len(tree_rows), agree, 100.0 * agree / max(1, len(tree_rows)), cl.summary(cls)))
    bad = {k: v for k, v in cls.items() if not set(k.split("+")) <= DRIFT_CLASSES}
    for k, ids in sorted(cls.items()):
        print("  %-24s %s" % (k, " ".join(ids[:12]) + (" ..." if len(ids) > 12 else "")))
    if bad:
        for k, ids in bad.items():
            for cid in ids[:10]:
                print("  UNTAGGED %s %s\n    tree: %s\n    7.94: %s" % (k, cid, "\t".join(tree_rows.get(cid, ("-",)))[:300],
                                                                  "\t".join(nmap_rows.get(cid, ("-",)))[:300]))
        fail("nmap 7.94 drifts from the tree outside the named classes: %s" % cl.summary(bad))


def build(outdir, with_794):
    os.makedirs(outdir, exist_ok=True)
    work = tempfile.mkdtemp(prefix="m66lpeg.", dir=outdir)
    allp = os.path.join(work, "all.txt")
    with open(allp, "w") as fh:
        subprocess.run([sys.executable, os.path.join(HERE, "gen_m66_lpeg_cases.py")], stdout=fh, check=True)
    digest = cl.sha256_file(allp)
    head, quarantined = cl.read_quarantine(QUARANTINE)
    if head.get("screened-corpus-sha256") != digest:
        fail("m66_lpeg_quarantine.txt screened another corpus (%s, generated %s): the generator changed, so "
             "re-run oracle/screen_m66_lpeg.py locally (it needs an ASan build and nmap 7.94)"
             % (head.get("screened-corpus-sha256"), digest))
    cases_all = cl.read_cases(allp)
    for cid, (reason, chunk) in quarantined.items():
        if cid not in cases_all or cases_all[cid][1] != chunk:
            fail("quarantined row %s is not in the corpus as screened" % cid)
    for cid, (tags, _) in cases_all.items():
        if any(t.startswith("q=") for t in tags) and cid not in quarantined:
            fail("row %s is tagged for quarantine but the quarantine file lacks it" % cid)

    casesp = os.path.join(outdir, "m66_lpeg_cases.txt")
    with open(allp, encoding="latin-1") as src, open(casesp, "w", encoding="latin-1") as dst:
        for line in src:
            if line.startswith("#"):
                dst.write(line)
            elif line.split("\t", 1)[0] not in quarantined:
                dst.write(line)
    cases = cl.read_cases(casesp)

    raw1, raw2 = os.path.join(work, "raw1.txt"), os.path.join(work, "raw2.txt")
    print("m6.6 lpeg: run 1:", run_driver(casesp, raw1))
    print("m6.6 lpeg: run 2:", run_driver(casesp, raw2))
    r1, r2 = cl.read_rows(raw1), cl.read_rows(raw2)
    if list(r1) != list(cases):
        fail("the oracle's output does not list every case in order")
    cls = cl.compare(r1, r2, cases)
    print("m6.6 lpeg: run 1 vs run 2: %s" % cl.summary(cls))
    bad = {k: v for k, v in cls.items() if k != "hashorder"}
    if bad:
        for k, ids in bad.items():
            for cid in ids[:10]:
                print("  UNTAGGED %s %s\n    run 1: %s\n    run 2: %s" % (k, cid, "\t".join(r1[cid])[:300], "\t".join(r2.get(cid, ("-",)))[:300]))
        fail("the oracle is not deterministic across two runs outside hashorder: %s" % cl.summary(bad))
    loaderr = [cid for cid, r in r1.items() if r[0] == "loaderr"]
    if loaderr:
        fail("rows that do not compile (a generator bug): %s" % " ".join(loaderr[:20]))
    goldenp = os.path.join(outdir, "m66_lpeg_golden.txt")
    with open(goldenp, "w", encoding="latin-1") as fh:
        fh.write(GOLDEN_HEAD)
        for cid, r in r1.items():
            fh.write("%s\t%s\t%s\t%s\n" % ((cid,) + cl.canon_row(r)))
    xerr = [cid for cid, r in r1.items() if r[0] == "xerr"]
    if xerr:
        print("m6.6 lpeg: note: %d rows raise outside a wrapped call (xerr): %s" % (len(xerr), " ".join(xerr[:10])))

    censusp = os.path.join(work, "census.txt")
    print("m6.6 lpeg: census:", run_driver(casesp, censusp, "census"))
    smap = cl.steps(censusp)
    if list(smap) != list(cases):
        fail("the census does not list every case in order")
    table = cl.step_table(smap)
    stepsp = os.path.join(outdir, "m66_lpeg_steps.txt")
    with open(stepsp, "w", encoding="latin-1") as fh:
        fh.write("# M6.6 step 0b: the first step whose engine can run each row of m66_lpeg_cases.txt\n")
        fh.write("# (docs/M6.6-ANALYSIS.md section 11), from a census of what each row made LPeg do\n")
        fh.write("# (oracle/m66_lpeg_core.lua, census mode; oracle/classify_m66_lpeg.py, steps):\n")
        fh.write("#   b  calls no lpeg.match and runs no re/lpeg-utility code (a constructor may call Lua:\n")
        fh.write("#      a grammar's __index, locale(t)'s __newindex)\n")
        fh.write("#   c  matches only patterns without Lua-calling captures, match itself calls no Lua,\n")
        fh.write("#      and it runs no re/lpeg-utility code\n")
        fh.write("#   d  the rest. Step d runs every row (test-only registration), and step e every row (registered).\n")
        fh.write("# family      b      c      d  total  (rows a step can run: b; b+c; all)\n")
        tot = {"b": 0, "c": 0, "d": 0}
        for f in sorted(table):
            t = table[f]
            for k in tot:
                tot[k] += t[k]
            fh.write("# %-6s %6d %6d %6d %6d\n" % (f, t["b"], t["c"], t["d"], t["b"] + t["c"] + t["d"]))
        fh.write("# %-6s %6d %6d %6d %6d\n" % ("all", tot["b"], tot["c"], tot["d"], sum(tot.values())))
        fh.write("# id<TAB>step<TAB>census flags\n")
        for cid, (st, fl) in smap.items():
            fh.write("%s\t%s\t%s\n" % (cid, st, fl))
    print("m6.6 lpeg: steps: b=%d c=%d d=%d (step b runs %d rows, step c %d, steps d and e %d)"
          % (tot["b"], tot["c"], tot["d"], tot["b"], tot["b"] + tot["c"], sum(tot.values())))

    if with_794:
        raw794 = os.path.join(work, "raw794.txt")
        run_794(casesp, raw794)
        agree_report(r1, cl.read_rows(raw794), cases, "raw, against standalone run 1")
    for f in os.listdir(work):
        os.remove(os.path.join(work, f))
    os.rmdir(work)


def agree():
    casesp = os.path.join(M6, "m66_lpeg_cases.txt")
    golden = cl.read_rows(os.path.join(M6, "m66_lpeg_golden.txt"))
    cases = cl.read_cases(casesp)
    with tempfile.TemporaryDirectory() as work:
        raw794 = os.path.join(work, "raw794.txt")
        run_794(casesp, raw794)
        rows = cl.read_rows(raw794)
    masked = sum(1 for cid, r in rows.items() if cl.canon_row(r) != r)
    canon = {cid: cl.canon_row(r) for cid, r in rows.items()}
    print("m6.6 lpeg: %d rows of 7.94 output carry a hash-ordered rule name (masked)" % masked)
    agree_report(golden, canon, cases, "hashorder-masked, against the committed golden")


def main():
    if len(sys.argv) >= 3 and sys.argv[1] == "build":
        build(sys.argv[2], "--with-794" in sys.argv[3:])
    elif len(sys.argv) == 2 and sys.argv[1] == "agree":
        agree()
    else:
        sys.exit(__doc__)


if __name__ == "__main__":
    main()
