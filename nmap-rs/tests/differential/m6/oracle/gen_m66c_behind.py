#!/usr/bin/env python3
"""M6.6 step c: what the C does with left calls through lpeg.B.

Runs each case of oracle/m66c_behind.lua (334 grammars in six uses) under the
tree's lpeg.c with the two defects the port fixes fixed (the build of
gen_m66c_quarantine_pins.py: its peephole's `i--`, and Cc(nil)), one process
per case, and writes m66c_behind_golden.txt: `i<TAB>outcome`, the outcome
`CRASH` where the C's getfirst recursed until the process died
(lpeg-getfirst-unbounded-recursion). The port's test
(crates/core/tests/lpeg_match_limits.rs) holds the port to every answer, and
to "rule '...' may be left recursive" at every crash; and step b refuses at
construction the grammars whose cycle runs past a sub-grammar, which the C
builds and then hangs or crashes on.

    python3 oracle/gen_m66c_behind.py           # rewrite the golden
    python3 oracle/gen_m66c_behind.py --check   # FAIL if stale

LOCAL ONLY (it builds a patched interpreter); CI never runs it.
"""
import concurrent.futures
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import gen_m66c_quarantine_pins as pins  # noqa: E402

M6 = os.path.dirname(HERE)
GOLDEN = os.path.join(M6, "m66c_behind_golden.txt")
CASES = os.path.join(HERE, "m66c_behind.lua")


def one(lua, i):
    code = ('lpeg = require "lpeg" local m = dofile(%r) io.write(m.run(%d))' % (CASES, i))
    try:
        p = subprocess.run([lua, "-e", code], capture_output=True, timeout=3, cwd=HERE)
    except subprocess.TimeoutExpired:
        # A left recursion past a sub-grammar that the C's verifier misses
        # loops without recursing (step b refuses these grammars).
        return "HANG"
    if p.returncode != 0:
        return "CRASH"
    out = p.stdout.decode("latin-1")
    if "\t" in out or "\n" in out:
        raise SystemExit("gen_m66c_behind: case %d printed a tab or a newline" % i)
    return out


def generate(work):
    lua = pins.build(work)
    count = subprocess.run(
        [lua, "-e", 'lpeg = require "lpeg" io.write(dofile(%r).count)' % CASES],
        capture_output=True, check=True, cwd=HERE).stdout.decode()
    n = int(count)
    lines = [
        "# M6.6 step c: oracle/m66c_behind.lua's cases under the tree's lpeg.c with its",
        "# peephole and Cc(nil) defects fixed, by oracle/gen_m66c_behind.py (local only).",
        "# i<TAB>outcome; CRASH where the C's getfirst recursed until the process died,",
        "# HANG where the C ran on (3 s) on a cycle its verifier missed.",
        "# %d cases." % n,
    ]
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        outcomes = list(pool.map(lambda i: one(lua, i), range(1, n + 1)))
    for i, o in enumerate(outcomes, 1):
        lines.append("%d\t%s" % (i, o))
    return "\n".join(lines) + "\n"


def main():
    check = "--check" in sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="m66c-behind-") as work:
        text = generate(work)
    if check:
        old = open(GOLDEN, encoding="latin-1").read() if os.path.exists(GOLDEN) else ""
        if old != text:
            raise SystemExit("FAIL: m66c_behind_golden.txt is stale; run gen_m66c_behind.py")
        print("m66c behind golden: current")
        return
    with open(GOLDEN, "w", encoding="latin-1") as fh:
        fh.write(text)
    print("m66c behind golden: %d cases, %d crash, %d hang"
          % (sum(1 for l in text.splitlines() if not l.startswith("#")),
             text.count("\tCRASH"), text.count("\tHANG")))


if __name__ == "__main__":
    main()
