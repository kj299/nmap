#!/usr/bin/env python3
"""M6.6 step d: pins for the quarantined rows of the LPeg corpus that run
match-time captures.

m66c_quarantine_pins.txt (gen_m66c_quarantine_pins.py) pins the rows whose
defect the step c build fixes (the peephole, `Cc(nil)`, `initposition`),
step d's among them. The rows of three more ids run `Cmt` and are undefined
or wrong in the C (docs/M6.6-ANALYSIS.md §1.2, §7):

  * lpeg-doublecap-stack-overread: a `Cmt` returning enough values grows the
    capture list from `lp_match`'s 32-entry stack array, and `doublecap`
    copies `captop` entries out of it, where only `captop - n - 1` are there,
    the capture's own open entry the last (ASan stack-buffer-overflow;
    natively a crash from 1,000 values);
  * lpeg-runtime-capture-index-16bit: a runtime capture's stack index is a
    `short`, so from the 32,762nd live one it reads another stack slot;
  * lpeg-code-freed-during-match: a `Cmt` that calls its pattern's `__gc`
    frees the code the machine is running.

This writes m66d_quarantine_pins.txt, in m66c's format,

  id<TAB>step<TAB>source<TAB>status<TAB>values<TAB>log

each the answer of the tree's lpeg.c with those three defects fixed as the
port fixes them, on top of the step c build's two (source `fixed-c`), built
from a patched COPY of the file (the tree's is never edited) by
lpeg_search/build_patched_lua.sh:
  - `doublecap` from the runtime capture's path copies the entries the list
    holds, `captop - n - 1` (`adddyncaptures` keeps the capture's own open
    entry, the last of them, as its group);
  - `Capture.idx` is an `int` (D4: wide indices);
  - `__gc` (`lp_gc`) frees nothing: a running match's code stays.

    python3 oracle/gen_m66d_quarantine_pins.py          # rewrite the pins
    python3 oracle/gen_m66d_quarantine_pins.py --check  # FAIL if stale

LOCAL ONLY: it builds a patched interpreter (a C compiler, about a
minute); CI never runs it.
"""
import os
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(M6, "..", "..", "..", ".."))
QUARANTINE = os.path.join(M6, "m66_lpeg_quarantine.txt")
PINS = os.path.join(M6, "m66d_quarantine_pins.txt")
BUILD = os.path.join(M6, "lpeg_search", "build_patched_lua.sh")

sys.path.insert(0, HERE)
import gen_m66c_quarantine_pins as c  # noqa: E402  (the step c build, run and step map)

STEP_D_IDS = {
    "lpeg-doublecap-stack-overread",
    "lpeg-runtime-capture-index-16bit",
    "lpeg-code-freed-during-match",
}

# Each (old, new) occurs exactly once in lpeg.c.
PATCHES = [
    # The runtime capture's growth copies what the list holds.
    ("            capture = doublecap(L, capture, captop, ptop);\n"
     "            capsize = 2 * captop;\n"
     "          }\n"
     "          /* add new captures to 'capture' list */\n",
     "            if (captop >= INT_MAX/((int)sizeof(Capture) * 2))\n"
     "              luaL_error(L, \"too many captures\");\n"
     "            Capture *newc = (Capture *)lua_newuserdatauv(L, captop * 2 * sizeof(Capture), 0);\n"
     "            memcpy(newc, capture, (captop - n - 1) * sizeof(Capture));\n"
     "            lua_replace(L, caplistidx(ptop));\n"
     "            capture = newc;\n"
     "            capsize = 2 * captop;\n"
     "          }\n"
     "          /* add new captures to 'capture' list */\n"),
    # Wide capture indices.
    ("  short idx;  /* extra info about capture (group name, arg index, etc.) */\n",
     "  int idx;  /* extra info about capture (group name, arg index, etc.) */\n"),
    # `__gc` frees nothing.
    ("  if (p->codesize > 0)\n"
     "    reallocprog(L, p, 0);\n"
     "  return 0;\n",
     "  (void)p;\n"
     "  return 0;\n"),
]


def patch(src):
    src = c.patch(src)
    for old, new in PATCHES:
        if src.count(old) != 1:
            raise SystemExit("gen_m66d_quarantine_pins: lpeg.c no longer has the lines it patches")
        src = src.replace(old, new)
    return src


def build(work):
    src = open(os.path.join(REPO, "lpeg.c"), encoding="latin-1").read()
    patched = os.path.join(work, "lpeg.c")
    with open(patched, "w", encoding="latin-1") as fh:
        fh.write(patch(src))
    lua = os.path.join(work, "lua-fixed-d")
    subprocess.run(["bash", BUILD, patched, lua, work], check=True, stdout=subprocess.DEVNULL)
    return lua


def generate(work):
    lua = build(work)
    rows = []
    with open(QUARANTINE, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line and not line.startswith("#"):
                rows.append(line)
    out = []
    for line in rows:
        cid, reason, _ = line.split("\t", 2)
        if c.ledger_id(reason) not in STEP_D_IDS:
            continue
        census = c.run_one(lua, work, line, True)
        answer = c.run_one(lua, work, line, False)
        if census is None or answer is None:
            raise SystemExit("gen_m66d_quarantine_pins: the fixed build crashed on %s" % cid)
        step = c.step_of(census.split("\t")[1])
        _, status, values, log = answer.split("\t")
        out.append("\t".join([cid, step, "fixed-c", status, values, log]))
    head = [
        "# M6.6 step d: pins for quarantined rows of m66_lpeg_cases.txt's generator that run",
        "# match-time captures, by oracle/gen_m66d_quarantine_pins.py (local only: it builds a",
        "# patched copy of lpeg.c). id<TAB>step<TAB>source<TAB>status<TAB>values<TAB>log; source",
        "# fixed-c is the tree's lpeg.c with doublecap's over-read, the 16-bit runtime-capture",
        "# index and the code __gc frees mid-match fixed, on top of step c's two. %d rows." % len(out),
    ]
    return "\n".join(head + out) + "\n"


def main():
    check = "--check" in sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="m66d-pins-") as work:
        text = generate(work)
    if check:
        old = open(PINS, encoding="latin-1").read() if os.path.exists(PINS) else ""
        if old != text:
            raise SystemExit("FAIL: m66d_quarantine_pins.txt is stale; run gen_m66d_quarantine_pins.py")
        print("m66d quarantine pins: current")
        return
    with open(PINS, "w", encoding="latin-1") as fh:
        fh.write(text)
    print("m66d quarantine pins: %d rows" % (text.count("\n") - 5))


if __name__ == "__main__":
    main()
