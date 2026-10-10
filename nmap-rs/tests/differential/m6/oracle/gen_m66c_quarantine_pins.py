#!/usr/bin/env python3
"""M6.6 step c: pins for the quarantined rows of the LPeg corpus.

The quarantine (m66_lpeg_quarantine.txt) holds the rows on which the tree's
lpeg.c crashes, trips a sanitizer, or is undefined; no golden records them
(LESSONS #033), and each needs a port pin with its semantic answer
(docs/M6.6-ANALYSIS.md §11). This writes m66c_quarantine_pins.txt:

  id<TAB>step<TAB>source<TAB>status<TAB>values<TAB>log

* source `fixed-c`: the answer of the tree's lpeg.c with the two defects
  fixed that the port fixes, built from a patched COPY of the file (the
  tree's is never edited) by lpeg_search/build_patched_lua.sh:
    - lpeg-codegen-jump-out-of-code: the peephole keeps its rewrite of a
      jump and goes on after it, without the `i--` re-scan (lpeg.c:1846);
    - lpeg-cc-nil-without-ktable: `Cconst` with key 0 pushes nil instead of
      reading entry 0 of a constant table the pattern may not have.
  Only rows of those two ids and of lpeg-initposition-negation-overflow
  (undefined `-ii` in C, a correct answer in practice) take this source:
  the other ids' defects are not fixed in the build.
* source `semantic`: the answer a correct LPeg gives where the fixed build
  still crashes or is wrong (16-bit constant keys, nested captures past
  the stack space LPeg checked for), written here with its reason.

`step` is what the case runner's census (oracle/m66_lpeg_core.lua) gives on
the fixed build, by the rule classify_m66_lpeg.py applies to the corpus;
the port's gate (crates/core/tests/lpeg_corpus_differential.rs) runs the
rows at or below its step.

    python3 oracle/gen_m66c_quarantine_pins.py          # rewrite the pins
    python3 oracle/gen_m66c_quarantine_pins.py --check  # FAIL if stale

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
PINS = os.path.join(M6, "m66c_quarantine_pins.txt")
DRIVER = os.path.join(HERE, "m66_lpeg_driver.lua")
BUILD = os.path.join(M6, "lpeg_search", "build_patched_lua.sh")

FIXED_IDS = {
    "lpeg-codegen-jump-out-of-code",
    "lpeg-cc-nil-without-ktable",
    "lpeg-initposition-negation-overflow",
}

# Rows the fixed build cannot answer, with a correct LPeg's answer.
SEMANTIC = {
    # Constants past 32,767 read back as nil, and from 65,537 alias, in the
    # C (16-bit keys, D4); with wide keys every constant reads back.
    "X.ktable.32768": ("c", "ok", "i32768 i0 i1 i32768"),
    "X.ktable.65537": ("c", "ok", "i65537 i0 i1 i65537"),
    # `pushnestedvalues` pushes past the stack space LPeg checked for: the
    # C crashes (or, with LUA_USE_APICHECK, aborts) at these depths. Each
    # level's simple capture gives the whole match, "a".
    "H.nestC.40": ("c", "ok", 'i40 s"a" s"a"'),
    "H.nestC.100": ("c", "ok", 'i100 s"a" s"a"'),
    "H.nestC.200": ("c", "ok", 'i200 s"a" s"a"'),
    "H.nestC.299": ("c", "ok", 'i299 s"a" s"a"'),
    "X.ub.nestC": ("c", "ok", "i300"),
}


def ledger_id(reason):
    """The §7 ledger id a quarantine reason names."""
    for part in reason.replace(";", "@").split("@"):
        part = part.strip()
        if part.startswith("q="):
            part = part[2:]
        if part.startswith("lpeg-"):
            return part
    return ""


def patch(src):
    old_pp = "            i--;  /* reoptimize its label */\n"
    old_cc = ("    case Cconst: {\n"
              "      pushluaval(cs);\n")
    new_cc = ("    case Cconst: {\n"
              "      if (cs->cap->idx == 0) lua_pushnil(L);\n"
              "      else pushluaval(cs);\n")
    if src.count(old_pp) != 1 or src.count(old_cc) != 1:
        raise SystemExit("gen_m66c_quarantine_pins: lpeg.c no longer has the lines it patches")
    return src.replace(old_pp, "").replace(old_cc, new_cc)


def step_of(flags):
    f = set(x for x in flags.split(",") if x and x != "-")
    if not ({"match", "reU"} & f):
        return "b"
    if not ({"luacap", "reU"} & f):
        return "c" if "dynm" not in f else "d"
    return "d"


def run_one(lua, work, line, census):
    one = os.path.join(work, "one.txt")
    out = os.path.join(work, "one.out")
    with open(one, "w", encoding="latin-1") as fh:
        fh.write(line + "\n")
    if os.path.exists(out):
        os.remove(out)
    args = [lua, DRIVER, one, out] + (["census"] if census else [])
    try:
        rc = subprocess.run(args, capture_output=True, timeout=120, cwd=HERE).returncode
    except subprocess.TimeoutExpired:
        return None
    if rc != 0 or not os.path.exists(out):
        return None
    text = open(out, encoding="latin-1").read().rstrip("\n")
    return text or None


def build(work):
    src = open(os.path.join(REPO, "lpeg.c"), encoding="latin-1").read()
    patched = os.path.join(work, "lpeg.c")
    with open(patched, "w", encoding="latin-1") as fh:
        fh.write(patch(src))
    lua = os.path.join(work, "lua-fixed")
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
        lid = ledger_id(reason)
        if cid in SEMANTIC:
            step, status, values = SEMANTIC[cid]
            out.append("\t".join([cid, step, "semantic", status, values, "-"]))
            continue
        if lid not in FIXED_IDS:
            continue
        census = run_one(lua, work, line, True)
        answer = run_one(lua, work, line, False)
        if census is None or answer is None:
            raise SystemExit("gen_m66c_quarantine_pins: the fixed build crashed on %s" % cid)
        step = step_of(census.split("\t")[1])
        _, status, values, log = answer.split("\t")
        out.append("\t".join([cid, step, "fixed-c", status, values, log]))
    head = [
        "# M6.6 step c: pins for quarantined rows of m66_lpeg_cases.txt's generator,",
        "# by oracle/gen_m66c_quarantine_pins.py (local only: it builds a patched copy of",
        "# lpeg.c). id<TAB>step<TAB>source<TAB>status<TAB>values<TAB>log; source fixed-c is",
        "# the tree's lpeg.c with its peephole and Cc(nil) defects fixed, semantic a",
        "# correct LPeg's answer where that build still fails. The chunks are the",
        "# quarantine's. %d rows." % len(out),
    ]
    return "\n".join(head + out) + "\n"


def main():
    check = "--check" in sys.argv[1:]
    with tempfile.TemporaryDirectory(prefix="m66c-pins-") as work:
        text = generate(work)
    if check:
        old = open(PINS, encoding="latin-1").read() if os.path.exists(PINS) else ""
        if old != text:
            raise SystemExit("FAIL: m66c_quarantine_pins.txt is stale; run gen_m66c_quarantine_pins.py")
        print("m66c quarantine pins: current")
        return
    with open(PINS, "w", encoding="latin-1") as fh:
        fh.write(text)
    print("m66c quarantine pins: %d rows" % (text.count("\n") - 6))


if __name__ == "__main__":
    main()
