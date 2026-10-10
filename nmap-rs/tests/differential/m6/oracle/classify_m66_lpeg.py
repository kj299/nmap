#!/usr/bin/env python3
"""M6.6 step 0b: read, canonicalise and compare LPeg corpus outputs, and map
each row to the plan's steps. Library for gen_m66_lpeg.py and
screen_m66_lpeg.py, and a command line for the port's gates.

    classify_m66_lpeg.py compare A B [--cases CASES] [--quarantine Q] [--allow C1,C2]
    classify_m66_lpeg.py canon RAW OUT

An output line is `id<TAB>status<TAB>values<TAB>log` (oracle/m66_lpeg_core.lua).

Named classes (docs/M6.6-ANALYSIS.md §3, E6). A row that differs between two
outputs gets the smallest set of these normalisations under which it agrees:
  hashorder  the rule name in LPeg's four grammar errors (`rule 'X' may be left
             recursive`, `rule 'X' is not a pattern` -- but not `initial rule
             'X' ...`, which is deterministic --, `empty loop in rule 'X'`,
             `rule 'X' undefined in given grammar`) follows table iteration
             order, which Lua salts per process; masked to '?'. The committed
             golden is stored with this mask applied (`canon`).
  path       a `.../nselib/re.lua:` style path, cut to the file name (the core
             already does this; a residue is a class, not a pass)
  position   a `chunk:N: `-style position prefix at the start of a message
             (stdlib-errors-have-no-position)
  argname    the function name in `bad argument #N to 'NAME'`
             (stdlib-bad-argument-naming)
and three classes decided by the row, not its text:
  cdepth     the row is tagged `cdepth` in the cases file: its answer is the
             embedding's depth -- the C-call depth of re-entry (195 standalone,
             194 under 7.94) or the Lua stack's ceiling on captures (999,934
             standalone, 999,945 under 7.94); only rows near a ceiling
  drift794   the row is tagged `drift794`: 7.94 answers differently from the
             tree (an embedding difference, measured), and only the agreement
             check with 7.94 accepts it. The port's gates do not: there the
             golden's answer is the pin (`H.reenter.rel`)
  quarantine the row is in m66_lpeg_quarantine.txt: never compared, pinned
Anything else is `other`, which no gate accepts.

Steps (`steps` in this module, from oracle/m66_lpeg_core.lua's census): the
earliest of the plan's steps whose engine can run a row (§11):
  b  never calls lpeg.match, and runs no code of re.lua or lpeg-utility.lua
     (the plan runs those libraries from step d). It may call Lua from a
     constructor -- a grammar table's __index, locale(t)'s __newindex --,
     which step b implements
  c  every pattern it matches is free of Lua-calling captures (Cmt and
     P(function), p/function, Cf, p/table), match itself calls no Lua, and
     it runs no code of nselib/re.lua or nselib/lpeg-utility.lua
  d  everything else (all rows run at d, through the test-only registration,
     and at e, through the registered module)
A row at c whose census saw match call a Lua function is a contradiction
(the taint tracking missed a capture kind), and `steps` refuses to map it.
"""

import argparse
import hashlib
import re
import sys

FOUR = [
    (re.compile(r"rule '[^']*' may be left recursive"), "rule '?' may be left recursive"),
    # not `initial rule 'X' is not a pattern`, whose name is the grammar's
    # first field and so deterministic
    (re.compile(r"(?<!initial )rule '[^']*' is not a pattern"), "rule '?' is not a pattern"),
    (re.compile(r"empty loop in rule '[^']*'"), "empty loop in rule '?'"),
    (re.compile(r"rule '[^']*' undefined in given grammar"), "rule '?' undefined in given grammar"),
]
PATH = re.compile(r"[^\s'\"]*nselib/([\w-]+\.lua):")
# a position prefix right after the opening quote of a rendered string
POSITION = re.compile(r'(?<=")(?:\.\.\.)?[^"\s:\\]+:\d+: ')
ARGNAME = re.compile(r"bad argument #(\d+) to '[^']*'")

NAMED = ("hashorder", "path", "position", "argname")


def mask_hashorder(s):
    for rx, rep in FOUR:
        s = rx.sub(rep, s)
    return s


NORM = {
    "hashorder": mask_hashorder,
    "path": lambda s: PATH.sub(r"\1:", s),
    "position": lambda s: POSITION.sub("", s),
    "argname": lambda s: ARGNAME.sub(r"bad argument #\1 to '?'", s),
}


def read_rows(path):
    """id -> (status, values, log), in file order; `done` and comments skipped."""
    rows = {}
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#") or line == "done":
                continue
            parts = line.split("\t")
            if len(parts) != 4:
                raise SystemExit("%s: malformed output line: %r" % (path, line[:200]))
            if parts[0] in rows:
                raise SystemExit("%s: duplicate id %s" % (path, parts[0]))
            rows[parts[0]] = (parts[1], parts[2], parts[3])
    return rows


def read_cases(path):
    """id -> (tags tuple, escaped chunk), in file order."""
    cases = {}
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cid, tags, chunk = line.split("\t")
            cases[cid] = (tuple(t for t in tags.split(",") if t and t != "-"), chunk)
    return cases


def read_quarantine(path):
    """(header dict, id -> (reason, escaped chunk))."""
    head, rows = {}, {}
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if line.startswith("# ") and ": " in line:
                k, v = line[2:].split(": ", 1)
                head[k] = v
                continue
            if not line or line.startswith("#"):
                continue
            cid, reason, chunk = line.split("\t")
            rows[cid] = (reason, chunk)
    return head, rows


def canon_row(row):
    st, vals, log = row
    return (st, mask_hashorder(vals), mask_hashorder(log))


def norm(row, names):
    st, vals, log = row
    for n in names:
        vals, log = NORM[n](vals), NORM[n](log)
    return (st, vals, log)


def classify_pair(cid, a, b, tags=(), quarantined=()):
    """The class of a differing pair, or None when they agree."""
    if a == b:
        return None
    if cid in quarantined:
        return "quarantine"
    if "cdepth" in tags:
        return "cdepth"
    if "drift794" in tags:
        return "drift794"
    # smallest subset of the named normalisations, in a fixed order
    from itertools import combinations
    for k in range(1, len(NAMED) + 1):
        for names in combinations(NAMED, k):
            if norm(a, names) == norm(b, names):
                return "+".join(names)
    return "other"


def compare(a, b, cases=None, quarantined=()):
    """{class: [ids]} over the ids of `a`; ids missing in b are `missing`."""
    out = {}
    for cid, ra in a.items():
        if cid not in b:
            out.setdefault("missing", []).append(cid)
            continue
        tags = cases[cid][0] if cases and cid in cases else ()
        c = classify_pair(cid, ra, b[cid], tags, quarantined)
        if c:
            out.setdefault(c, []).append(cid)
    for cid in b:
        if cid not in a:
            out.setdefault("extra", []).append(cid)
    return out


def summary(classes):
    if not classes:
        return "no difference"
    return " ".join("%s=%d" % (k, len(v)) for k, v in sorted(classes.items()))


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for blk in iter(lambda: fh.read(1 << 20), b""):
            h.update(blk)
    return h.hexdigest()


# ------------------------------------------------------------ steps

def steps(census_path):
    """id -> (step, flags) from a census output (`id<TAB>flags`)."""
    out = {}
    bad = []
    with open(census_path, encoding="latin-1") as fh:
        for line in fh:
            line = line.rstrip("\n")
            if not line or line.startswith("#"):
                continue
            cid, fl = line.split("\t")
            f = set(x for x in fl.split(",") if x and x != "-")
            unknown = f - {"match", "luacap", "localet", "reU", "dynm", "dync"}
            if unknown:
                raise SystemExit("census: unknown flags %s for %s" % (unknown, cid))
            if not ({"match", "reU"} & f):
                step = "b"
            elif not ({"luacap", "reU"} & f):
                step = "c"
            else:
                step = "d"
            if step in "bc" and "dynm" in f:
                bad.append(cid)
            out[cid] = (step, ",".join(sorted(f)) or "-")
    if bad:
        raise SystemExit("census: %d rows classed b/c had match call Lua (taint tracking is incomplete): %s"
                         % (len(bad), " ".join(bad[:20])))
    return out


def step_table(stepmap):
    fams = {}
    for cid, (st, _) in stepmap.items():
        f = cid.split(".")[0]
        fams.setdefault(f, {"b": 0, "c": 0, "d": 0})[st] += 1
    return fams


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("compare")
    c.add_argument("a")
    c.add_argument("b")
    c.add_argument("--cases")
    c.add_argument("--quarantine")
    c.add_argument("--allow", default="", help="comma-separated classes that do not fail")
    c.add_argument("--show", type=int, default=10)
    k = sub.add_parser("canon")
    k.add_argument("raw")
    k.add_argument("out")
    a = ap.parse_args()
    if a.cmd == "canon":
        rows = read_rows(a.raw)
        with open(a.out, "w", encoding="latin-1") as fh:
            for cid, r in rows.items():
                fh.write("%s\t%s\t%s\t%s\n" % ((cid,) + canon_row(r)))
        return 0
    A, B = read_rows(a.a), read_rows(a.b)
    cases = read_cases(a.cases) if a.cases else None
    q = read_quarantine(a.quarantine)[1] if a.quarantine else {}
    cls = compare(A, B, cases, q)
    allow = set(x for x in a.allow.split(",") if x)
    print("%d rows: %s" % (len(A), summary(cls)))
    rc = 0
    for name, ids in sorted(cls.items()):
        ok = all(part in allow for part in name.split("+"))
        if not ok:
            rc = 1
        for cid in ids[:a.show]:
            print("  %s %s\n    A: %s\n    B: %s" % ("allowed" if ok else "FAIL", cid, "\t".join(A.get(cid, ("-",)))[:300],
                                                 "\t".join(B.get(cid, ("-",)))[:300]))
    return rc


if __name__ == "__main__":
    sys.exit(main())
