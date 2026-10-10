#!/usr/bin/env -S python3 -I -B
"""Run the committed M6.6 LPeg corpus through sabotaged builds and count the
rows that differ from the committed golden. LOCAL ONLY.

    sabcmp.py --work WORK [--limit N] [--timeout SECONDS] [VARIANT ...]

Needs WORK/bin/lua_NAME from build_variants.py. The cases, golden and step
map (m66_lpeg_{cases,golden,steps}.txt) are copied into WORK/snapshot first,
so a regeneration running at the same time cannot change them mid-run; the
cases and the golden must name the same rows. Rows the cases file tags
`cdepth` or `drift794` are left out: their answer belongs to the embedding,
not the engine. Each build runs the cases through oracle/m66_lpeg_driver.lua,
resuming after any row that kills or hangs it (screen_m66_lpeg.resume); such
a row counts as caught. Outputs are compared hash-order masked
(classify_m66_lpeg.canon_row), as the golden is stored.

Checks (exit 1 on failure): the baseline differs on no row; on a full run
(no --limit), every sabotage differs on at least one row, and each of
variants.REQUIRED_X is caught by a row of family X.
"""
import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import collections  # noqa: E402
import importlib.util  # noqa: E402
import json  # noqa: E402
import os  # noqa: E402
import shutil  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.realpath(os.path.join(HERE, "..", "..", "..", "..", ".."))
M6 = os.path.join(REPO, "nmap-rs", "tests", "differential", "m6")
ORACLE = os.path.join(M6, "oracle")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


# by path, not through sys.path; screen_m66_lpeg's own `import
# classify_m66_lpeg` then finds the module already loaded
cl = load("classify_m66_lpeg", os.path.join(ORACLE, "classify_m66_lpeg.py"))
sc = load("screen_m66_lpeg", os.path.join(ORACLE, "screen_m66_lpeg.py"))
V = load("lpeg_sabotage_variants", os.path.join(HERE, "variants.py"))

SKIP_TAGS = ("cdepth", "drift794")


def inside_repo(path):
    p = os.path.realpath(path)
    return p == REPO or p.startswith(REPO + os.sep)


def snapshot(work):
    snap = os.path.join(work, "snapshot")
    os.makedirs(snap, exist_ok=True)
    out = {}
    for key, name in (("cases", "m66_lpeg_cases.txt"), ("golden", "m66_lpeg_golden.txt"),
                      ("steps", "m66_lpeg_steps.txt")):
        src = os.path.join(M6, name)
        if not os.path.exists(src):
            if key == "steps":
                out[key] = None
                continue
            sys.exit("missing %s" % src)
        dst = os.path.join(snap, name)
        shutil.copyfile(src, dst)
        out[key] = dst
    return out


def first_rows(cases_path, n, dst):
    """The cases file cut to its first n rows (comment lines kept)."""
    kept = 0
    with open(cases_path, encoding="latin-1") as src, open(dst, "w", encoding="latin-1") as out:
        for line in src:
            if line.startswith("#") or not line.strip():
                out.write(line)
                continue
            if kept < n:
                out.write(line)
                kept += 1
    return dst


def read_steps(path):
    """id -> step from m66_lpeg_steps.txt (`id<TAB>step<TAB>flags`); {} if absent."""
    steps = {}
    if not path:
        return steps
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            if line.startswith("#") or not line.strip():
                continue
            parts = line.rstrip("\n").split("\t")
            if len(parts) >= 2:
                steps[parts[0]] = parts[1]
    return steps


def fam(cid):
    return cid.split(".", 1)[0]


def shown(rows, k=6):
    s = ", ".join("`%s`" % x for x in rows[:k])
    return s + (" (+%d)" % (len(rows) - k) if len(rows) > k else "")


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work", required=True, help="work directory (never inside the repository)")
    ap.add_argument("--limit", type=int, default=0, help="run only the first N rows of the cases")
    ap.add_argument("--timeout", type=int, default=120,
                    help="seconds one driver process may run before its next row counts as hung (default 120)")
    ap.add_argument("variants", nargs="*")
    a = ap.parse_args()
    work = os.path.realpath(a.work)
    if inside_repo(work):
        sys.exit("refusing a work directory inside the repository: %s" % work)
    names = V.select(a.variants)
    bindir, outdir = os.path.join(work, "bin"), os.path.join(work, "out")
    os.makedirs(outdir, exist_ok=True)
    missing = [n for n in names if not os.access(os.path.join(bindir, "lua_" + n), os.X_OK)]
    if missing:
        sys.exit("not built (run build_variants.py first): %s" % " ".join(missing))

    snap = snapshot(work)
    cases = cl.read_cases(snap["cases"])
    golden = cl.read_rows(snap["golden"])
    only_c = [c for c in cases if c not in golden]
    only_g = [c for c in golden if c not in cases]
    if only_c or only_g:
        sys.exit("the cases and the golden disagree (%d rows only in the cases, e.g. %s; %d only in the golden, e.g. %s): "
                 "is a regeneration running? Re-run when it has finished."
                 % (len(only_c), only_c[:3], len(only_g), only_g[:3]))
    steps = read_steps(snap["steps"])
    ids = list(cases)
    cases_path = snap["cases"]
    if a.limit:
        ids = ids[:a.limit]
        cases_path = first_rows(snap["cases"], a.limit, os.path.join(work, "snapshot", "cases_first%d.txt" % a.limit))
    skip = set(c for c in ids if any(t in SKIP_TAGS for t in cases[c][0]))
    driver = os.path.join(ORACLE, "m66_lpeg_driver.lua")
    print("corpus: %d rows run%s, %d left out (tagged %s); cases sha256 %s, golden sha256 %s" % (
        len(ids), " (--limit)" if a.limit else "", len(skip), "/".join(SKIP_TAGS),
        cl.sha256_file(snap["cases"])[:16], cl.sha256_file(snap["golden"])[:16]), flush=True)

    res = {}
    for name in names:
        lua = os.path.join(bindir, "lua_" + name)
        out = os.path.join(outdir, "out_%s.txt" % name)
        bad = sc.resume(name, lambda st: [lua, driver, cases_path, out, "flush"] + (["start=" + st] if st else []),
                        ids, out, a.timeout)
        rows = cl.read_rows(out)

        def differs(cid):
            return cid in bad or cid not in rows or cl.canon_row(rows[cid]) != golden[cid]

        diff = [c for c in ids if c not in skip and differs(c)]
        skipped_diff = [c for c in ids if c in skip and differs(c)]
        fixed = [c for c in diff if fam(c) not in ("R", "Q")]
        xrows = [c for c in diff if fam(c) == "X"]
        by_step = dict(sorted(collections.Counter(steps.get(c, "?") for c in diff).items()))
        res[name] = {"diff": diff, "fixed": fixed, "x": xrows, "bad": {c: list(v) for c, v in bad.items()},
                     "skipped_diff": skipped_diff, "by_step": by_step,
                     "families": dict(sorted(collections.Counter(fam(c) for c in diff).items()))}
        print("%-32s differ=%6d fixed=%5d crashed=%3d X=%4d by-step=%s fam=%s" % (
            name, len(diff), len(fixed), len(bad), len(xrows), by_step, res[name]["families"]), flush=True)
        os.remove(out)

    meta = {"rows": len(ids), "limit": a.limit, "left_out": sorted(skip), "timeout": a.timeout,
            "cases_sha256": cl.sha256_file(snap["cases"]), "golden_sha256": cl.sha256_file(snap["golden"])}
    with open(os.path.join(outdir, "sab.json"), "w") as fh:
        json.dump({"meta": meta, "variants": res}, fh, indent=1)

    print()
    print("| variant | rows differing | of them, fixed rows (not R or Q) | crashed or hung | fixed rows that catch it (family X first) | by step |")
    print("|---|---|---|---|---|---|")
    for name in names:
        r = res[name]
        sid = name.split("_", 1)[0]
        print("| %s %s | %d | %d | %d | %s | %s |" % (
            sid, V.LABELS[name], len(r["diff"]), len(r["fixed"]), len(r["bad"]),
            shown(r["x"] or r["fixed"]) or "-", " ".join("%s=%d" % kv for kv in r["by_step"].items()) or "-"))
    print()
    for name in names:
        if res[name]["skipped_diff"]:
            print("%s differs on %d left-out row(s): %s" % (name, len(res[name]["skipped_diff"]),
                                                        " ".join(res[name]["skipped_diff"][:8])))

    fail = []
    if V.BASELINE in res and res[V.BASELINE]["diff"]:
        fail.append("the baseline differs on %d rows" % len(res[V.BASELINE]["diff"]))
    if a.limit:
        print("partial run (--limit %d): only the baseline check applies" % a.limit)
    else:
        for name in names:
            if name == V.BASELINE:
                continue
            if not res[name]["diff"]:
                fail.append("%s is not caught" % name)
            if name.split("_", 1)[0] in V.REQUIRED_X and not res[name]["x"]:
                fail.append("%s is caught by no row of family X" % name)
    for f in fail:
        print("FAIL: " + f)
    print("RESULT:", "FAIL" if fail else "ok", "(details: %s)" % os.path.join(outdir, "sab.json"))
    return 1 if fail else 0


if __name__ == "__main__":
    sys.exit(main())
