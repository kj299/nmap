#!/usr/bin/env python3
"""M6.6 step 0b: the sanitizer quarantine for the LPeg corpus. LOCAL ONLY.

    screen_m66_lpeg.py --work SCRATCHDIR [--no-794] [--out m66_lpeg_quarantine.txt]

Runs every row of the generated corpus (oracle/gen_m66_lpeg_cases.py, default
arguments) through three harnesses, each resuming after the row that killed it:
  tree   this tree's standalone Lua + LPeg (oracle/build_lua_oracle.sh);
  asan   the same sources built with -fsanitize=address,undefined,
         -fno-sanitize-recover and LUA_USE_APICHECK, so the first report ends
         the process, and so does a push past the stack space the C function
         was given or checked for (lpeg-nested-capture-lua-stack-overflow
         writes past it into stack slack, which ASan alone cannot see);
  nmap   nmap 7.94 through oracle/m66_lpeg_probe.nse (skipped by --no-794).
plus the tree oracle once more in census mode (oracle/m66_lpeg_core.lua), which
CI also runs and whose debug hook moves the heap.
A row that crashes, trips a sanitizer or hangs in any of them is quarantined,
with the harnesses' reasons and, where the report's first lpeg.c frame falls
in a known defect, its ledger id (docs/M6.6-ANALYSIS.md §7). Rows the
generator tags `q=LEDGERID` are quarantined without being run: the C is
undefined or knowingly wrong there (a 16-bit truncation, D4), and some of them
would allocate gigabytes.

Crash outcomes depend on the harness and the binary's layout (§1.2), so a row
is quarantined when it misbehaves in at least one harness, and no per-harness
outcome is recorded as a pin. Quarantined rows never enter the golden; each
needs a port pin with the semantic answer by step e.

The output's header records the SHA-256 of the corpus it screened. The
regeneration (gen_m66_lpeg.py) refuses a corpus with another digest, so any
change to the generator means re-running this screen. CI never runs it: it
needs a sanitizer build and minutes, and its answer is committed.
"""

import argparse
import os
import re
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
REPO = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
sys.path.insert(0, HERE)
import classify_m66_lpeg as cl  # noqa: E402

# lpeg.c line ranges of the defects in §7, for naming a sanitizer report
LEDGER_LINES = [
    ((469, 482), "lpeg-nested-capture-lua-stack-overflow"),
    ((838, 845), "lpeg-cc-nil-without-ktable"),
    ((1175, 1252), "lpeg-getfirst-unbounded-recursion"),
    ((1500, 1515), "lpeg-codegen-jump-out-of-code"),
    ((2285, 2295), "lpeg-pattern-string-size-overflow"),
    ((2366, 2386), "lpeg-tree-size-int-overflow"),
    ((2395, 2402), "lpeg-pattern-string-size-overflow"),
    ((2636, 2662), "lpeg-tree-size-int-overflow"),
    ((3185, 3195), "lpeg-initposition-negation-overflow"),
    ((3388, 3396), "lpeg-doublecap-stack-overread"),
    ((3436, 3442), "lpeg-initposition-negation-overflow"),
    ((3500, 3508), "lpeg-code-freed-during-match"),
    ((3640, 3648), "lpeg-doublecap-stack-overread"),
]


def ledger_for(report):
    for m in re.finditer(r"lpeg\.c:(\d+)", report):
        line = int(m.group(1))
        for (lo, hi), lid in LEDGER_LINES:
            if lo <= line <= hi:
                return lid
        return "lpeg.c:%d" % line
    return None


def summarize(stderr, rc):
    m = re.search(r"SUMMARY: AddressSanitizer: (\S+)", stderr)
    a = re.search(r"Assertion `([^']{0,60})", stderr)
    if a:
        kind = "apicheck:" + re.sub(r"[^\w.<>=-]+", "_", a.group(1))[:40]
    elif m:
        kind = "asan:" + m.group(1)
    else:
        m = re.search(r"runtime error: ([^\n]{0,80})", stderr)
        if m:
            kind = "ubsan:" + m.group(1).split(" ")[0]
        elif rc is None:
            kind = "timeout"
        elif rc < 0:
            kind = "signal:%d" % -rc
        else:
            kind = "rc:%d" % rc
    return kind, ledger_for(stderr)


def build_asan(work):
    out = os.path.join(work, "lua-asan-apicheck")
    if os.path.exists(out):
        return out
    src = os.path.join(work, "asan-src")
    if os.path.exists(src):
        shutil.rmtree(src)
    os.makedirs(src)
    for d in (os.path.join(REPO, "liblua"),):
        for f in os.listdir(d):
            if f.endswith((".c", ".h")) and f != "luac.c":
                shutil.copy(os.path.join(d, f), src)
    for f in ("lpeg.c", "nse_lpeg.cc", "nse_lpeg.h", "nse_lua.h"):
        shutil.copy(os.path.join(REPO, f), src)
    with open(os.path.join(src, "nse_lpeg.cc"), "a") as fh:
        fh.write('\nextern "C" int oracle_open_lpeg (lua_State *L) { return luaopen_lpeg(L); }\n')
    linit = os.path.join(src, "linit.c")
    s = open(linit).read()
    for anchor in ("  {LUA_DBLIBNAME, luaopen_debug},", '#include "lualib.h"'):
        if s.count(anchor) != 1:
            sys.exit("linit.c anchor moved: %r" % anchor)
    s = s.replace("  {LUA_DBLIBNAME, luaopen_debug},", '  {LUA_DBLIBNAME, luaopen_debug},\n  {"lpeg", oracle_open_lpeg},')
    s = s.replace('#include "lualib.h"', '#include "lualib.h"\nLUALIB_API int oracle_open_lpeg (lua_State *L);')
    open(linit, "w").write(s)
    san = ["-O1", "-g", "-fno-omit-frame-pointer", "-fsanitize=address,undefined", "-fno-sanitize-recover=all",
           "-DLUA_USE_APICHECK"]
    objs = []
    for f in sorted(os.listdir(src)):
        if f.endswith(".c") and f != "lpeg.c":
            o = os.path.join(src, f[:-2] + ".o")
            subprocess.run(["cc"] + san + ["-std=gnu99", "-DLUA_USE_LINUX", "-I", src, "-c", os.path.join(src, f), "-o", o], check=True)
            objs.append(o)
    o = os.path.join(src, "nse_lpeg.o")
    subprocess.run(["c++"] + san + ["-DLUA_INCLUDED", "-I", src, "-c", os.path.join(src, "nse_lpeg.cc"), "-o", o], check=True)
    objs.append(o)
    subprocess.run(["c++", "-fsanitize=address,undefined", "-o", out] + objs + ["-lm", "-ldl"], check=True)
    shutil.rmtree(src)
    return out


def ids_in(path):
    ids = []
    with open(path, encoding="latin-1") as fh:
        for line in fh:
            if line.endswith("\n") and "\t" in line and not line.startswith("#"):
                ids.append(line.split("\t", 1)[0])
    return ids


def resume(name, cmd_for, cases_ids, out, timeout, env=None):
    """Run until every row has an output line; return {id: (kind, ledger)}."""
    bad = {}
    start = None
    if os.path.exists(out):
        os.remove(out)
    index = {cid: i for i, cid in enumerate(cases_ids)}
    t0 = time.time()
    while True:
        try:
            p = subprocess.run(cmd_for(start), capture_output=True, timeout=timeout, env=env)
            rc, err = p.returncode, p.stderr.decode("latin-1") + p.stdout.decode("latin-1")
        except subprocess.TimeoutExpired as e:
            rc, err = None, ((e.stderr or b"") + (e.stdout or b"")).decode("latin-1")
        done = ids_in(out) if os.path.exists(out) else []
        finished = (rc == 0 and len(done) == len(cases_ids))
        if finished:
            break
        nxt = index[done[-1]] + 1 if done else 0
        if start is not None:
            nxt = max(nxt, index[start])   # a resumed run that died on its first row
        if nxt >= len(cases_ids):
            if rc == 0:
                break
            sys.exit("%s: the harness failed after the last row (rc %s): %s" % (name, rc, err[-2000:]))
        cid = cases_ids[nxt]
        kind, lid = summarize(err, rc)
        bad[cid] = (kind, lid)
        sys.stderr.write("  %s: %s %s %s\n" % (name, cid, kind, lid or ""))
        if nxt + 1 >= len(cases_ids):
            break
        start = cases_ids[nxt + 1]
    sys.stderr.write("%s: %d rows, %d quarantined, %.1fs\n" % (name, len(cases_ids), len(bad), time.time() - t0))
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work", required=True, help="scratch directory (the ASan build and outputs go here)")
    ap.add_argument("--out", default=os.path.join(M6, "m66_lpeg_quarantine.txt"))
    ap.add_argument("--no-794", action="store_true")
    ap.add_argument("--timeout", type=int, default=900)
    a = ap.parse_args()
    work = os.path.abspath(a.work)
    os.makedirs(work, exist_ok=True)

    allp = os.path.join(work, "all_cases.txt")
    with open(allp, "w") as fh:
        subprocess.run([sys.executable, os.path.join(HERE, "gen_m66_lpeg_cases.py")], stdout=fh, check=True)
    digest = cl.sha256_file(allp)
    cases = cl.read_cases(allp)
    tagged = {cid: [t[2:] for t in tags if t.startswith("q=")][0] for cid, (tags, _) in cases.items()
              if any(t.startswith("q=") for t in tags)}
    runp = os.path.join(work, "run_cases.txt")
    with open(allp, encoding="latin-1") as src, open(runp, "w", encoding="latin-1") as dst:
        for line in src:
            if line.startswith("#") or line.split("\t", 1)[0] not in tagged:
                dst.write(line)
    run_ids = [cid for cid in cases if cid not in tagged]

    subprocess.run(["bash", os.path.join(HERE, "build_lua_oracle.sh")], check=True, stdout=subprocess.DEVNULL)
    tree = os.path.join(HERE, "lua")
    asan = build_asan(work)
    driver = os.path.join(HERE, "m66_lpeg_driver.lua")
    found = {}

    def merge(name, bad):
        for cid, v in bad.items():
            found.setdefault(cid, []).append((name,) + v)

    def lua_cmd(lua, out):
        return lambda start: [lua, driver, runp, out, "flush"] + (["start=" + start] if start else [])

    env_asan = dict(os.environ, ASAN_OPTIONS="detect_leaks=0:abort_on_error=0:symbolize=1:handle_abort=1",
                    UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1")
    merge("tree", resume("tree", lua_cmd(tree, os.path.join(work, "out_tree.txt")), run_ids, os.path.join(work, "out_tree.txt"), a.timeout))
    # the census (a debug-hooked run, which CI repeats) moves the heap: a
    # layout-dependent defect can kill it on a row the plain run survived
    cen = os.path.join(work, "out_census.txt")
    merge("census", resume("census", lambda start: lua_cmd(tree, cen)(start) + ["census"], run_ids, cen, a.timeout))
    merge("asan", resume("asan", lua_cmd(asan, os.path.join(work, "out_asan.txt")), run_ids, os.path.join(work, "out_asan.txt"),
                         a.timeout * 4, env_asan))
    def nmap_cmd_for(cases_path, out):
        def cmd(start):
            args = "core=%s,cases=%s,out=%s,flush=1" % (os.path.join(HERE, "m66_lpeg_core.lua"), cases_path, out)
            if start:
                args += ",start=" + start
            return ["nmap", "--datadir", REPO, "-sn", "-n", "--script", os.path.join(HERE, "m66_lpeg_probe.nse"),
                    "--script-args", args, "127.0.0.1"]
        return cmd

    if not a.no_794:
        out = os.path.join(work, "out_794.txt")
        merge("nmap794", resume("nmap794", nmap_cmd_for(runp, out), run_ids, out, a.timeout))

    # Verify as CI runs: one uninterrupted process per harness over the rows
    # that remain. Resumed runs above restart the process after each crash,
    # so the heap they leave differs; repeat until a whole pass is clean.
    for rnd in range(1, 11):
        keep = os.path.join(work, "verify_cases.txt")
        with open(runp, encoding="latin-1") as src, open(keep, "w", encoding="latin-1") as dst:
            for line in src:
                if line.startswith("#") or line.split("\t", 1)[0] not in found:
                    dst.write(line)
        keep_ids = [cid for cid in run_ids if cid not in found]
        vout = os.path.join(work, "verify_out.txt")
        new = resume("verify-tree", lambda st: [tree, driver, keep, vout, "flush"] + (["start=" + st] if st else []),
                     keep_ids, vout, a.timeout)
        new.update(resume("verify-census", lambda st: [tree, driver, keep, vout, "flush", "census"] + (["start=" + st] if st else []),
                          keep_ids, vout, a.timeout))
        if not a.no_794:
            new.update(resume("verify-nmap794", lambda st: nmap_cmd_for(keep, vout)(st), keep_ids, vout, a.timeout))
        merge("verify%d" % rnd, new)
        if not new:
            break
    else:
        sys.exit("the verification passes did not converge")

    with open(a.out, "w", encoding="latin-1") as fh:
        fh.write("# M6.6 step 0b: LPeg corpus rows no oracle may record (LESSONS #033), from oracle/screen_m66_lpeg.py\n")
        fh.write("# screened-corpus-sha256: %s\n" % digest)
        fh.write("# harnesses: tree, census, asan%s\n" % ("" if a.no_794 else ", nmap794"))
        fh.write("# rows: %d (%d tagged by the generator, %d found by a harness)\n" % (len(tagged) + len(found), len(tagged), len(found)))
        fh.write("# id<TAB>reason<TAB>chunk (as in the cases file). reason: q=LEDGERID for a generator tag, else\n")
        fh.write("# harness=kind[@ledger-id] for each harness that misbehaved, `;`-separated\n")
        for cid, (tags, chunk) in cases.items():
            if cid in tagged:
                fh.write("%s\tq=%s\t%s\n" % (cid, tagged[cid], chunk))
            elif cid in found:
                reason = ";".join("%s=%s%s" % (h, k, ("@" + l) if l else "") for h, k, l in found[cid])
                fh.write("%s\t%s\t%s\n" % (cid, reason, chunk))
    sys.stderr.write("wrote %s: %d quarantined (%d tagged, %d found)\n" % (a.out, len(tagged) + len(found), len(tagged), len(found)))


if __name__ == "__main__":
    main()
