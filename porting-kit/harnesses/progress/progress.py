#!/usr/bin/env python3
"""Progress tracker — a per-module status table so any session (human or agent)
orients in seconds: which modules are done, which are mid-port, what gate each is
stuck at. State lives in a human-editable JSON file (default: progress.json).

The gates mirror PLAYBOOK.md Phase 4, in order:
    ported -> differential -> fuzzed -> sanitized -> unsafe_audited
A module's status is the highest gate it has cleared. "Done" = unsafe_audited.

  init   --modules a,b,c            seed a fresh table (all not_started)
  set    MODULE GATE                mark MODULE as having cleared GATE
  show   [--json]                   render the table
  ingest --unsafe-json FILE ...     auto-advance from a harness's --json output
  drift  --src DIR ...              fail if a shipped module is absent from the table

`drift` exists because "keep progress.json current" was a habit and not a control,
and habits rot silently. nmap's M5 milestone added ten modules (fpmodel, fp6,
fp6_match, build6, ndp, osscan, fpengine, ...) and **not one** reached the table;
meanwhile finished modules still read "differential". The retrospective procedure
leans on this file as a primary artifact, so a stale table does not merely fail to
help — it actively misleads the review that is supposed to catch drift. Wire
`drift` into CI and the table cannot silently rot. (LESSONS #021 — nmap M5.)

Usage: progress.py [--file progress.json] {init,set,show,ingest,drift} ...
       (--file is a top-level flag: it precedes the subcommand)
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

GATES = ["not_started", "ported", "differential", "fuzzed", "sanitized", "unsafe_audited"]
DONE = "unsafe_audited"


def load(path):
    if os.path.exists(path):
        return json.load(open(path, encoding="utf-8"))
    return {"modules": {}}


def save(path, state):
    json.dump(state, open(path, "w", encoding="utf-8"), indent=2, sort_keys=True)


def cmd_init(path, modules):
    state = {"modules": {m: "not_started" for m in modules}}
    save(path, state)
    print(f"seeded {len(modules)} module(s) into {path}")
    return 0


def cmd_set(path, module, gate):
    if gate not in GATES:
        print(f"error: gate must be one of {', '.join(GATES)}", file=sys.stderr)
        return 2
    state = load(path)
    state["modules"][module] = gate
    save(path, state)
    print(f"{module} -> {gate}")
    return 0


def render(state):
    mods = state["modules"]
    if not mods:
        return "(no modules; run `progress.py init --modules a,b,c`)"
    width = max((len(m) for m in mods), default=6)
    cols = GATES[1:]  # skip not_started in the tick columns
    head = "module".ljust(width) + "  " + "  ".join(c[:5].center(5) for c in cols) + "   status"
    rows = [head, "-" * len(head)]
    for m in sorted(mods):
        cur = mods[m]
        ci = GATES.index(cur) if cur in GATES else 0
        ticks = []
        for g in cols:
            ticks.append(" [x] " if ci >= GATES.index(g) else " [ ] ")
        status = "DONE" if cur == DONE else cur
        rows.append(m.ljust(width) + "  " + "  ".join(t[:5] for t in ticks) + "   " + status)
    done = sum(1 for v in mods.values() if v == DONE)
    rows.append("")
    rows.append(f"{done}/{len(mods)} modules fully gated (unsafe-audited).")
    return "\n".join(rows)


def cmd_show(path, as_json):
    state = load(path)
    if as_json:
        print(json.dumps(state, indent=2, sort_keys=True))
    else:
        print(render(state))
    return 0


def cmd_ingest(path, unsafe_jsons):
    """Advance modules to `unsafe_audited` when an audit_unsafe.py --json report
    shows zero undocumented findings for their files. Conservative: only ticks
    the final gate, and only for modules already at `sanitized`."""
    state = load(path)
    clean_files = set()
    for jf in unsafe_jsons:
        rep = json.load(open(jf, encoding="utf-8"))
        if rep.get("undocumented", 1) == 0:
            clean_files.add(os.path.basename(jf))
    # Heuristic: match module names appearing in the report path.
    for m in state["modules"]:
        if state["modules"][m] == "sanitized" and any(m in f for f in clean_files):
            state["modules"][m] = "unsafe_audited"
    save(path, state)
    print("ingest complete")
    return 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "progress.json")
        cmd_init(p, ["process", "sockets", "handles"])
        st = load(p)
        check("init seeds 3 not_started modules",
              len(st["modules"]) == 3 and all(v == "not_started" for v in st["modules"].values()))
        cmd_set(p, "process", "unsafe_audited")
        cmd_set(p, "sockets", "differential")
        st = load(p)
        check("set advances a module to DONE", st["modules"]["process"] == "unsafe_audited")
        out = render(st)
        check("render marks the done module", "DONE" in out)
        check("render shows partial progress", "differential" in out)
        check("render counts 1/3 fully gated", "1/3 modules fully gated" in out)

        # drift: a shipped module absent from the table must fail; the two naming
        # conventions real tables use must not produce false positives.
        crate = os.path.join(d, "crates", "core", "src")
        os.makedirs(crate)
        open(os.path.join(crate, "lib.rs"), "w").write(
            "pub mod a;\npub mod b;\npub mod c;\n")
        cmd_init(p, ["core::a"])
        check("untracked shipped modules fail drift",
              cmd_drift(p, [os.path.join(d, "crates")]) == 1)
        cmd_init(p, ["core::a", "b", "core::c::inner"])
        check("bare-name and sub-module tracking both count as covered",
              cmd_drift(p, [os.path.join(d, "crates")]) == 0)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


MOD_RE = re.compile(r"^\s*pub mod (\w+)\s*;", re.M)


def shipped_modules(srcs):
    """Every `pub mod` declared in a lib.rs under each src dir, as crate::module."""
    found = set()
    for src in srcs:
        for dirpath, _dirs, files in os.walk(src):
            if "lib.rs" not in files:
                continue
            text = open(os.path.join(dirpath, "lib.rs"), encoding="utf-8", errors="replace").read()
            # crates/<name>/src/lib.rs -> <name>
            parts = os.path.normpath(dirpath).split(os.sep)
            crate = parts[-2] if len(parts) >= 2 and parts[-1] == "src" else parts[-1]
            for m in MOD_RE.findall(text):
                found.add(f"{crate}::{m}")
    return found


def cmd_drift(path, srcs):
    """Report shipped modules missing from the table. Exit 1 on any drift."""
    data = load(path)
    tracked = set(data.get("modules", {}))
    # Two conventions to absorb, both seen in real tables:
    #  * sub-modules tracked instead of the parent (core::osdb::expr for core::osdb) —
    #    a parent covered by any child counts as tracked;
    #  * the crate prefix omitted (`model` for `core::model`).
    def covered(mod):
        bare = mod.split("::", 1)[1] if "::" in mod else mod
        for cand in (mod, bare):
            if cand in tracked or any(t.startswith(cand + "::") for t in tracked):
                return True
        return False

    shipped = shipped_modules(srcs)
    missing = sorted(m for m in shipped if not covered(m))
    for m in missing:
        print(f"UNTRACKED: {m}")
    print(f"\n{len(shipped)} shipped module(s), {len(missing)} untracked")
    if missing:
        print("Add them with: progress.py --file <f> set <module> <gate>")
    return 1 if missing else 0


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--file", default="progress.json")
    ap.add_argument("--self-test", action="store_true")
    sub = ap.add_subparsers(dest="cmd")
    pi = sub.add_parser("init"); pi.add_argument("--modules", required=True, help="comma-separated")
    ps = sub.add_parser("set"); ps.add_argument("module"); ps.add_argument("gate")
    psh = sub.add_parser("show"); psh.add_argument("--json", action="store_true")
    pg = sub.add_parser("ingest"); pg.add_argument("--unsafe-json", nargs="+", default=[])
    pd = sub.add_parser("drift"); pd.add_argument("--src", nargs="+", required=True)
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.cmd == "init":
        return cmd_init(args.file, [m.strip() for m in args.modules.split(",") if m.strip()])
    if args.cmd == "set":
        return cmd_set(args.file, args.module, args.gate)
    if args.cmd == "show":
        return cmd_show(args.file, args.json)
    if args.cmd == "ingest":
        return cmd_ingest(args.file, args.unsafe_json)
    if args.cmd == "drift":
        return cmd_drift(args.file, args.src)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
