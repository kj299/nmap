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
  exempt MODULE GATE --reason ...   record that GATE does not apply to MODULE
  cover  MODULE --targets a,b       record which fuzz target(s) cover MODULE
  audit  [--fuzz-manifest F] [--require-done] [--src DIR ...]
                                    fail on an unreasoned exemption or a coverage
                                    claim naming a fuzz target that does not exist;
                                    with --src, also on a stale stamped tick
  stamp  MODULE GATE --src DIR ...  record a digest of MODULE's source files at
                                    the moment GATE was (re-)run; `set ... --src`
                                    does the same as it ticks

A gate tick vouches for the code as it was when the gate ran. nmap's
`core::nse::stdlib::base` stayed "fuzzed" while base.rs grew from 756 to 2,499
lines and gained a byte parser (`tonumber(s, base)`), because its fuzz target
reaches two functions and nothing re-checked the tick (LESSONS #045). Stamps are
opt-in: a table without them audits exactly as before. Once a gate is stamped,
`audit --src` fails when the module's files have changed since, until the gate
is re-run and re-stamped, which is the moment to ask whether its fuzz target
still reaches the new entry points.

A gate a module is exempt from renders as [-], never [x] — an exemption is an
argument that the gate does not apply, not evidence that it passed. There is
deliberately no blanket `n/a` status; see the note above GATES for why.

`drift` exists because "keep progress.json current" was a habit and not a control,
and habits rot silently. nmap's M5 milestone added ten modules (fpmodel, fp6,
fp6_match, build6, ndp, osscan, fpengine, ...) and **not one** reached the table;
meanwhile finished modules still read "differential". The retrospective procedure
leans on this file as a primary artifact, so a stale table does not merely fail to
help — it actively misleads the review that is supposed to catch drift. Wire
`drift` into CI and the table cannot silently rot. (LESSONS #021 — nmap M5.)

Usage: progress.py [--file progress.json] {init,set,show,ingest,drift,exempt,cover,audit,stamp} ...
       (--file is a top-level flag: it precedes the subcommand)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys

GATES = ["not_started", "ported", "differential", "fuzzed", "sanitized", "unsafe_audited"]
DONE = "unsafe_audited"

# Why there is no blanket `n/a` MODULE state
# -----------------------------------------
# The obvious fix for "this module will never have a fuzz target" is a sixth status,
# `n/a`. Resist it. A module is not inapplicable; a *specific gate* is inapplicable to
# it, and collapsing that into one module-level flag throws away which gates still
# apply — a scheduler exempt from `fuzzed` must still be differential-clean and
# unsafe-audited. Worse, one escape hatch broad enough to silence a module is broad
# enough to silence the module you should have looked harder at: nmap's `output`
# renders attacker-controlled hostnames and service banners into XML, looks exactly as
# "unfuzzable" as the schedulers beside it, and is the one module on that list that
# genuinely needs a fuzz target.
#
# So exemptions are PER GATE and carry a REASON, in the same shape as the divergence
# ledger this kit already requires: every exemption is named, argued, and checked.
# `audit` hard-fails on an exemption without a real reason, and `show` renders an
# exempt gate as [-], never [x] — an exemption is not a pass, and must not read like
# one at a glance.
MIN_REASON_LEN = 30


def exemptions(state):
    return state.get("exemptions", {})


def is_exempt(state, module, gate):
    return gate in exemptions(state).get(module, {})


def effective_done(state, module):
    """True when every gate this module has not cleared is explicitly exempt."""
    cur = state["modules"].get(module, "not_started")
    ci = GATES.index(cur) if cur in GATES else 0
    for g in GATES[1:]:
        if GATES.index(g) > ci and not is_exempt(state, module, g):
            return False
    return True


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


def cmd_set(path, module, gate, srcs=None):
    if gate not in GATES:
        print(f"error: gate must be one of {', '.join(GATES)}", file=sys.stderr)
        return 2
    state = load(path)
    state["modules"][module] = gate
    save(path, state)
    print(f"{module} -> {gate}")
    if srcs and gate != "not_started":
        return cmd_stamp(path, module, gate, srcs)
    return 0


def module_files(srcs, module):
    """The source files that make up MODULE (`crate::a::b`): `a/b.rs` and
    everything under `a/b/`, inside `<src>/<crate>/src`. A crate name alone
    means the whole crate."""
    crate, _, rest = module.partition("::")
    parts = rest.split("::") if rest else []
    found = []
    for root in srcs:
        for base in (os.path.join(root, crate, "src"),
                     os.path.join(root, "src") if os.path.basename(os.path.normpath(root)) == crate
                     else None):
            if not base or not os.path.isdir(base):
                continue
            target = os.path.join(base, *parts) if parts else base
            if parts and os.path.isfile(target + ".rs"):
                found.append((base, target + ".rs"))
            if os.path.isdir(target):
                for dirpath, _dirs, files in os.walk(target):
                    found.extend((base, os.path.join(dirpath, f)) for f in files if f.endswith(".rs"))
    return sorted(set(found), key=lambda bf: bf[1])


def module_digest(srcs, module):
    """(sha256 over each file's path relative to its crate's src/ and bytes,
    file count), or (None, 0) when the module has no files of its own."""
    files = module_files(srcs, module)
    if not files:
        return None, 0
    h = hashlib.sha256()
    for base, f in files:
        h.update(os.path.relpath(f, base).replace(os.sep, "/").encode() + b"\0")
        with open(f, "rb") as fh:
            h.update(hashlib.sha256(fh.read()).digest())
    return h.hexdigest(), len(files)


def cmd_stamp(path, module, gate, srcs):
    """Record the digest of MODULE's files as of GATE's (re-)run."""
    if gate not in GATES[1:]:
        print(f"error: gate must be one of {', '.join(GATES[1:])}", file=sys.stderr)
        return 2
    state = load(path)
    if module not in state.get("modules", {}):
        print(f"error: unknown module {module!r}", file=sys.stderr)
        return 2
    digest, n = module_digest(srcs, module)
    if digest is None:
        print(f"error: no source files found for {module!r} under {', '.join(srcs)} "
              "(expected <src>/<crate>/src/<path>.rs or a directory)", file=sys.stderr)
        return 2
    state.setdefault("stamps", {}).setdefault(module, {})[gate] = {"sha256": digest, "files": n}
    save(path, state)
    print(f"{module}: {gate} stamped at {digest[:12]} ({n} file(s))")
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
            # Exemption is checked FIRST, deliberately. A module's status is the
            # highest gate it has cleared *or been exempted from*, so a module can sit
            # above an exempt gate — and if the cleared-check ran first, that gate
            # would render [x] and the exemption would vanish from the table at
            # exactly the point someone reads it to decide the module is done.
            if is_exempt(state, m, g):
                # NOT [x]. An exemption is a recorded argument that the gate does not
                # apply, not evidence the gate passed, and the table must not let the
                # two blur at a glance.
                ticks.append(" [-] ")
            elif ci >= GATES.index(g):
                ticks.append(" [x] ")
            else:
                ticks.append(" [ ] ")
        if cur == DONE:
            status = "DONE"
        elif effective_done(state, m):
            status = "DONE*"
        else:
            status = cur
        rows.append(m.ljust(width) + "  " + "  ".join(t[:5] for t in ticks) + "   " + status)
    done = sum(1 for v in mods.values() if v == DONE)
    starred = sum(1 for m in mods if mods[m] != DONE and effective_done(state, m))
    rows.append("")
    rows.append(f"{done}/{len(mods)} modules fully gated (unsafe-audited).")
    if starred:
        rows.append(
            f"{starred} further module(s) complete on every gate that applies "
            f"(DONE*, [-] = exempt with a recorded reason; see `exemptions`)."
        )
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


def cmd_exempt(path, module, gate, reason):
    """Record that GATE does not apply to MODULE, with the argument for why."""
    if gate not in GATES[1:]:
        print(f"error: gate must be one of {', '.join(GATES[1:])}", file=sys.stderr)
        return 2
    if len(reason.strip()) < MIN_REASON_LEN:
        print(
            f"error: a reason of at least {MIN_REASON_LEN} characters is required.\n"
            "An exemption is an argument that a gate does not apply. If it cannot be\n"
            "written down, it has not been made.",
            file=sys.stderr,
        )
        return 2
    state = load(path)
    if module not in state.get("modules", {}):
        print(f"error: unknown module {module!r}", file=sys.stderr)
        return 2
    state.setdefault("exemptions", {}).setdefault(module, {})[gate] = reason.strip()
    save(path, state)
    print(f"{module}: {gate} exempt — {reason.strip()[:60]}...")
    return 0


def cmd_cover(path, module, targets):
    """Record which fuzz target(s) cover MODULE, so the claim is auditable."""
    state = load(path)
    if module not in state.get("modules", {}):
        print(f"error: unknown module {module!r}", file=sys.stderr)
        return 2
    state.setdefault("coverage", {})[module] = sorted(set(targets))
    save(path, state)
    print(f"{module} <- {', '.join(sorted(set(targets)))}")
    return 0


def _manifest_targets(manifest):
    """Fuzz target names from a cargo-fuzz Cargo.toml's [[bin]] entries."""
    if not manifest or not os.path.exists(manifest):
        return None
    text = open(manifest, encoding="utf-8", errors="replace").read()
    return set(re.findall(r'^name = "(.+)"$', text, re.M))


def cmd_audit(path, manifest, require_done=False, srcs=None):
    """Hard-fail on an unbacked exemption or a coverage claim naming no real target.

    This exists because module-to-target coverage had only ever been *inferred*, and
    inference is wrong in both directions. nmap's M7 analysis put "19 modules are
    covered but unrecorded" in a milestone document; the real number was 14. Six of
    the nineteen were counted because a fuzz target shared a NAME with the module
    (`sys::ndp` credited to `ndp_advert`, which fuzzes `core::ndp` — the sys module is
    the I/O driver and parses nothing). One was missed in the other direction:
    `core::osdb::parse` IS covered, by a target importing `osdb::model::FingerPrintDb`,
    because an inherent impl need not live in the module its type is declared in.
    No heuristic over import paths gets both right. Write the mapping down.

    It also names every module that is not done. With `require_done`, that fails.
    nmap's `core::output` sat at `differential` from M1 to M6 with no exemption
    and no note. `show` printed "103/104" every time, and nothing asked why
    (LESSONS #035). A retrospective, and a milestone's close, run with
    `--require-done`. Mid-milestone, the listing alone is the reminder.
    """
    state = load(path)
    mods = state.get("modules", {})
    rc = 0

    for module, gates in sorted(exemptions(state).items()):
        if module not in mods:
            print(f"EXEMPT-UNKNOWN-MODULE: {module}")
            rc = 1
            continue
        cur = mods[module]
        ci = GATES.index(cur) if cur in GATES else 0
        for gate, reason in sorted(gates.items()):
            if gate not in GATES[1:]:
                print(f"EXEMPT-UNKNOWN-GATE: {module}: {gate}")
                rc = 1
            elif len(str(reason).strip()) < MIN_REASON_LEN:
                print(f"EXEMPT-NO-REASON: {module}: {gate}")
                rc = 1
            elif gate == "fuzzed" and state.get("coverage", {}).get(module):
                # A contradiction worth failing on: "the fuzz gate does not apply to
                # this module" and "here are the fuzz targets covering this module"
                # cannot both be true. Whichever is stale, the table is lying.
                print(f"EXEMPT-BUT-COVERED: {module}: exempt from fuzzed, yet coverage "
                      f"names {', '.join(state['coverage'][module])}")
                rc = 1
        del ci, cur

    known = _manifest_targets(manifest)
    for module, targets in sorted(state.get("coverage", {}).items()):
        if module not in mods:
            print(f"COVER-UNKNOWN-MODULE: {module}")
            rc = 1
            continue
        if known is None:
            continue
        for t in targets:
            if t not in known:
                print(f"COVER-NO-SUCH-TARGET: {module} -> {t}")
                rc = 1

    stamps = state.get("stamps", {})
    if stamps and srcs:
        for module, gates in sorted(stamps.items()):
            if module not in mods:
                print(f"STAMP-UNKNOWN-MODULE: {module}")
                rc = 1
                continue
            now, n = module_digest(srcs, module)
            for gate, rec in sorted(gates.items()):
                if now != rec.get("sha256"):
                    was = rec.get("sha256", "?")[:12]
                    print(f"STALE-TICK: {module}: {gate} was stamped at {was} "
                          f"({rec.get('files', '?')} file(s)); its files are now "
                          f"{(now or 'missing')[:12]} ({n} file(s)). Re-run the gate, check its "
                          f"target still reaches the new code, then `stamp {module} {gate}`.")
                    rc = 1
    elif stamps:
        print("note: stamped ticks not checked (pass --src <crates dir>)")

    stalled = sorted(m for m in mods if not effective_done(state, m))
    for module in stalled:
        print(f"NOT-DONE: {module} at {mods[module]}"
              + ("" if require_done else " (pass --require-done to fail on this)"))
    if require_done and stalled:
        rc = 1

    n_ex = sum(len(g) for g in exemptions(state).values())
    n_cov = len(state.get("coverage", {}))
    if known is None and state.get("coverage"):
        print("note: no fuzz manifest given; coverage targets not checked "
              "(pass --fuzz-manifest <path/to/fuzz/Cargo.toml>)")
    print(f"\n{n_ex} exemption(s), {n_cov} coverage mapping(s) — "
          + ("OK" if rc == 0 else "PROBLEMS ABOVE"))
    return rc


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
        # Assert the CLEARED marker explicitly. Every other render assertion here is
        # about [-], DONE or a count, and all of them stayed green through a version
        # of this function that had lost its [x] branch entirely — the table rendered
        # every gate of every module as unticked and still passed the suite.
        done_row = [r for r in out.splitlines() if r.startswith("process")][0]
        check("a cleared gate renders [x]", " [x] " in done_row)
        part_row = [r for r in out.splitlines() if r.startswith("sockets")][0]
        check("an uncleared gate renders [ ]", " [ ] " in part_row)
        check("a partially-gated module shows both markers", " [x] " in part_row)

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

        # A vendored tree must be skipped, and skipping it must not make an
        # UNVENDORED untracked module disappear along with it.
        vend = os.path.join(d, "crates", "vendor", "thirdparty", "src")
        os.makedirs(vend)
        open(os.path.join(vend, "lib.rs"), "w").write("pub mod x;\npub mod y;\n")
        open(os.path.join(d, "crates", "vendor", "thirdparty", "PROVENANCE.md"), "w").write("x")
        check("a PROVENANCE.md tree is not walked",
              cmd_drift(p, [os.path.join(d, "crates")]) == 0)
        open(os.path.join(crate, "lib.rs"), "a").write("pub mod d;\n")
        check("skipping a vendored tree still catches real drift beside it",
              cmd_drift(p, [os.path.join(d, "crates")]) == 1)

        # --- per-gate exemptions -------------------------------------------------
        cmd_init(p, ["sched", "parser"])
        cmd_set(p, "sched", "differential")
        cmd_set(p, "parser", "differential")
        REASON = "scheduling math over our own state; no untrusted-input parse path"
        check("an exemption needs a real reason",
              cmd_exempt(p, "sched", "fuzzed", "n/a") == 2)
        check("an exemption on an unknown gate is refused",
              cmd_exempt(p, "sched", "vibes", REASON) == 2)
        check("an exemption on an unknown module is refused",
              cmd_exempt(p, "nope", "fuzzed", REASON) == 2)
        check("a reasoned exemption is accepted",
              cmd_exempt(p, "sched", "fuzzed", REASON) == 0)
        st = load(p)
        check("an exempt gate is not counted as cleared",
              st["modules"]["sched"] == "differential")
        check("exempt renders as [-], never [x]", " [-] " in render(st))
        check("a module exempt from only SOME remaining gates is not done",
              not effective_done(st, "sched"))
        for g in ("sanitized", "unsafe_audited"):
            cmd_exempt(p, "sched", g, REASON)
        st = load(p)
        check("exempt from every remaining gate reads DONE*",
              effective_done(st, "sched") and "DONE*" in render(st))
        check("the module with no exemptions is still not done",
              not effective_done(st, "parser"))
        check("DONE* is counted separately from DONE",
              "0/2 modules fully gated" in render(st))
        check("audit passes on a well-formed table", cmd_audit(p, None) == 0)
        check("audit --require-done fails while a module is not done",
              cmd_audit(p, None, require_done=True) == 1)
        # A module may legitimately advance PAST an exempt gate; the exemption must
        # still render as [-] rather than silently becoming [x].
        cmd_set(p, "sched", "unsafe_audited")
        st = load(p)
        row = [r for r in render(st).splitlines() if r.startswith("sched")][0]
        check("an exempt gate stays [-] even when the module advances past it",
              " [-] " in row and row.rstrip().endswith("DONE"))
        # "exempt from fuzzing" and "here are its fuzz targets" cannot both be true.
        cmd_cover(p, "sched", ["parse_thing"])
        check("audit rejects exempt-from-fuzzed alongside a coverage claim",
              cmd_audit(p, None) == 1)

        # --- coverage mapping is checked against the real fuzz manifest ----------
        cmd_init(p, ["parser"])
        cmd_set(p, "parser", "differential")
        man = os.path.join(d, "Cargo.toml")
        open(man, "w").write('[package]\nname = "fuzz"\n\n[[bin]]\nname = "parse_thing"\n')
        check("a coverage claim naming a real target passes",
              cmd_cover(p, "parser", ["parse_thing"]) == 0 and cmd_audit(p, man) == 0)
        check("a coverage claim naming no such target fails",
              cmd_cover(p, "parser", ["parse_ghost"]) == 0 and cmd_audit(p, man) == 1)

        # --- stamped ticks (LESSONS #045) ----------------------------------------
        src = os.path.join(d, "stamp", "crates")
        core = os.path.join(src, "core", "src")
        os.makedirs(os.path.join(core, "nse"))
        files = {"lib.rs": "pub mod parser;\npub mod nse;\n", "parser.rs": "fn p() {}\n",
                 "nse/mod.rs": "pub mod base;\n", "nse/base.rs": "fn b() {}\n"}
        for rel, body in files.items():
            open(os.path.join(core, rel), "w").write(body)
        cmd_init(p, ["core::parser", "core::nse", "core::nse::base"])
        check("a table with no stamps audits as before, --src or not",
              cmd_audit(p, None, srcs=[src]) == 0)
        check("stamping a module with no files of its own is refused",
              cmd_stamp(p, "core::parser", "fuzzed", [os.path.join(d, "nowhere")]) == 2)
        check("set --src ticks and stamps in one step",
              cmd_set(p, "core::parser", "fuzzed", [src]) == 0
              and "fuzzed" in load(p)["stamps"]["core::parser"])
        cmd_stamp(p, "core::nse", "fuzzed", [src])
        check("audit passes while the stamped files are unchanged",
              cmd_audit(p, None, srcs=[src]) == 0)
        open(os.path.join(core, "parser.rs"), "a").write("fn tonumber_base() {}\n")
        check("audit fails once a stamped module's file changes",
              cmd_audit(p, None, srcs=[src]) == 1)
        check("re-stamping after re-running the gate clears it",
              cmd_stamp(p, "core::parser", "fuzzed", [src]) == 0
              and cmd_audit(p, None, srcs=[src]) == 0)
        open(os.path.join(core, "nse", "str2int.rs"), "w").write("fn s() {}\n")
        check("a new file inside a directory module makes its tick stale",
              cmd_audit(p, None, srcs=[src]) == 1)
        cmd_stamp(p, "core::nse", "fuzzed", [src])
        check("audit without --src does not check stamps (opt-in)",
              cmd_audit(p, None) == 0)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


MOD_RE = re.compile(r"^\s*pub mod (\w+)\s*;", re.M)


def shipped_modules(srcs):
    """Every `pub mod` declared in a lib.rs OR a mod.rs, as crate::path::to::module.

    mod.rs was originally not scanned, and the omission was invisible because it makes
    the gate report GREEN rather than red: nmap's table showed "56 shipped modules, 0
    untracked" while 25 sub-modules — every `headers::*`, `osdb::*`, `osprobe::*`,
    `nse::*`, `sigstore::*` — were outside the walk entirely. One of them,
    `core::osprobe::demux`, was genuinely missing from the table AND was the only
    untested byte parser in the port (nmap M7.1). A drift gate that cannot see
    sub-modules cannot do the job it was added for, since sub-modules are where a
    maturing port puts most of its code.
    """
    found = set()
    vendored = []
    for src in srcs:
        for dirpath, dirs, files in os.walk(src):
            # A tree that declares its own provenance is VENDORED THIRD PARTY, not a
            # ported module, and must not be walked: the table tracks this port's own
            # code through the six gates, and "ported -> differential -> fuzzed" is a
            # claim that cannot be true of code nobody here ported. Listing a vendored
            # dependency's sub-modules would either force 29 false gate claims or force
            # someone to delete the gate.
            #
            # The marker is PROVENANCE.md rather than a path pattern or a --exclude
            # flag, because a vendored tree has to carry one anyway (upstream, commit,
            # local patches) and a directory cannot acquire one by accident.
            #
            # The skip is REPORTED, never silent. This is the same harness whose walk
            # once missed every mod.rs and reported "0 untracked" while 25 sub-modules
            # sat outside it; an exclusion nobody can see is how that happens again.
            if "PROVENANCE.md" in files:
                vendored.append(dirpath)
                dirs[:] = []
                continue
            for fname in ("lib.rs", "mod.rs"):
                if fname not in files:
                    continue
                path = os.path.join(dirpath, fname)
                text = open(path, encoding="utf-8", errors="replace").read()
                parts = os.path.normpath(dirpath).split(os.sep)
                if fname == "lib.rs":
                    # crates/<name>/src/lib.rs -> crate <name>, no module prefix
                    crate = parts[-2] if len(parts) >= 2 and parts[-1] == "src" else parts[-1]
                    prefix = ""
                else:
                    # crates/<name>/src/a/b/mod.rs -> crate <name>, prefix a::b
                    if "src" not in parts:
                        continue
                    i = len(parts) - 1 - parts[::-1].index("src")
                    crate = parts[i - 1] if i >= 1 else parts[-1]
                    prefix = "::".join(parts[i + 1:])
                for m in MOD_RE.findall(text):
                    full = f"{prefix}::{m}" if prefix else m
                    found.add(f"{crate}::{full}")
    return found, sorted(vendored)


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

    shipped, vendored = shipped_modules(srcs)
    missing = sorted(m for m in shipped if not covered(m))
    for m in missing:
        print(f"UNTRACKED: {m}")
    for v in vendored:
        print(f"vendored (not walked, see {v}/PROVENANCE.md): {v}")
    print(f"\n{len(shipped)} shipped module(s), {len(missing)} untracked"
          + (f", {len(vendored)} vendored tree(s) skipped" if vendored else ""))
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
    ps.add_argument("--src", nargs="+", help="also stamp the module's source digest for this gate")
    pst = sub.add_parser("stamp"); pst.add_argument("module"); pst.add_argument("gate")
    pst.add_argument("--src", nargs="+", required=True, help="crates directory (as for drift)")
    psh = sub.add_parser("show"); psh.add_argument("--json", action="store_true")
    pg = sub.add_parser("ingest"); pg.add_argument("--unsafe-json", nargs="+", default=[])
    pd = sub.add_parser("drift"); pd.add_argument("--src", nargs="+", required=True)
    pe = sub.add_parser("exempt")
    pe.add_argument("module"); pe.add_argument("gate")
    pe.add_argument("--reason", required=True)
    pc = sub.add_parser("cover")
    pc.add_argument("module"); pc.add_argument("--targets", required=True, help="comma-separated")
    pa = sub.add_parser("audit")
    pa.add_argument("--fuzz-manifest", default=None,
                    help="cargo-fuzz Cargo.toml, to check coverage names against [[bin]] entries")
    pa.add_argument("--require-done", action="store_true",
                    help="fail on any module that is not done (retrospectives, milestone close)")
    pa.add_argument("--src", nargs="+",
                    help="crates directory: also fail on a stamped tick whose files changed")
    args = ap.parse_args(argv)

    if args.self_test:
        return _self_test()
    if args.cmd == "init":
        return cmd_init(args.file, [m.strip() for m in args.modules.split(",") if m.strip()])
    if args.cmd == "set":
        return cmd_set(args.file, args.module, args.gate, args.src)
    if args.cmd == "stamp":
        return cmd_stamp(args.file, args.module, args.gate, args.src)
    if args.cmd == "show":
        return cmd_show(args.file, args.json)
    if args.cmd == "ingest":
        return cmd_ingest(args.file, args.unsafe_json)
    if args.cmd == "drift":
        return cmd_drift(args.file, args.src)
    if args.cmd == "exempt":
        return cmd_exempt(args.file, args.module, args.gate, args.reason)
    if args.cmd == "cover":
        return cmd_cover(args.file, args.module,
                         [t.strip() for t in args.targets.split(",") if t.strip()])
    if args.cmd == "audit":
        return cmd_audit(args.file, args.fuzz_manifest, args.require_done, args.src)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main())
