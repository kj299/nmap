#!/usr/bin/env python3
"""Output normalization for differential testing — importable + CLI.

The C oracle and the Rust rewrite will differ in *nondeterministic* ways that are
not bugs: PIDs, timestamps, ephemeral ports, pointer/handle values, and sometimes
line ordering. If you diff raw output, that noise buries real regressions and
fakes false ones. These rules (learned from winlsof, where PIDs/timestamps/hex
handles all varied run-to-run) canonicalize both sides *identically* before the
diff, so only meaningful differences survive.

Rules are data (REGEX list + flags), so a new port tunes them without editing
logic. Keep them symmetric: whatever you erase from the oracle you erase from the
Rust, or you manufacture a divergence.

Noise rules and TOLERANCES are different things. A noise rule erases what varies
run to run (a PID, a timestamp) and is safe everywhere. A tolerance erases a
*known, ledgered* difference between the port and C (an error message that names
argument #1 where C says #2) and is an EXEMPTION: applied to every case, it
blinds the gate to that same difference anywhere else. nmap's LPeg corpus gate
tried its argument-name and line-number tolerances on every differing row; they
reached 5,906 of 62,599 rows, and a port sabotaged to report the wrong argument
number passed on all of them (LESSONS #048). So a tolerance is a SCOPED rule:
(name, regex, replacement, the case ids it was ledgered for). It fires only on
those cases, and `diff_run.py` fails a listed case that no longer needs it, so
its membership is pinned in both directions. Name the ledger entry that argues
for it; when the entry closes, the tolerance goes with it (LESSONS #031).

A tolerance file (TOML or JSON) holds a list of them:

  [[tolerance]]
  name = "argname"                       # what the difference is
  ledger = "lpeg-argument-names"         # the DIVERGENCES.md entry that argues it
  regex = "bad argument #[0-9]+"
  repl = "bad argument #N"
  cases = ["A.name.typeerr", "X.name.rep"]

Usage:
  normalize.py [--sort] [--strip-blank] [--case ID --tolerances FILE] [FILE]
                                                    # stdin if no FILE
  normalize.py --self-test
"""
from __future__ import annotations

import argparse
import json
import re
import sys

# (name, compiled-regex, replacement). Ordered; applied to every line.
DEFAULT_RULES = [
    ("hex-ptr",     re.compile(r"0x[0-9a-fA-F]{6,16}"),                 "0xPTR"),
    ("iso-time",    re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:?\d{2})?"), "<TIME>"),
    ("clock-time",  re.compile(r"\b\d{1,2}:\d{2}:\d{2}\b"),            "<TIME>"),
    # ephemeral ports (IANA 49152-65535) on an addr:port — mask the port only
    ("ephem-port",  re.compile(r"(?<=[:.])(4915[2-9]|491[6-9]\d|49[2-9]\d\d|5\d{4}|6[0-4]\d{3}|65[0-4]\d\d|655[0-2]\d|6553[0-5])\b"), "<EPORT>"),
    ("uuid",        re.compile(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}"), "<UUID>"),
]

# Rules that need an explicit opt-in because they are lossy for some tools.
PID_RULE = ("pid-like", re.compile(r"\b\d{2,7}\b"), "<NUM>")


def scoped_rule(name, pattern, repl, cases, ledger=None):
    """A tolerance: (name, compiled regex, replacement, frozenset of case ids,
    ledger id). It fires only on the cases it was ledgered for."""
    if not cases:
        raise ValueError(f"tolerance {name!r} names no cases; an unscoped tolerance "
                         "is an exemption for every case (LESSONS #048)")
    return (name, re.compile(pattern), repl, frozenset(cases), ledger)


def load_tolerances(path):
    """Read [[tolerance]] entries from a TOML or JSON file into scoped rules."""
    if not path:
        return []
    if path.endswith(".json"):
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
    else:
        import tomllib
        with open(path, "rb") as f:
            data = tomllib.load(f)
    entries = data.get("tolerance", []) if isinstance(data, dict) else data
    return [scoped_rule(e["name"], e["regex"], e.get("repl", ""), e["cases"], e.get("ledger"))
            for e in entries]


def scoped_for(scoped, case_id):
    """The (name, rx, repl) triples of the tolerances that apply to CASE_ID."""
    return [(n, rx, repl) for n, rx, repl, cases, _l in scoped if case_id in cases]


def normalize_text(text, rules=DEFAULT_RULES, sort=False, strip_blank=False,
                   trim=True, mask_numbers=False, case_id=None, scoped=()):
    active = list(rules) + ([PID_RULE] if mask_numbers else []) + scoped_for(scoped, case_id)
    out = []
    for line in text.splitlines():
        for _name, rx, repl in active:
            line = rx.sub(repl, line)
        if trim:
            line = line.rstrip()
            line = re.sub(r"[ \t]+", " ", line)
        if strip_blank and not line.strip():
            continue
        out.append(line)
    if sort:
        out.sort()
    return "\n".join(out) + ("\n" if out else "")


def _self_test():
    a = "pid 1234 conn 127.0.0.1:53621 at 2026-07-05 10:00:01 ptr 0xffffd48fe3cb"
    b = "pid 9999 conn 127.0.0.1:61000 at 2026-07-05 11:22:33 ptr 0x00007ffabc12"
    # PIDs are nondeterministic noise → compare with --mask-numbers on.
    na, nb = normalize_text(a, mask_numbers=True), normalize_text(b, mask_numbers=True)
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("nondeterministic noise normalizes two runs to equal", na == nb)
    check("hex pointer masked", "0xPTR" in na)
    check("timestamp masked", "<TIME>" in na)
    check("ephemeral port masked", "<EPORT>" in na)
    # a REAL difference must survive
    c = normalize_text("state LISTEN")
    d = normalize_text("state CLOSED")
    check("a real difference is preserved", c != d)
    # sort makes order-independent
    check("sort canonicalizes order",
          normalize_text("b\na", sort=True) == normalize_text("a\nb", sort=True))

    # A tolerance is scoped to the cases it was ledgered for (LESSONS #048).
    tol = [scoped_rule("argname", r"bad argument #\d+", "bad argument #N", ["A.name.typeerr"])]
    c_out, r_out = "bad argument #1 to 'P'", "bad argument #2 to 'P'"
    check("a scoped tolerance absorbs its ledgered difference on its own case",
          normalize_text(c_out, case_id="A.name.typeerr", scoped=tol)
          == normalize_text(r_out, case_id="A.name.typeerr", scoped=tol))
    check("a scoped tolerance does NOT fire on another case",
          normalize_text(c_out, case_id="B.other", scoped=tol)
          != normalize_text(r_out, case_id="B.other", scoped=tol))
    check("a scoped tolerance does not fire when no case id is given",
          normalize_text(c_out, scoped=tol) != normalize_text(r_out, scoped=tol))
    try:
        scoped_rule("everywhere", r".", "", [])
        check("a tolerance with no cases is refused", False)
    except ValueError:
        check("a tolerance with no cases is refused", True)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("file", nargs="?", help="input file (stdin if omitted)")
    ap.add_argument("--sort", action="store_true", help="sort lines (order-independent compare)")
    ap.add_argument("--strip-blank", action="store_true", help="drop blank lines")
    ap.add_argument("--mask-numbers", action="store_true", help="also mask bare 2-7 digit numbers (PIDs); lossy")
    ap.add_argument("--case", help="the case id, so tolerances scoped to it apply")
    ap.add_argument("--tolerances", help="TOML/JSON file of [[tolerance]] scoped rules")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    text = open(args.file, encoding="utf-8", errors="replace").read() if args.file else sys.stdin.read()
    sys.stdout.write(normalize_text(text, sort=args.sort, strip_blank=args.strip_blank,
                                    mask_numbers=args.mask_numbers, case_id=args.case,
                                    scoped=load_tolerances(args.tolerances)))
    return 0


if __name__ == "__main__":
    sys.exit(main())
