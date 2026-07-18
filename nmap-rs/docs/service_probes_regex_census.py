#!/usr/bin/env python3
"""Census the regex features used across nmap-service-probes match/softmatch lines.

The Milestone-3 (`-sV`) port decision hinges on one empirical number: what fraction
of nmap's real match corpus needs a *backtracking* regex engine (lookaround,
backreferences, atomic/possessive) versus fits a linear-time finite-automaton engine
like Rust's `regex` crate. This script measures it directly so the "which regex
engine" choice is a data input, not an opinion. See docs/M3-ANALYSIS.md.

Usage:  service_probes_regex_census.py [PATH_TO_nmap-service-probes]
        (defaults to ./nmap-service-probes)
"""
import re
import sys

# Line format:  match <svc> m/<regex>/<flags> <version template...>
#           or:  softmatch <svc> m/<regex>/<flags>
# The delimiter after `m` may be any punctuation char (/, %, =, @, |, ...).
DELIM = re.compile(r"^(match|softmatch)\s+\S+\s+m([%=@/|#~,;!])(.*)")
BACKREF = re.compile(r"\\[1-9]")
POSSESSIVE = re.compile(r"[*+?}]\+")

# feature label -> (predicate over the pattern string, needs_backtracking?)
BACKTRACKING_ONLY = [
    ("negative lookahead  (?!",  lambda p: "(?!" in p),
    ("atomic group       (?>",   lambda p: "(?>" in p),
    ("possessive         a++",   lambda p: bool(POSSESSIVE.search(p))),
    ("backreference      \\1-9",  lambda p: bool(BACKREF.search(p))),
    ("positive lookahead (?=",   lambda p: "(?=" in p),
    ("named backref     \\k<n>", lambda p: "\\k<" in p or "\\g" in p),
    ("lookbehind        (?<=",   lambda p: "(?<=" in p or "(?<!" in p),
]
# supported by `regex` regardless — reported for completeness
SUPPORTED = [
    ("inline flags       (?i)", lambda p: bool(re.search(r"\(\?[a-zA-Z]+[):]", p))),
    ("unicode class      \\p{}", lambda p: "\\p{" in p or "\\P{" in p),
]


def census(path):
    total = hard = soft = 0
    counts = {label: 0 for label, _ in BACKTRACKING_ONLY + SUPPORTED}
    needs_bt = 0
    with open(path, encoding="utf-8", errors="replace") as f:
        for raw in f:
            m = DELIM.match(raw.rstrip("\n"))
            if not m:
                continue
            total += 1
            hard += m.group(1) == "match"
            soft += m.group(1) == "softmatch"
            delim, rest = m.group(2), m.group(3)
            end = rest.find(delim)
            pat = rest if end < 0 else rest[:end]
            hit = False
            for label, pred in BACKTRACKING_ONLY:
                if pred(pat):
                    counts[label] += 1
                    hit = True
            for label, pred in SUPPORTED:
                if pred(pat):
                    counts[label] += 1
            needs_bt += hit
    return total, hard, soft, counts, needs_bt


def main(argv):
    path = argv[1] if len(argv) > 1 else "nmap-service-probes"
    try:
        total, hard, soft, counts, needs_bt = census(path)
    except OSError as e:
        sys.exit(f"error: {e}")
    if total == 0:
        sys.exit(f"error: no match/softmatch lines found in {path!r} "
                 "(wrong file?)")
    print(f"match/softmatch patterns: {total}  (hard={hard}, soft={soft})")
    print("\nbacktracking-only features (force a non-linear engine):")
    for label, _ in BACKTRACKING_ONLY:
        print(f"   {counts[label]:5}  {label}")
    print("supported by `regex` regardless:")
    for label, _ in SUPPORTED:
        print(f"   {counts[label]:5}  {label}")
    print(f"\npatterns needing backtracking (distinct): {needs_bt} / {total} "
          f"= {100.0 * needs_bt / total:.2f}%")
    print(f"fit a linear-time engine: {total - needs_bt} / {total} "
          f"= {100.0 * (total - needs_bt) / total:.2f}%")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
