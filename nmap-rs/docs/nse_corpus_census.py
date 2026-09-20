#!/usr/bin/env python3
"""Census of what the shipped NSE Lua corpus actually asks of a Lua runtime.

M6-ANALYSIS.md measured the corpus by counting *missing functions*
(`string.find`, `string.format`, `string.pack`, ...). That framing missed a
whole class of requirement: the *dispatch mechanisms* those calls travel
through. `s:sub(1, 2)` is not a call to `string.sub` that a runtime can satisfy
by defining `string.sub`; it is an `__index` lookup on a *string value*, which
needs a string metatable the runtime must support at the VM level. A runtime can
implement every function in the gap table and still fail on 61% of the corpus.

So this tool counts both, and it counts them over *code* rather than over bytes:
Lua comments and string literals are stripped first, because the corpus is full
of Lua patterns (`"%s:%d"`), documentation blocks and protocol constants that
otherwise inflate every count. A naive grep for `//` over `nselib/` reports
~2,300 integer-division sites; almost all of them are URLs inside strings and
comments.

Usage:
    nse_corpus_census.py [ROOT ...]        # defaults to ./scripts ./nselib
    nse_corpus_census.py --json
    nse_corpus_census.py --self-test
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

# String methods: called as `s:NAME(...)` they route through the string
# metatable's `__index`, not through the `string` table directly.
STRING_METHODS = (
    "byte char find format gmatch gsub len lower match rep reverse sub upper "
    "pack unpack packsize"
).split()


def strip_lua(src: str) -> str:
    """Return `src` with comments and string literals blanked to spaces, keeping
    every byte offset and newline so line numbers survive.

    Handles: `--` line comments, `--[[ ]]` / `--[==[ ]==]` long comments,
    `[[ ]]` / `[==[ ]==]` long strings, and '...' / "..." with backslash
    escapes. Long-bracket levels must match to close, per the Lua manual."""
    out = []
    i, n = 0, len(src)

    def blank(upto: int) -> None:
        for k in range(i, upto):
            out.append("\n" if src[k] == "\n" else " ")

    while i < n:
        c = src[i]

        # long bracket, possibly preceded by `--` (long comment)
        is_comment = src.startswith("--", i)
        j = i + 2 if is_comment else i
        m = re.match(r"\[(=*)\[", src[j:]) if j < n else None
        if m and (is_comment or c == "["):
            level = m.group(1)
            close = "]" + level + "]"
            end = src.find(close, j + m.end())
            end = n if end < 0 else end + len(close)
            blank(end)
            i = end
            continue

        # `--` line comment
        if is_comment:
            end = src.find("\n", i)
            end = n if end < 0 else end
            blank(end)
            i = end
            continue

        # quoted string
        if c in "\"'":
            k = i + 1
            while k < n:
                if src[k] == "\\":
                    k += 2
                    continue
                if src[k] == c:
                    k += 1
                    break
                if src[k] == "\n":  # unterminated; Lua would error, don't hang
                    break
                k += 1
            blank(min(k, n))
            i = min(k, n)
            continue

        out.append(c)
        i += 1

    return "".join(out)


def census(paths: list[str]) -> dict:
    method_re = {m: re.compile(r":%s\s*\(" % m) for m in STRING_METHODS}
    # After strip_lua, a string literal is a run of spaces, so `("abc"):rep(n)`
    # reads `(     ):rep(n)` while `(x):rep(n)` keeps its `x`. An all-blank
    # parenthesized expression is not otherwise valid Lua, which makes this an
    # exact test for "method call whose receiver is a string literal" — the case
    # where no metatable-free runtime can possibly be right.
    literal_re = re.compile(r"\(\s+\)\s*:\s*\w+\s*\(")
    direct_re = {m: re.compile(r"\bstring\.%s\s*\(" % m) for m in STRING_METHODS}
    feature_re = {
        "goto": re.compile(r"\bgoto\s+\w"),
        "label": re.compile(r"::\s*\w+\s*::"),
        "idiv": re.compile(r"//"),
        "shl": re.compile(r"<<"),
        "shr": re.compile(r">>"),
        "band": re.compile(r"(?<![&])&(?![&])"),
        "bor": re.compile(r"(?<![|])\|(?![|])"),
        "varargs": re.compile(r"\.\.\."),
        "_ENV": re.compile(r"\b_ENV\b"),
        "_G": re.compile(r"\b_G\b"),
        "coroutine": re.compile(r"\bcoroutine\.\w+"),
        "os.*": re.compile(r"\bos\.\w+"),
        "io.*": re.compile(r"\bio\.\w+"),
        "debug.*": re.compile(r"\bdebug\.\w+"),
        "require": re.compile(r"\brequire\s*[\(\"']"),
        "select": re.compile(r"\bselect\s*\("),
        "load": re.compile(r"\bload\s*\("),
        "setmetatable": re.compile(r"\bsetmetatable\s*\("),
    }

    files = []
    for root in paths:
        for dirpath, _dirnames, filenames in os.walk(root):
            for fn in sorted(filenames):
                if fn.endswith((".lua", ".nse")):
                    files.append(os.path.join(dirpath, fn))
    files.sort()

    methods = {m: [0, set()] for m in STRING_METHODS}
    direct = {m: [0, set()] for m in STRING_METHODS}
    features = {k: [0, set()] for k in feature_re}
    literal_sites, literal_files = 0, set()
    any_method_files = set()

    for path in files:
        try:
            with open(path, "r", encoding="utf-8", errors="replace") as fh:
                code = strip_lua(fh.read())
        except OSError:
            continue
        for m, rx in method_re.items():
            hits = len(rx.findall(code))
            if hits:
                methods[m][0] += hits
                methods[m][1].add(path)
                any_method_files.add(path)
        for m, rx in direct_re.items():
            hits = len(rx.findall(code))
            if hits:
                direct[m][0] += hits
                direct[m][1].add(path)
        for k, rx in feature_re.items():
            hits = len(rx.findall(code))
            if hits:
                features[k][0] += hits
                features[k][1].add(path)
        lit = len(literal_re.findall(code))
        if lit:
            literal_sites += lit
            literal_files.add(path)

    return {
        "files": len(files),
        "string_methods": {m: {"sites": v[0], "files": len(v[1])} for m, v in methods.items()},
        "string_direct": {m: {"sites": v[0], "files": len(v[1])} for m, v in direct.items()},
        "features": {k: {"sites": v[0], "files": len(v[1])} for k, v in features.items()},
        "literal_method_calls": {"sites": literal_sites, "files": len(literal_files)},
        "files_using_string_methods": len(any_method_files),
    }


def _self_test() -> int:
    cases = [
        ("a = 1 -- b:sub(1)\n", 0, "line comment"),
        ('a = "x:sub(1)"\n', 0, "quoted string"),
        ("a = [[ y:sub(1) ]]\n", 0, "long string"),
        ("--[==[ z:sub(1) ]==]\n", 0, "long comment, level 2"),
        ("s:sub(1, 2)\n", 1, "bare call"),
        ('s:sub(1, "]]")\n', 1, "string arg does not end a long bracket"),
        ("a = '\\'' ; s:sub(1)\n", 1, "escaped quote"),
        ("--[[ a ]] s:sub(1)\n", 1, "code after long comment"),
    ]
    rx = re.compile(r":sub\s*\(")
    bad = 0
    for src, want, name in cases:
        got = len(rx.findall(strip_lua(src)))
        if got != want:
            print("FAIL %-40s want %d got %d" % (name, want, got))
            bad += 1

    # The string-literal receiver test relies on stripping having blanked the
    # literal; it is exactly the measurement the M6.0 decision turns on, so it
    # gets its own cases rather than riding on the method count.
    lit_rx = re.compile(r"\(\s+\)\s*:\s*\w+\s*\(")
    lit_cases = [
        ('(" "):rep(4)\n', 1, "literal receiver"),
        ("('%d'):format(1)\n", 1, "literal receiver, single quotes"),
        ("(x):rep(4)\n", 0, "variable receiver is not a literal"),
        ("(f()):rep(4)\n", 0, "call receiver is not a literal"),
        ('-- (" "):rep(4)\n', 0, "commented out"),
        ('s = " " .. (""):rep(4)\n', 1, "empty literal receiver"),
    ]
    for src, want, name in lit_cases:
        got = len(lit_rx.findall(strip_lua(src)))
        if got != want:
            print("FAIL %-40s want %d got %d" % (name, want, got))
            bad += 1
    cases = cases + lit_cases
    # offsets must be preserved exactly
    for src, _w, name in cases:
        if len(strip_lua(src)) != len(src):
            print("FAIL %-40s length not preserved" % name)
            bad += 1
    print("self-test: %d case(s), %d failure(s)" % (len(cases) * 2, bad))
    return 1 if bad else 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("roots", nargs="*", default=["scripts", "nselib"])
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return _self_test()

    roots = [r for r in (args.roots or ["scripts", "nselib"]) if os.path.isdir(r)]
    if not roots:
        print("no corpus directories found; run from the nmap repo root", file=sys.stderr)
        return 2

    data = census(roots)
    if args.json:
        print(json.dumps(data, indent=2))
        return 0

    n = data["files"]
    print("corpus: %d Lua files under %s\n" % (n, ", ".join(roots)))
    print("string access, method form `s:NAME(...)` vs direct `string.NAME(...)`")
    print("  %-10s %8s %6s   %8s %6s" % ("name", "m:sites", "files", "d:sites", "files"))
    for m in STRING_METHODS:
        a, b = data["string_methods"][m], data["string_direct"][m]
        if a["sites"] or b["sites"]:
            print("  %-10s %8d %6d   %8d %6d" % (m, a["sites"], a["files"], b["sites"], b["files"]))
    ms = sum(v["sites"] for v in data["string_methods"].values())
    ds = sum(v["sites"] for v in data["string_direct"].values())
    print("  %-10s %8d %6d   %8d %6d" % ("TOTAL", ms, data["files_using_string_methods"], ds, 0))
    print("\n  files using the method form: %d of %d (%.1f%%)"
          % (data["files_using_string_methods"], n, 100.0 * data["files_using_string_methods"] / n))
    lit = data["literal_method_calls"]
    print("  of which, calls on a string *literal* (receiver is unambiguous): %d sites in %d files"
          % (lit["sites"], lit["files"]))
    print("\nlanguage and library features")
    print("  %-14s %8s %6s" % ("feature", "sites", "files"))
    for k in sorted(data["features"], key=lambda k: -data["features"][k]["sites"]):
        v = data["features"][k]
        print("  %-14s %8d %6d" % (k, v["sites"], v["files"]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
