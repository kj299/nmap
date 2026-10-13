#!/usr/bin/env python3
"""C vulnerability-class scanner — run at Phase 0, BEFORE porting, so the Rust
rewrite fixes C's latent flaws instead of faithfully re-implementing them.
("Recognize that the existing operating system running code may have other
flaws." — the prime directive.)

This is a fast, dependency-free heuristic grep over C sources for the classic
sink patterns. It is deliberately noisy: every hit is a *question* for the porter
("is this exploitable? does the Rust version close it?"), and confirmed ones go
into DIVERGENCES.md as intentional fix-of-C-defect entries. It does NOT replace a
real SAST pass (clang analyzer, CodeQL, cppcheck) — it bootstraps the flaw
inventory when you have minutes, not hours.

Categories flagged (CWE in parens):
  unbounded-copy    strcpy/strcat/sprintf/gets/scanf %s          (CWE-120/787)
  format-string     printf-family with a non-literal format      (CWE-134)
  stack-vla-alloca  alloca / variable-length arrays              (CWE-770)
  int-overflow-mul  a multiplication in the size argument of any
                    function in ALLOC_FUNCS                      (CWE-190)
  command-exec      system/popen/exec* with composed strings     (CWE-78)
  toctou            access()/stat() then open()/fopen()          (CWE-367)
  unterminated-list a sentinel-terminated array, passed to an API that
                    needs the sentinel, with no sentinel           (CWE-170/125)
  nonformatting-format  a format specifier in a literal handed to an API
                    that does not format it                       (CWE-628)
  scanf-narrow-int  a scanf-family literal format with %h/%hh integer
                    conversion: out-of-range input is UB, wraps
                    in practice (C11 7.21.6.2p10)                 (CWE-190)
  index-rewind-in-stride-loop  a `for` stepping `i += <non-constant>`
                    whose body also moves `i` back (i--, -=, =)   (CWE-823)
  negation-to-unsigned  `(size_t)(-x)`: negating a signed value
                    (INT_MIN overflows) then reinterpreting it    (CWE-190)
  narrow-field-store  a non-constant store into a struct field
                    declared `short`/`unsigned short`, with no
                    SHRT_MAX/USHRT_MAX check within 3 lines       (CWE-197)
  ctype-signed-char  is*/to* from <ctype.h> on a subscript or deref
                    of a plain `char`, with no unsigned cast       (CWE-758) [weak]

`unterminated-list`, `nonformatting-format` and `int-overflow-mul` are driven
by tables of *API contracts* (SENTINEL_LIST_ARGS, NON_FORMATTING_ARGS,
ALLOC_FUNCS), because the code's embedded libraries have contracts of their own
that libc's sinks do not cover. Extend them per target with `--config FILE.json`
or `--alloc-func NAME[:ARG]` rather than by editing this file. nmap's Lua C API
and its nbase `safe_*` allocators seed them. Before the first two tables
existed, this scanner reported 0 sites in the three NSE files where nmap's M6
port found four unterminated `luaL_checkoption` lists (LESSONS #032). Before
ALLOC_FUNCS, `int-overflow-mul` matched only `malloc|calloc|realloc` on one
line, and so saw none of LPeg's five size overflows (they allocate through
`lua_newuserdata`, via a file-local `newtree`) and none of nmap's 60-odd
`safe_*` size multiplications (LESSONS #050).

`--inventory recursion` lists, separately from the hits, every function on a
call-graph cycle in its own file whose parameters and body mention no depth
guard. It is an inventory, not a flaw rule: recursion is often fine, but a
walker over attacker-shaped trees with no depth limit is a stack overflow
(LESSONS #050: it lists all of LPeg's ledgered walkers, and 72 functions in the
rest of nmap's tree).

What this CANNOT find (know it before you trust a clean scan)
------------------------------------------------------------
Every category above is *API misuse*: a banned function, a non-literal format, a
size computed by multiplication. All of it is recognisable from a single line.

Two whole defect classes are structurally outside that model, and both are the
kind a port most wants to find:

  * **A guard that does not dominate the read it protects.** nmap's
    `read_ns_reply_pcap` bounds-checks `caplen` inside an `if`, then does the
    16-byte `memcpy` of the target address *outside* that `if` — a heap overread
    any host on the local link can trigger. Every token on the offending line is
    ordinary; only the relationship between two lines is wrong.
  * **An out-parameter written but never read.** nmap's `doND` asks
    `read_ns_reply_pcap` for `has_mac` and never tests it, so a legal reply with
    no link-layer option leaves the caller's MAC buffer uninitialised and reports
    success. That is a dataflow fact, invisible to any pattern.

Running this scanner over the file containing both (`libnetutil/netutil.cc`)
reports 2 format-string hits and neither defect. A memcpy-with-constant-size rule
was measured as a candidate and rejected: 155 hits across nmap's C tree, which is
the "noisy scanner gets ignored" failure this kit already paid for (LESSONS #2).

M6.6 (nmap's LPeg 0.12 and `nmapdb`) ledgered 22 C defects. Before the last
five rules and ALLOC_FUNCS this scanner found 1 of them; it now finds 8 with the
default tables, 10 once LPeg's file-local `newtree` is added (`--alloc-func
newtree:1`), and the recursion inventory lists 2 more (LESSONS #050). Six
classes remain outside any line rule:

  * **Interprocedural capacity.** LPeg's `doublecap` over-reads a stack buffer
    whose size is set by the caller.
  * **A lifetime across a callback.** LPeg frees the compiled program from a Lua
    callback that runs during the match that is using it.
  * **The type of an embedded runtime's value.** A `Cc(nil)` capture without a
    ktable, and a uservalue read as the wrong type: correct C, wrong Lua value.
  * **Error-path state.** A partially compiled program that is not cached when
    compilation raises, so the next call sees a half-built one.
  * **An `assert` reachable from data.** An empty vendor in `nmap-mac-prefixes`
    aborts nmap; there are 1,077 `assert(` in the tree, and the scanner cannot
    tell which inputs reach which.
  * **The semantics of the file opened.** A data file that is a FIFO or
    `/dev/zero` blocks or loops forever (classify path inputs at Phase 0).

Three candidate rules were measured and rejected as noise (LESSONS #2): a
pointer difference passed as a length (24 hits in 15 files, mostly guarded), a
Lua push in a loop with no `checkstack` (10 false positives; the real push is
in a callee), and an array sized `UCHAR_MAX` (4 false positives without pairing
it with the `> MAX` guard).

So: a clean scan means "no *API-misuse* flaw found", never "this file is safe".
The controls that actually caught both were (a) pasting the C verbatim into a
differential oracle, which forces line-by-line reading, and (b) compiling that
pasted C under AddressSanitizer and feeding it TRUNCATED inputs. Both are now
PLAYBOOK Phase 2 steps. (LESSONS #019, #020 — nmap M5.) When later work finds a
C flaw this scanner missed, measure a rule for it *then* (hits on the file, hits
on the rest of the tree) and add it or record why not; do not wait for the
retrospective (LESSONS #050).

Usage:
  scan_c_flaws.py PATH [PATH ...] [--json] [--strict]
                  [--config FILE.json] [--alloc-func NAME[:ARG] ...]
                  [--inventory recursion]
  scan_c_flaws.py --self-test

  --config FILE.json   extend the contract tables for this target:
                       {"alloc_funcs": {"newtree": 1},
                        "sentinel_list_args": {"my_checkopt": [3, ["NULL"]]},
                        "non_formatting_args": {"my_argerror": 2}}
                       (an alloc_funcs value of null means every argument is a size)
  --alloc-func NAME[:ARG]  add one allocator; ARG is the 0-based size argument
Exit: 0 always (this is an inventory, not a gate) unless --strict (then 1 if hits).
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys

CHECKS = [
    ("unbounded-copy", "CWE-120",
     re.compile(r"\b(strcpy|strcat|sprintf|vsprintf|gets)\s*\(")),
    ("unbounded-copy", "CWE-120",
     re.compile(r"\bscanf\s*\([^)]*%s")),
    ("stack-vla-alloca", "CWE-770",
     re.compile(r"\balloca\s*\(")),
    # int-overflow-mul is table-driven now (ALLOC_FUNCS, _scan_alloc_mul): the
    # regex it replaces hard-coded malloc|calloc|realloc and missed every size
    # computed for another allocator (LESSONS #050).
    ("command-exec", "CWE-78",
     re.compile(r"\b(system|popen|execl|execlp|execv|execvp)\s*\(")),
    ("toctou", "CWE-367",
     re.compile(r"\b(access|stat|lstat)\s*\(")),
]

# printf-family: name -> index of the *format-string* argument. The format is
# NOT always arg 0 — it follows the stream (fprintf), buffer (sprintf), size
# (snprintf), or priority/eval (syslog/err). Flagging arg 0 blindly produces a
# false positive on every `fprintf(stderr, "literal", ...)` — which is what
# buried the real findings when this scanner was first run against lsof
# (828 false positives). We flag only when the format-position arg is a
# *non-literal* (doesn't start with a string literal). (LESSONS #2)
FORMAT_FUNCS = {
    "printf": 0, "vprintf": 0, "warn": 0, "warnx": 0, "vwarn": 0,
    "fprintf": 1, "vfprintf": 1, "dprintf": 1, "sprintf": 1, "vsprintf": 1,
    "syslog": 1, "vsyslog": 1, "err": 1, "errx": 1, "asprintf": 1,
    "snprintf": 2, "vsnprintf": 2,
}
_FMT_CALL = re.compile(r"\b(" + "|".join(FORMAT_FUNCS) + r")\s*\(")


def _call_args(src, open_paren):
    """Return the top-level comma-separated argument strings of a call whose
    '(' is at index `open_paren`, plus the index just past the ')'. Skips string
    and char literals and nested parens. Best-effort on an unbalanced tail."""
    depth, args, cur, j, n = 0, [], [], open_paren, len(src)
    while j < n:
        c = src[j]
        if c in '"\'':
            quote = c
            cur.append(c); j += 1
            while j < n and src[j] != quote:
                if src[j] == "\\" and j + 1 < n:
                    cur.append(src[j]); cur.append(src[j + 1]); j += 2; continue
                cur.append(src[j]); j += 1
            if j < n:
                cur.append(src[j]); j += 1
            continue
        if c == "(":
            depth += 1
            if depth > 1:
                cur.append(c)
            j += 1; continue
        if c == ")":
            depth -= 1
            if depth == 0:
                args.append("".join(cur))
                return args, j + 1
            cur.append(c); j += 1; continue
        if c == "," and depth == 1:
            args.append("".join(cur)); cur = []; j += 1; continue
        cur.append(c); j += 1
    args.append("".join(cur))
    return args, n


def _scan_format_strings(src):
    hits = []
    for m in _FMT_CALL.finditer(src):
        name = m.group(1)
        args, _end = _call_args(src, m.end() - 1)
        idx = FORMAT_FUNCS[name]
        if idx >= len(args):
            continue  # too few args to tell; don't cry wolf
        fmt = args[idx].strip()
        # Literal format (starts with a string, or a wide/utf literal) is safe.
        if fmt.startswith(('"', 'L"', 'u8"', 'u"', 'U"')):
            continue
        if not fmt:
            continue
        lineno = src.count("\n", 0, m.start()) + 1
        hits.append({"line": lineno, "category": "format-string", "cwe": "CWE-134",
                     "text": (name + "(" + args[idx].strip())[:120]})
    return hits


# Embedded-API contracts (LESSONS #032). Extend these per target: a function
# whose argument must be an array ending in a sentinel, and a function whose
# message argument is printed as is.
#   name -> (0-based index of the array argument, accepted sentinels)
SENTINEL_LIST_ARGS = {
    "luaL_checkoption": (3, ("NULL", "0", "nullptr")),
}
#   name -> 0-based index of the message argument
NON_FORMATTING_ARGS = {
    "luaL_argerror": 2,
}
# Allocators whose size argument is checked for a multiplication (int-overflow-
# mul). name -> 0-based index of the size argument, or None when every argument
# is a size (calloc). The hard-coded `malloc|calloc|realloc` this replaced could
# not see an allocation made through anything else, which in nmap was LPeg's
# whole tree builder (lua_newuserdata via `newtree`) and nbase's `safe_*`
# wrappers (LESSONS #050). Add a target's own wrappers with --config or
# --alloc-func; a file-local wrapper such as LPeg's `newtree` belongs there, not
# here.
ALLOC_FUNCS = {
    "malloc": 0, "calloc": None, "realloc": 1,
    "lua_newuserdata": 1, "lua_newuserdatauv": 1,   # Lua C API
    "safe_malloc": 0, "safe_zalloc": 0, "safe_realloc": 1,   # nmap's nbase
}


def _alt(names):
    return re.compile(r"\b(" + "|".join(map(re.escape, sorted(names))) + r")\s*\(")


def _compile_tables():
    """(Re)build the call regexes from the tables; call after extending them."""
    global _SENTINEL_CALL, _NONFMT_CALL, _ALLOC_CALL
    _SENTINEL_CALL = _alt(SENTINEL_LIST_ARGS)
    _NONFMT_CALL = _alt(NON_FORMATTING_ARGS)
    _ALLOC_CALL = _alt(ALLOC_FUNCS)


def extend_tables(cfg):
    """Merge a per-target config dict into the contract tables."""
    for k, v in (cfg.get("alloc_funcs") or {}).items():
        ALLOC_FUNCS[k] = None if v is None else int(v)
    for k, v in (cfg.get("sentinel_list_args") or {}).items():
        SENTINEL_LIST_ARGS[k] = (int(v[0]), tuple(v[1]))
    for k, v in (cfg.get("non_formatting_args") or {}).items():
        NON_FORMATTING_ARGS[k] = int(v)
    _compile_tables()


_compile_tables()
_ARRAY_DEF = r"\b{name}\s*\[\s*\w*\s*\]\s*=\s*\{{([^}}]*)\}}"
_CONVERSION = re.compile(r"%[-+ #0]*\d*(?:\.\d+)?[hlLqjzt]*[diouxXeEfgGcspn]")


def _scan_contracts(src):
    hits = []
    for m in _SENTINEL_CALL.finditer(src):
        idx, sentinels = SENTINEL_LIST_ARGS[m.group(1)]
        args, _end = _call_args(src, m.end() - 1)
        if idx >= len(args):
            continue
        name = args[idx].strip()
        if not re.fullmatch(r"[A-Za-z_]\w*", name):
            continue  # an expression: cannot tell
        # The nearest definition before the call (a function-local static).
        defs = [d for d in re.finditer(_ARRAY_DEF.format(name=re.escape(name)), src)
                if d.start() < m.start()]
        if not defs:
            continue
        body = re.sub(r"/\*.*?\*/|//[^\n]*", "", defs[-1].group(1), flags=re.S)
        elems = [e.strip() for e in body.split(",") if e.strip()]
        if elems and elems[-1] not in sentinels:
            lineno = src.count("\n", 0, m.start()) + 1
            hits.append({"line": lineno, "category": "unterminated-list",
                         "cwe": "CWE-170",
                         "text": f"{m.group(1)}(..., {name}) but {name}[] ends in {elems[-1][:40]}"})
    for m in _NONFMT_CALL.finditer(src):
        idx = NON_FORMATTING_ARGS[m.group(1)]
        args, _end = _call_args(src, m.end() - 1)
        if idx >= len(args):
            continue
        msg = args[idx].strip()
        if msg.startswith('"') and _CONVERSION.search(msg.replace("%%", "")):
            lineno = src.count("\n", 0, m.start()) + 1
            hits.append({"line": lineno, "category": "nonformatting-format",
                         "cwe": "CWE-628", "text": (m.group(1) + "(... " + msg)[:120]})
    return hits


def strip_comments(src):
    """Blank out /* */ and // comments, keeping string and char literals and
    every newline, so line numbers in the result match the source."""
    out, i, n = [], 0, len(src)
    while i < n:
        c = src[i]
        if c in "\"'":
            j = i + 1
            while j < n and src[j] != c and src[j] != "\n":
                j += 2 if src[j] == "\\" else 1
            out.append(src[i:j + 1]); i = j + 1; continue
        if src.startswith("/*", i):
            j = src.find("*/", i + 2)
            j = n if j < 0 else j + 2
            out.append(re.sub(r"[^\n]", " ", src[i:j])); i = j; continue
        if src.startswith("//", i):
            j = src.find("\n", i)
            j = n if j < 0 else j
            out.append(" " * (j - i)); i = j; continue
        out.append(c); i += 1
    return "".join(out)


def _line(src, pos):
    return src.count("\n", 0, pos) + 1


def _hit(src, pos, cat, cwe, text):
    return {"line": _line(src, pos), "category": cat, "cwe": cwe, "text": text[:120]}


def _is_definition(src, end):
    """True if the call-shaped text ending at `end` is a function definition."""
    return src[end:end + 40].lstrip().startswith("{")


# int-overflow-mul ------------------------------------------------------------
_SIZEOF = re.compile(r"\bsizeof\s*(?:\((?:[^()]|\([^()]*\))*\)|\**\s*[A-Za-z_][\w.>-]*)")
# A BINARY `*`: an operand on both sides. `*len` (a dereference) is not one.
_BINARY_MUL = re.compile(r"[\w)\]]\s*\*\s*[\w(]")
_TOKEN = re.compile(r"[A-Za-z_]\w*|\d\w*")


def _constant_expr(expr):
    """True when every operand is a sizeof (already `S`), a number, or an
    ALL-CAPS macro: `sizeof(u_int) * 2` cannot overflow at run time."""
    return all(t == "S" or t[0].isdigit() or re.fullmatch(r"[A-Z_][A-Z0-9_]*", t)
               for t in _TOKEN.findall(expr))


def _scan_alloc_mul(src):
    hits = []
    for m in _ALLOC_CALL.finditer(src):
        args, end = _call_args(src, m.end() - 1)
        if _is_definition(src, end):
            continue
        idx = ALLOC_FUNCS[m.group(1)]
        sizes = args if idx is None else (args[idx:idx + 1] if idx < len(args) else [])
        for a in sizes:
            e = _SIZEOF.sub("S", a)
            if _BINARY_MUL.search(e) and not _constant_expr(e):
                hits.append(_hit(src, m.start(), "int-overflow-mul", "CWE-190",
                                 m.group(1) + "(" + " ".join(a.split())))
                break
    return hits


# scanf-narrow-int ------------------------------------------------------------
_SCANF_FMT = {"scanf": 0, "sscanf": 1, "fscanf": 1, "vscanf": 0, "vsscanf": 1, "vfscanf": 1}
_SCANF_CALL = _alt(_SCANF_FMT)
_NARROW_CONV = re.compile(r"%\*?\d*hh?[diouxX]")


def _scan_scanf_narrow(src):
    hits = []
    for m in _SCANF_CALL.finditer(src):
        args, _end = _call_args(src, m.end() - 1)
        i = _SCANF_FMT[m.group(1)]
        if i < len(args):
            f = args[i].strip()
            if f.startswith('"') and _NARROW_CONV.search(f.replace("%%", "")):
                hits.append(_hit(src, m.start(), "scanf-narrow-int", "CWE-190",
                                 m.group(1) + "(... " + f))
    return hits


# index-rewind-in-stride-loop -------------------------------------------------
_FOR = re.compile(r"\bfor\s*\(")


def _block_after(src, k):
    """The statement or braced block starting at or after index k."""
    while k < len(src) and src[k] in " \t\r\n":
        k += 1
    if k < len(src) and src[k] == "{":
        depth, j = 0, k
        while j < len(src):
            if src[j] == "{":
                depth += 1
            elif src[j] == "}":
                depth -= 1
                if depth == 0:
                    break
            j += 1
        return k, src[k:j + 1]
    end = src.find(";", k)
    return k, src[k:(len(src) if end < 0 else end + 1)]


def _scan_stride_rewind(src):
    hits = []
    for m in _FOR.finditer(src):
        args, end = _call_args(src, m.end() - 1)
        parts = ",".join(args).split(";")   # _call_args splits on commas
        if len(parts) != 3:
            continue
        um = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*\+=\s*(.+?)\s*", parts[2])
        if not um:
            continue
        var, step = um.group(1), um.group(2)
        if re.fullmatch(r"\d+|[A-Z_][A-Z0-9_]*|sizeof\s*\(.*\)", step):
            continue  # a constant stride cannot skip past the end
        k, body = _block_after(src, end)
        v = re.escape(var)
        rx = re.compile(r"\b" + v + r"\s*--|--\s*" + v + r"\b|\b" + v + r"\s*-=|\b" + v + r"\s*=(?!=)")
        for bm in rx.finditer(body):
            hits.append(_hit(src, k + bm.start(), "index-rewind-in-stride-loop", "CWE-823",
                             f"for (...; {var} += {step}) body: {bm.group(0).strip()}"))
    return hits


# negation-to-unsigned --------------------------------------------------------
_NEG_UNSIGNED = re.compile(r"\(\s*(?:size_t|unsigned(?:\s+(?:int|long|char|short))*|u_?int\d+_t|lua_Unsigned)\s*\)"
                           r"\s*\(\s*-\s*[A-Za-z_]\w*\s*\)")


def _scan_negation_unsigned(src):
    return [_hit(src, m.start(), "negation-to-unsigned", "CWE-190", m.group(0))
            for m in _NEG_UNSIGNED.finditer(src)]


# narrow-field-store ----------------------------------------------------------
_STRUCT_BODY = re.compile(r"\b(?:struct|union)\s*\w*\s*\{([^{}]*(?:\{[^{}]*\}[^{}]*)*)\}", re.S)
_SHORT_FIELD = re.compile(r"\b(?:(?:unsigned|signed)\s+)?short(?:\s+int)?\s+(\w+)\s*(?:\[[^\]]*\])?\s*;")
_SHORT_GUARD = re.compile(r"\bU?SHRT_MAX\b|\bU?INT16_MAX\b")
_MASKED = re.compile(r"&\s*0x[fF]{2,4}\b")


def _scan_narrow_store(src):
    names = set()
    for b in _STRUCT_BODY.finditer(src):
        names.update(_SHORT_FIELD.findall(b.group(1)))
    if not names:
        return []
    lines = src.splitlines()
    rx = re.compile(r"(?:\.|->)(" + "|".join(map(re.escape, sorted(names))) + r")\s*[-+]?=(?!=)\s*([^;]*);")
    hits = []
    for m in rx.finditer(src):
        rhs = m.group(2).strip()
        if re.fullmatch(r"-?\d+|0x[0-9a-fA-F]+|'.'|[A-Z_][A-Z0-9_]*", rhs) or _MASKED.search(rhs):
            continue  # a literal, a constant macro, or a value masked to fit
        ln = _line(src, m.start())
        near = "\n".join(lines[max(0, ln - 4):ln + 3])
        if _SHORT_GUARD.search(near):
            continue  # a range check within 3 lines either side
        hits.append(_hit(src, m.start(), "narrow-field-store", "CWE-197", " ".join(m.group(0).split())))
    return hits


# ctype-signed-char [weak] ----------------------------------------------------
_CTYPE = re.compile(r"\b(is(?:alnum|alpha|blank|cntrl|digit|graph|lower|print|punct|space|upper|xdigit)"
                    r"|to(?:lower|upper))\s*\(")
_UNSIGNED_CAST = re.compile(r"\(\s*(?:const\s+)?(?:unsigned\s+char|u_char|u8|uint8_t|u_int8_t|byte|unsigned)\s*\)")
_SUBSCRIPT_OR_DEREF = re.compile(
    r"\*?\s*\(?\s*([A-Za-z_]\w*)(?:\s*\[[^\]]*\]|\s*\+\+|\s*\+\s*\w+\)?)*\s*\)?")


def _plain_char_decl(src, name):
    n = re.escape(name)
    if re.search(r"\b(?:unsigned\s+char|u_char|u8|uint8_t|u_int8_t|byte)\s*(?:const\s*)?\**\s*(?:const\s*)?\b"
                 + n + r"\b", src):
        return False
    return bool(re.search(r"(?<!unsigned )(?<!signed )\bchar\s*(?:const\s*)?\**\s*(?:const\s*)?\b"
                          + n + r"\s*(?:\[|[,;=)])", src))


def _scan_ctype_signed(src):
    hits = []
    for m in _CTYPE.finditer(src):
        args, _end = _call_args(src, m.end() - 1)
        if len(args) != 1:
            continue
        a = args[0].strip()
        if _UNSIGNED_CAST.search(a) or not (a.startswith("*") or "[" in a):
            continue
        mm = _SUBSCRIPT_OR_DEREF.fullmatch(a)
        if mm and _plain_char_decl(src, mm.group(1)):
            hits.append(_hit(src, m.start(), "ctype-signed-char", "CWE-758", f"{m.group(1)}({a})"))
    return hits


# --inventory recursion -------------------------------------------------------
_FUNC_DEF = re.compile(r"^[A-Za-z_][\w \t*]*?\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)\s*\{", re.M)
_DEPTH_GUARD = re.compile(r"depth|level|limit|nest|ccall|recurs|MAX|LIMIT|checkstack|incCstack|luaE_|count",
                          re.I)
_NOT_FUNCS = {"if", "while", "for", "switch", "return", "sizeof"}


def _function_bodies(src):
    for m in _FUNC_DEF.finditer(src):
        if m.group(1) in _NOT_FUNCS:
            continue
        _k, body = _block_after(src, m.end() - 1)
        yield m.group(1), m.group(2), m.start(), body


def _sccs(graph):
    """Tarjan's strongly connected components, iteratively (deep call graphs
    must not overflow *this* stack)."""
    index, low, on, stack, out, counter = {}, {}, set(), [], [], [0]
    for root in graph:
        if root in index:
            continue
        work = [(root, iter(sorted(graph[root])))]
        index[root] = low[root] = counter[0]; counter[0] += 1
        stack.append(root); on.add(root)
        while work:
            v, it = work[-1]
            w = next(it, None)
            if w is not None:
                if w not in index:
                    index[w] = low[w] = counter[0]; counter[0] += 1
                    stack.append(w); on.add(w)
                    work.append((w, iter(sorted(graph[w]))))
                elif w in on:
                    low[v] = min(low[v], index[w])
                continue
            work.pop()
            if work:
                low[work[-1][0]] = min(low[work[-1][0]], low[v])
            if low[v] == index[v]:
                comp = []
                while True:
                    w = stack.pop(); on.discard(w); comp.append(w)
                    if w == v:
                        break
                out.append(comp)
    return out


def recursion_inventory(src):
    """Functions on a call-graph cycle within this file whose parameters and
    body mention no depth guard. An inventory, not a flaw list."""
    funcs = {}
    for name, params, pos, body in _function_bodies(src):
        funcs.setdefault(name, (params, pos, body))
    graph = {n: {c for c in re.findall(r"\b([A-Za-z_]\w*)\s*\(", b[2]) if c in funcs}
             for n, b in funcs.items()}
    found = []
    for comp in _sccs(graph):
        if len(comp) > 1 or comp[0] in graph[comp[0]]:
            for n in comp:
                params, pos, body = funcs[n]
                if not (_DEPTH_GUARD.search(params) or _DEPTH_GUARD.search(body)):
                    found.append({"line": _line(src, pos), "function": n, "cycle_size": len(comp)})
    return sorted(found, key=lambda f: f["line"])


_RULES = (_scan_alloc_mul, _scan_scanf_narrow, _scan_stride_rewind,
          _scan_negation_unsigned, _scan_narrow_store, _scan_ctype_signed)


def scan_text(src):
    hits = []
    for lineno, line in enumerate(src.splitlines(), 1):
        # skip obvious comment-only lines to cut noise
        stripped = line.strip()
        if stripped.startswith(("*", "//", "/*")):
            continue
        for cat, cwe, rx in CHECKS:
            if rx.search(line):
                hits.append({"line": lineno, "category": cat, "cwe": cwe, "text": stripped[:120]})
    hits.extend(_scan_format_strings(src))
    hits.extend(_scan_contracts(src))
    # The rules added since LESSONS #050 parse calls across lines, so they read
    # the source with its comments blanked rather than skipping comment lines.
    code = strip_comments(src)
    for rule in _RULES:
        hits.extend(rule(code))
    hits.sort(key=lambda h: h["line"])
    return hits


# C *and* C++ sources: the classic sink classes (strcpy/sprintf/memcpy/malloc/
# system/…) apply to C++ too, and many real targets (e.g. nmap's core engine) are
# C++. Scanning only .c/.h silently skips a whole codebase and reports a false
# "0 flaws" — a scanner that reads nothing is worse than none (LESSONS #2/#3).
C_SOURCE_EXTS = (".c", ".h", ".cc", ".cpp", ".cxx", ".c++",
                 ".hpp", ".hh", ".hxx", ".h++")


def iter_c_files(paths):
    for p in paths:
        if os.path.isfile(p) and p.endswith(C_SOURCE_EXTS):
            yield p
        elif os.path.isdir(p):
            for root, _d, files in os.walk(p):
                for f in files:
                    if f.endswith(C_SOURCE_EXTS):
                        yield os.path.join(root, f)


def run(paths, as_json, strict, inventory=()):
    all_hits, by_cat, recursion = [], {}, []
    for path in sorted(set(iter_c_files(paths))):
        try:
            src = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        for h in scan_text(src):
            h["file"] = path
            all_hits.append(h)
            by_cat[h["category"]] = by_cat.get(h["category"], 0) + 1
        if "recursion" in inventory:
            for f in recursion_inventory(strip_comments(src)):
                f["file"] = path
                recursion.append(f)

    if as_json:
        out = {"total": len(all_hits), "by_category": by_cat, "hits": all_hits}
        if "recursion" in inventory:
            out["inventory"] = {"recursion": recursion}
        print(json.dumps(out, indent=2))
    else:
        for h in all_hits:
            print(f"{h['file']}:{h['line']}  [{h['category']}/{h['cwe']}]  {h['text']}")
        print(f"\n{len(all_hits)} potential flaw site(s); by category:")
        for cat, n in sorted(by_cat.items(), key=lambda kv: -kv[1]):
            print(f"    {n:4}  {cat}")
        if "recursion" in inventory:
            print("\nInventory (not flaws): functions on an unguarded call-graph cycle")
            for f in recursion:
                print(f"{f['file']}:{f['line']}  {f['function']} (cycle of {f['cycle_size']})")
            print(f"    {len(recursion):4}  in {len({f['file'] for f in recursion})} file(s); "
                  "each needs a depth limit or an argument that input cannot shape its depth")
        print("\nTriage each: does the Rust port close it? Record confirmed fixes in DIVERGENCES.md.")
    return 1 if (strict and all_hits) else 0


SELF_TEST_C = r'''
#include <stdio.h>
void bad(char *u, char *dynfmt) {
    char buf[16];
    strcpy(buf, u);                     /* unbounded-copy */
    printf(u);                          /* format-string: arg 0 non-literal */
    fprintf(stderr, "literal %s\n", u); /* SAFE: format arg is a literal */
    fprintf(stderr, dynfmt, u);         /* format-string: arg 1 non-literal */
    snprintf(buf, sizeof buf, "%d", 1); /* SAFE: format arg (idx 2) literal */
    char *p = malloc(n * width);        /* int-overflow-mul */
    system(cmd);                        /* command-exec */
    if (access(path, R_OK)) {}          /* toctou */
    /* strcpy(x, y);  in a comment - should be ignored */
}
static int opts_bad (lua_State *L) {
  static const char *op[] = {"wait", "signal", "broadcast"};
  return luaL_checkoption(L, 1, NULL, op);          /* unterminated-list */
}
static int opts_ok (lua_State *L) {
  static const char *const ok[] = {"tcp", "udp", NULL};
  luaL_argerror(L, 1, "invalid option");            /* SAFE: no specifier */
  luaL_argerror(L, 1, "100%% sure");                /* SAFE: escaped percent */
  return luaL_checkoption(L, 2, "tcp", ok);         /* SAFE: terminated */
}
static int bad_msg (lua_State *L) {
  return luaL_argerror(L, 1, "device %s not found"); /* nonformatting-format */
}
'''

# Each rule added in LESSONS #050, with the shape it was measured on (LPeg 0.12,
# nmapdb, protocols.cc/services.cc) and the near miss it must NOT flag.
SELF_TEST_M66 = r'''
typedef struct TTree { unsigned char tag; unsigned short key; int ps; } TTree;
typedef struct Capture { const char *s; short idx; unsigned char kind; } Capture;
static void *newtree (lua_State *L, int len) {
  return lua_newuserdatauv(L, (len - 1) * sizeof(TTree), 1);  /* int-overflow-mul (Lua API) */
}
static void sizes (lua_State *L, int n, size_t *len) {
  char *a = safe_malloc(n * sizeof(int));          /* int-overflow-mul (nbase) */
  char *b = malloc(sizeof(TTree) * n);             /* int-overflow-mul: sizeof first */
  char *c = malloc(*len);                          /* SAFE: a dereference, not a product */
  char *d = malloc(sizeof(int) * 2 + MAXLEN);      /* SAFE: a constant product */
  TTree *t = newtree(L, 2 * n - 1);                /* only with --alloc-func newtree:1 */
}
static void ports (const char *line, char *name, unsigned short *port, int *x) {
  sscanf(line, "%127s %hu", name, port);           /* scanf-narrow-int */
  sscanf(line, "%d 100%%hd", x);                    /* SAFE: %% escapes the h */
}
static void jumps (Instruction *code, int n) {
  int i;
  for (i = 0; i < n; i += sizei(&code[i])) {
    if (code[i].i.code == IJmp) { code[i].i.code = INop; i--; }  /* index-rewind-in-stride-loop */
  }
  for (i = 0; i < n; i += 2) { if (code[i].i.code) i--; }       /* SAFE: constant stride */
}
static void init (lua_Integer ii, size_t len) {
  size_t a = (size_t)(-ii);                         /* negation-to-unsigned */
  size_t b = (size_t)(ii);                          /* SAFE: no negation */
}
static void keys (TTree *t, int idx, unsigned raw) {
  t->key = addtoktable(L, idx);                     /* narrow-field-store */
  t->key = 0;                                       /* SAFE: a constant */
  t->key = (raw >> 4) & 0xffff;                     /* SAFE: masked to fit */
}
static void capidx (Capture *cap, int n) {
  /* the guard must be no more than 3 lines away; keep the masked store above
     out of its reach so each exemption is tested on its own */
  luaL_argcheck(L, 0 <= n && n <= SHRT_MAX, 1, "invalid number");
  cap->idx = n;                                     /* SAFE: range-checked just above */
}
static int mac (lua_State *L, const char *buf, const unsigned char *ubuf) {
  int i = 0;
  if (!isxdigit(buf[i])) return 0;                  /* ctype-signed-char */
  if (!isxdigit((unsigned char)buf[i])) return 0;   /* SAFE: cast */
  return isdigit(ubuf[0]);                          /* SAFE: unsigned char */
}
static int walk (TTree *tree) {                      /* recursion inventory: walk<->walk2 */
  if (tree->tag) return walk2(tree);
  return 0;
}
static int walk2 (TTree *tree) { return walk(tree + 1); }
static int guarded (TTree *tree, int depth) {        /* SAFE: depth guard */
  if (depth > 200) return 0;
  return guarded(tree + 1, depth + 1);
}
'''


def _self_test():
    hits = scan_text(SELF_TEST_C)
    cats = {h["category"] for h in hits}
    fmt_hits = [h for h in hits if h["category"] == "format-string"]
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("flags unbounded-copy", "unbounded-copy" in cats)
    check("flags format-string", "format-string" in cats)
    check("flags int-overflow-mul", "int-overflow-mul" in cats)
    check("flags command-exec", "command-exec" in cats)
    check("flags toctou", "toctou" in cats)
    check("flags exactly the unterminated option list",
          [h["text"].split("(")[0] for h in hits if h["category"] == "unterminated-list"]
          == ["luaL_checkoption"]
          and "op[]" in next(h["text"] for h in hits if h["category"] == "unterminated-list"))
    check("flags exactly the format specifier handed to luaL_argerror",
          len([h for h in hits if h["category"] == "nonformatting-format"]) == 1)
    check("ignores the commented strcpy (no double count)",
          sum(1 for h in hits if h["category"] == "unbounded-copy") == 1)
    # The Pass-1 fix: only NON-LITERAL format args flag; the stream/buffer/size
    # arg is not mistaken for the format. Exactly 2 real hits (printf(u), the
    # variable-format fprintf); the two literal-format calls must NOT flag.
    check("format-string flags exactly the 2 non-literal calls", len(fmt_hits) == 2)
    check("literal-format fprintf/snprintf NOT flagged",
          not any("literal" in h["text"] or '"%d"' in h["text"] for h in fmt_hits))

    # LESSONS #050: the rules M6.6's 22 ledgered C defects were measured on.
    # Each rule must fire on its target line and stay quiet on the near miss.
    src = SELF_TEST_M66
    m66 = scan_text(src)

    def lines_of(cat):
        return sorted({h["line"] for h in m66 if h["category"] == cat})

    def line_with(marker):
        return next(i for i, l in enumerate(src.splitlines(), 1) if marker in l)

    check("int-overflow-mul reads ALLOC_FUNCS: lua_newuserdatauv, safe_malloc, "
          "and a sizeof-first malloc; not a dereference or a constant product",
          lines_of("int-overflow-mul") == sorted([
              line_with("int-overflow-mul (Lua API)"), line_with("int-overflow-mul (nbase)"),
              line_with("sizeof first")]))
    check("a file-local allocator is not in the default table",
          line_with("--alloc-func newtree") not in lines_of("int-overflow-mul"))
    saved = dict(ALLOC_FUNCS)
    try:
        extend_tables({"alloc_funcs": {"newtree": 1}})
        check("--config/--alloc-func adds a target's allocator",
              line_with("--alloc-func newtree") in
              [h["line"] for h in scan_text(src) if h["category"] == "int-overflow-mul"])
    finally:
        ALLOC_FUNCS.clear(); ALLOC_FUNCS.update(saved); _compile_tables()
    check("scanf-narrow-int flags %hu and not an escaped %%h",
          lines_of("scanf-narrow-int") == [line_with('"%127s %hu"')])
    check("index-rewind-in-stride-loop flags i-- under a variable stride only",
          lines_of("index-rewind-in-stride-loop") == [line_with("index-rewind-in-stride-loop")])
    check("negation-to-unsigned flags (size_t)(-ii) only",
          lines_of("negation-to-unsigned") == [line_with("negation-to-unsigned")])
    check("narrow-field-store skips constants, masks and range-checked stores",
          lines_of("narrow-field-store") == [line_with("narrow-field-store")])
    check("ctype-signed-char flags a plain char subscript, not a cast or unsigned char",
          lines_of("ctype-signed-char") == [line_with("ctype-signed-char")])
    inv = {f["function"] for f in recursion_inventory(strip_comments(src))}
    check("recursion inventory lists the unguarded cycle and not the guarded one",
          inv == {"walk", "walk2"})
    check("comments are blanked without moving lines",
          strip_comments('a; /* x\n y */ b; // "q"\n"/*s*/";').splitlines()
          == ["a;     ", "      b;       ", '"/*s*/";'])

    # LESSONS #6: the file walk must cover C++ (.cc/.cpp/.hpp/…), not just
    # .c/.h — scanning only C silently skips a C++ codebase and reports a false
    # "0 flaws". Prove iter_c_files yields C++ sources and ignores non-source.
    import tempfile
    with tempfile.TemporaryDirectory() as d:
        for fn in ("engine.cc", "header.hpp", "mod.cpp", "legacy.c",
                   "notes.txt", "build.py"):
            open(os.path.join(d, fn), "w").write("int main(){}\n")
        found = {os.path.basename(p) for p in iter_c_files([d])}
        check("C++ sources (.cc/.hpp/.cpp) are scanned, not just .c/.h",
              {"engine.cc", "header.hpp", "mod.cpp", "legacy.c"} <= found)
        check("non-source files are not scanned",
              "notes.txt" not in found and "build.py" not in found)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("paths", nargs="*")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--strict", action="store_true", help="exit 1 if any hit (for a gate)")
    ap.add_argument("--config", help="JSON extending alloc_funcs / sentinel_list_args / "
                    "non_formatting_args for this target")
    ap.add_argument("--alloc-func", action="append", default=[], metavar="NAME[:ARG]",
                    help="add an allocator whose ARG-th (0-based) argument is a size")
    ap.add_argument("--inventory", action="append", default=[], choices=["recursion"],
                    help="also list functions on an unguarded call-graph cycle")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.paths:
        ap.print_usage(sys.stderr)
        print("error: give at least one PATH, or --self-test", file=sys.stderr)
        return 2
    if args.config:
        with open(args.config, encoding="utf-8") as f:
            extend_tables(json.load(f))
    for spec in args.alloc_func:
        name, _, arg = spec.partition(":")
        extend_tables({"alloc_funcs": {name: int(arg) if arg else 0}})
    return run(args.paths, args.json, args.strict, args.inventory)


if __name__ == "__main__":
    sys.exit(main())
