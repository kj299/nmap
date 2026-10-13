---
name: porting-kit-cflaw-scan
description: Hunt vulnerability classes in C source before porting, and triage each into the divergence ledger. Use during Phase 0, before translating a module, or whenever the user wants to find memory-safety / injection / TOCTOU risks in C code that a Rust port should fix rather than faithfully reproduce.
---

# Porting Kit — C vulnerability hunt + triage

Wraps `porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py`. Grounds the prime
directive "the C may be buggy — don't re-port a CVE" (RETROSPECTIVE §9).

## Procedure
1. **Scan** the C tree (confirm it read the target's languages — LESSONS #006):
   `python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py <c-src-dirs> --inventory recursion`
   Categories: unbounded-copy (CWE-120), format-string (CWE-134),
   int-overflow-mul (CWE-190), command-exec (CWE-78), toctou (CWE-367),
   stack-vla-alloca (CWE-770), unterminated-list (CWE-170),
   nonformatting-format (CWE-628), scanf-narrow-int (CWE-190),
   index-rewind-in-stride-loop (CWE-823), negation-to-unsigned (CWE-190),
   narrow-field-store (CWE-197), ctype-signed-char (CWE-758, weak). The
   recursion inventory lists functions on an unguarded call-graph cycle.
   **Extend the API-contract tables first** if the C embeds an interpreter or
   framework, with `--config FILE.json` or `--alloc-func NAME[:ARG]`:
   `SENTINEL_LIST_ARGS` (an array that must end in a sentinel),
   `NON_FORMATTING_ARGS` (a message printed as is) and `ALLOC_FUNCS` (allocators
   and wrappers whose size argument is checked for a product). nmap's Lua C API
   and nbase seed them (LESSONS #032, #050); LPeg needed `--alloc-func newtree:1`.
2. **Check signal-to-noise before trusting it** (LESSONS #2 — this exact tool once
   produced 828 false format-string positives on lsof, burying ~215 real
   candidates, until it was fixed to locate the true format-position argument).
   If a category is implausibly large, inspect a sample; a scanner that cries wolf
   gets muted. If you improve the scanner, run its self-test:
   `python3 porting-kit/harnesses/c-flaw-scan/scan_c_flaws.py --self-test`
3. **Triage every hit**: does the Rust port close it? For each confirmed flaw, add a
   `DIVERGENCES.md` entry — `- [x] <case>: <why + CWE>` — so the fix is (a) planned,
   (b) surfaced (never silently patched — the most dangerous UB option), and (c)
   shipped as a release note. This is the "decide in writing what you do with UB"
   policy, mechanized.
4. Feed confirmed flaws into `THREAT-MODEL.md` §6 and into the module's test vectors
   (add a boundary/hostile-input case that exercises the fix).
5. **Sweep the existing corpora for an input that reaches each confirmed flaw**
   (LESSONS #033). A golden recorded over undefined behaviour passes until the
   allocator changes. **Decode encoded goldens first** (a hex golden defeats grep),
   and prefer the UB screen of `porting-kit/ORACLE-CHECKS.md` §3 to a grep
   (LESSONS #049). Remove the case from the oracle's input, and pin the port's
   behaviour with a test on the Rust side instead.
6. **When a later step finds a C flaw the scanner missed, measure a rule for it
   then** — hits on that file and on the rest of the tree — and add it with a
   self-test case, or record why not (LESSONS #050: the scanner found 1 of M6.6's
   22 defects, and the miss was known at Phase 0).

The rest of Phase 0 shapes what to hunt: blocking calls and path inputs (FIFOs,
`/dev/zero`; LESSONS #001, #040), safe crates that remove the `unsafe` and the
flaw with it (LESSONS #018), and reused code whose fidelity must be measured, not
read from its docs (LESSONS #043).

## Note
This is a fast heuristic, not a full SAST pass — it bootstraps the flaw inventory in
minutes. For depth, add clang-analyzer / CodeQL / cppcheck; this skill just makes
sure the hunt *happens* before translation, not after a CVE is faithfully reproduced.

## Integrity
`check_skills.py` fails if a lesson that amended Phase 0 is not cited here (LESSONS #046).
Paths/flags/categories must match `scan_c_flaws.py`. If they drift, fix the reference
and re-run `make -C porting-kit check-kit`.
