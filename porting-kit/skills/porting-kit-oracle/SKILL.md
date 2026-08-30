---
name: porting-kit-oracle
description: Establish the differential oracle and test-vector harness BEFORE translating any C to Rust. Use in Phase 2, or whenever the user needs to lock the reference behavior / build the input matrix / set up golden tests for a C-to-Rust port. Enforces "semantic equivalence, not it-builds" — the single biggest finding behind translation failures.
---

# Porting Kit — establish the oracle (test harness first)

Wraps the differential + golden harnesses and PLAYBOOK Phase 2 / synthesis Step 0.5.
**Do this before writing Rust.** TRACTOR's central finding: most failures are at the
semantic-comparison stage, not build time — "it builds" tells you almost nothing.

## Procedure
1. **Lock the C binary** at a known commit as the reference oracle.
2. **Build the input matrix** from `porting-kit/harnesses/differential/input-matrix.example.toml`.
   Cover: every output format, every flag, empty/edge inputs, large inputs, and —
   critically — malformed/hostile inputs and **every integer boundary**
   (`INT_MAX`/`CHAR_MAX`, off-by-one indices, empty buffers): the UB shapes a rewrite
   must handle better than C.
3. **Capture + version the golden corpus**, flagging oracle nondeterminism so you
   normalize it instead of enshrining it:
   `python3 porting-kit/harnesses/golden/golden.py capture --oracle <c-bin> --matrix <m> --corpus <dir>`
4. **Tune normalization** (`porting-kit/harnesses/differential/normalize.py`) so
   PIDs/timestamps/pointers/ephemeral-ports are masked *identically* on both sides —
   whatever you erase from C you must erase from Rust, or you manufacture a divergence.
5. **Validate every vector against the C first** — a wrong vector that "passes"
   teaches nothing. **Hold back a hidden acceptance set** (an LLM in the loop will
   overfit to visible vectors).
5a. **An oracle copies the C; it never restates it.** Paste the reference function and
   diff it against the source. Where that is impractical (headers, globals, member
   state), state in a comment exactly which *inputs* were substituted and that no
   logic was. A gate that compares the port against a paraphrase proves only
   self-consistency — nmap's `apply_scale` oracle was retyped without the C's
   `if (val < 0) continue;`, under a comment claiming verbatim, and the differential
   passed bit-exact **while both sides were wrong** (LESSONS #019).
5b. **Sanitize the pasted C over truncated input** (LESSONS #020). Where the oracle
   contains real C that parses attacker-controlled bytes, build a second copy with
   `-fsanitize=address -g -O0` and drive it with inputs cut short at every length
   across each length-check boundary. A *curated* corpus will not trip it — the
   corpus is built to stay inside defined behavior — so write the truncation sweep
   separately. This is the cheapest mechanical check for a bounds test that does not
   dominate the read it guards, the class `scan_c_flaws.py` structurally cannot see.
5c. **Record no golden where the C is undefined.** Exclude that region from the
   corpus, say so in the generator, and cover it from the Rust side (a test asserting
   the port rejects every input in the gap, plus fuzz seeds at each boundary). A
   golden captured over UB records whatever was left in memory, not behavior.
6. **Seed `DIVERGENCES.md`** (copy `porting-kit/skeleton/DIVERGENCES.md`) from the
   Phase-0 flaw scan — the intentional-divergence ledger the differential reads.
7. **Wire the differential** (used per module in `porting-kit-module`):
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust <rust> --matrix <m> --ledger DIVERGENCES.md`
   The verdict is stdout **and** exit code; a per-case timeout is the liveness
   backstop (a hang isn't UB, so sanitizers miss it). For a C-ABI **library** rather
   than an executable, use a `cando`-style function-level harness (synthesis Step 0.5).

## Integrity
Harness paths/subcommands/flags must match the kit. If they drift, fix the reference
and re-run `make -C porting-kit check-kit`.
