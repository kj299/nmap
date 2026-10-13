# Prompt — port one module (the Phase 4 loop)

Paste this once per module, after Phase 0/1 are agreed. Replace `[MODULE]`.

---

Port the C module **`[MODULE]`** to Rust following `porting-kit/PLAYBOOK.md`
Phase 4. Re-read PLAYBOOK Phase 4 and `RETROSPECTIVE-lsof.md` §6 first, and
load the **standing gates**: every finding class an earlier step's review found
is an entry gate here (LESSONS #041).

**If this module was flagged hazardous (blocking syscall, exotic ioctl, unions,
threads), SPIKE FIRST** (LESSONS #001): a timeboxed experiment on the one scary
operation, recorded *before* committing to a design. Its decision gate covers
teardown while idle for a blocking design (LESSONS #017) and total work plus the
slice bound for a pre-emptible one (LESSONS #040).

Run every gate with the exact command CI runs — unscoped, `--all-features`, and
the MSRV build of `--all-targets` (LESSONS #030, #036). Each is a hard
requirement before merge:

1. **Port** into `core` (pure logic) or a safe wrapper in `sys` (if it touches
   FFI). Call-twice-for-size → growing `Vec` + length checks; pointer/struct
   math → slices + `repr(C)` with bounds; unions/flexible arrays → audited casts
   each with a `// SAFETY:`; integer math → checked/saturating. A byte parser
   stays on `&[u8]` (LESSONS #012). No `unwrap`/`expect`/unchecked indexing on
   untrusted input.
2. **Differential-test** vs the oracle:
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust
   <rust> --matrix <m> --ledger DIVERGENCES.md --tolerances <t>`. A divergence is
   a TRIAGE: fix the Rust, OR — if the C was wrong — record the intentional fix
   in `DIVERGENCES.md` (`- [x] <case>: <why + CWE>`). Never silently match a C
   bug. Stdout and exit code (LESSONS #004); projections for subsets and data-file
   lookups (LESSONS #007, #013); every tolerance scoped to its ledgered cases and
   pinned (LESSONS #048).
3. **Fuzz** the input surface (threat-model-scoped, LESSONS #009):
   `bash porting-kit/harnesses/fuzz/gen_fuzz_target.sh [MODULE] --crate <crate>`,
   then `cargo fuzz run [MODULE] -- -max_total_time=60`. Any panic/crash blocks;
   seed it (LESSONS #015). Re-run every crash artefact on HEAD before dismissing
   it (LESSONS #039).
4. **Sanitize:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh miri .`
   (and `asan` for the `sys` layer). Split decision from I/O (LESSONS #008); no
   TSan over an async runtime, a liveness test instead, no defensive `break`
   (LESSONS #010, #014); a root-only teardown test for blocking `sys` resources
   (LESSONS #017).
   **4b. Resource bounds** (`porting-kit/RESOURCE-BOUNDS.md`, LESSONS #040):
   `python3 porting-kit/harnesses/scaling/scale_check.py` at n/2n/4n, release
   build, port vs C, time and peak memory; work ≤ c·fuel per slice for
   self-metering code.
5. **Unsafe-audit:** `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py
   crates/` — must report **0 undocumented**.
6. **Independent review, then merge** (`porting-kit/REVIEW-GATE.md`, LESSONS
   #041): two lenses (fidelity, security/resources), an independent sabotage set
   run by the protocol — byte-copy restore plus `touch`, named assertions only
   (LESSONS #038, #044) — a severity table, and the fix round in this PR. Pin each
   regression test in the same change. Merge only with check runs on the head SHA
   or a pasted `make -C porting-kit ci-local` summary (LESSONS #042).

Advance and stamp the tracker as gates clear (LESSONS #021, #045):
`python3 porting-kit/harnesses/progress/progress.py --file progress.json set
[MODULE] <gate> --src crates`.

Report the module's final gate row, the review's severity table, and any new
`DIVERGENCES.md` entries.
