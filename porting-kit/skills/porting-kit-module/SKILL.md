---
name: porting-kit-module
description: Port one C module to Rust through the safety gates. Use when translating/porting a specific module, function, or subsystem from C to Rust as part of a Porting-Kit port. Runs the per-module loop — spike-if-hazardous, port, differential-test, fuzz, sanitize, resource-bound, unsafe-audit, independent review + merge — with each gate a hard requirement.
---

# Porting Kit — port one module (the Phase 4 loop)

Wraps `porting-kit/PROMPTS/10-module-port.md` and PLAYBOOK Phase 4. Re-read those first;
they are authoritative and this skill only sequences them.

## Before the first gate
- **Load the standing gates.** Every class an earlier review found is an entry gate for
  this module (LESSONS #041); the plan lists them.
- **Spike first if the module is hazardous** (blocking syscall, exotic ioctl, unions,
  threads): a timeboxed experiment on the one scary operation, recorded before the
  design (LESSONS #001). For a capability that might be *impossible*, run the
  spike-and-gate ritual (effort/confidence, a written decision gate, a pivot check).
  The decision gate covers **teardown while idle** for a blocking design (LESSONS #017)
  and **total work and the slice bound** for a pre-emptible one (LESSONS #040).
- **Run every gate exactly as CI runs it** — no `-p`, no filter, `--all-features`, and
  the MSRV build of `--all-targets` (LESSONS #030, #036).

## The gates (each a hard requirement before merge)
1. **Port** into `core` (pure logic) or a safe wrapper in `sys`. Call-twice-for-size →
   growing `Vec`; pointer math → slices; unions → audited casts with `// SAFETY:`;
   integer math → `checked_*`/`saturating_*`. A byte parser stays on `&[u8]`, never
   `&str` (LESSONS #012). No `unwrap`/`expect`/unchecked index on input.
2. **Differential-test** vs the oracle:
   `python3 porting-kit/harnesses/differential/diff_run.py --oracle <c> --rust <rust> --matrix <m> --ledger DIVERGENCES.md --tolerances <t>`
   A divergence is a triage: fix the Rust, or ledger a fix-of-C-defect. Verdict =
   stdout AND exit code (LESSONS #004); a timeout is a design smell (LESSONS #001).
   Project subset renders and data-file lookups (LESSONS #007, #013). **Every tolerance
   is scoped to its ledgered case ids and pinned** — `STALE-TOLERANCE` fails (LESSONS #048).
3. **Fuzz** (threat-model-scoped, LESSONS #009):
   `bash porting-kit/harnesses/fuzz/gen_fuzz_target.sh <module> --crate <crate>`, then
   `cargo fuzz run <t> corpus/<t> seeds/<t> -- -max_total_time=60`. Seed every crash
   (LESSONS #015); **re-run every crash artefact on HEAD before dismissing it** (LESSONS #039).
4. **Sanitize:** `bash porting-kit/harnesses/sanitizers/run_sanitizers.sh miri .`
   (+ `asan` for `sys`). Split decision from I/O for Miri (LESSONS #008); no TSan over an
   async runtime, keep a liveness test, never a defensive `break` (LESSONS #010, #014);
   a root-only real-resource teardown test for blocking `sys` modules (LESSONS #017).
4b. **Resource bounds** — `porting-kit/RESOURCE-BOUNDS.md` (LESSONS #040). Pre-emptible
   is not bounded: n/2n/4n in a release build, port vs C, by wall clock and RSS:
   `python3 porting-kit/harnesses/scaling/scale_check.py --cmd '<port {input}>' --oracle-cmd '<c {input}>' --gen '<gen {n} > {input}>' --n <N> --time-exp 1 --mem-exp 1`
   For self-metering code: work ≤ c·fuel per slice, counted apart from the charge.
5. **Unsafe-audit** (0 undocumented):
   `python3 porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/` — clippy's
   `missing_safety_doc` + `undocumented_unsafe_blocks` (workspace lints, CI) cover `unsafe fn`.
6. **Independent review, then merge** — `porting-kit/REVIEW-GATE.md` (LESSONS #041).
   Two lenses (fidelity beyond the corpus; time/memory/totality), an independent sabotage
   set, a severity table, the fix round in the same PR, merge blocked until each finding
   is fixed or ledgered, out-of-scope findings recorded the same day. **Sabotage
   protocol** (LESSONS #038, #044): restore from a byte copy and `touch` it; only a named
   assertion is a catch. Pin the regression test in the same change.
   **CI ran on the head SHA**, or paste `make -C porting-kit ci-local` (LESSONS #042).

Advance the tracker and stamp the tick (LESSONS #021, #045):
`python3 porting-kit/harnesses/progress/progress.py --file progress.json set <module> <gate> --src crates`

For the hardest modules, consider **two candidate translations by different methods**
and let the vector suite pick the winner.

## Integrity
Commands/paths/gate-names must match the kit and PLAYBOOK Phase 4; `check_skills.py`
also fails if a lesson that amended Phase 4 is not cited here (LESSONS #046). Fix the
reference on drift; re-run `make -C porting-kit check-kit`.
