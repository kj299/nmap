# PLAYBOOK — porting a C codebase to Rust, safely

A repeatable, codebase-agnostic procedure for rewriting C in Rust with **safety
and security as the primary goal** — distilled from the winlsof port (see
[`RETROSPECTIVE-lsof.md`](RETROSPECTIVE-lsof.md)) and designed to compound after
every use (see [`CLAUDE.md`](CLAUDE.md) and [`LESSONS.md`](LESSONS.md)).

**Prime directive.** The Rust rewrite exists to be *safer and more secure* than
the C, not merely equivalent. Two consequences run through every phase:

1. **The C is a specification, not an authority.** It may contain
   vulnerabilities, UB, and latent bugs. Faithfully re-implementing a CVE is a
   failure, not fidelity. Every divergence from C behavior is triaged, and the
   intentional ones (where C was wrong) are recorded — never silently matched.
2. **Every module clears the safety gates before it merges.** Compiling and
   matching the oracle is the floor, not the bar. The bar is: unsafe audited,
   fuzzed, sanitizer-clean, resource-bounded, reviewed, supply-chain-clean.

Nothing here assumes a target OS or that the port is cross-platform. If your port
*is* cross-platform, keep a platform seam — but that is an isolation detail, not
this playbook's focus.

This page holds the rules; the evidence for each is in the `LESSONS.md` entry it
cites. Detail lives in linked docs: [`SECURITY-CHECKLIST.md`](SECURITY-CHECKLIST.md)
(the per-module control ledger), [`ORACLE-CHECKS.md`](ORACLE-CHECKS.md) (Phase 2),
[`RESOURCE-BOUNDS.md`](RESOURCE-BOUNDS.md) (Phase 4 step 4b) and
[`REVIEW-GATE.md`](REVIEW-GATE.md) (Phase 4 gate 6 and the sabotage protocol).

---

## Phase 0 — Inventory & threat model

**Goal:** know the terrain and the risk before writing Rust.

**Do:**
- Enumerate the C: modules, LOC, external deps, the syscall/ioctl/FFI surface,
  global mutable state, macros, the build system. `harnesses/progress/progress.py
  init` seeds the module table from this.
- **Scan the C for vulnerability classes** with `harnesses/c-flaw-scan/scan_c_flaws.py`
  (unbounded copies, format strings, `alloca`, size overflow before allocation,
  command exec, TOCTOU, and the embedded-API rules below). Every hit becomes a note
  on the owning module: *do not port this bug — fix it, and log the fix as an
  intentional divergence.* Three rules make the scan worth trusting:
  - **Tune it for signal-to-noise first.** A check that cries wolf gets muted;
    the format-string check once buried ~215 real lsof candidates under 828
    false positives (LESSONS #2).
  - **Confirm it reads the target's languages before believing a low count.**
    "0 flaws" on a large tree usually means the glob missed the files (LESSONS
    #6: nmap's C++ `.cc` was skipped).
  - **Teach it the contracts of the target's embedded libraries**: the
    `SENTINEL_LIST_ARGS`, `NON_FORMATTING_ARGS` and `ALLOC_FUNCS` tables, extended
    per target with `--config`/`--alloc-func` (LESSONS #032, #050). With libc's
    sinks alone it found 1 of the 22 C defects nmap's M6.6 ledgered.
  **When a later step finds a C flaw the scanner missed, measure a rule for it
  then** — hits on that file and on the rest of the tree — and add it or record
  why not (LESSONS #050: the 1/22 miss was known at Phase 0 and never acted on).
- **Classify the FFI/syscall surface by failure mode** (LESSONS #1): can each
  call **block indefinitely**, does it need **privilege**, does it **vary by
  OS/version**? This is what arms Phase 1's spike-first rule; the winlsof hang
  cost seven commits because `NtQueryObject`'s blocking was never written down.
  **Path inputs count:** a data file can be a FIFO or `/dev/zero` (LESSONS #040).
- **Record a fourth property: does a *vetted, maintained, safe* crate already
  wrap it?** If so, it is the default backend and hand-FFI is a feature-gated,
  cross-checked escape hatch — the **Option-C pattern** (`ARCHITECTURE-TEMPLATE.md`;
  LESSONS #18: nmap's M4 shipped 0 first-party `unsafe` by default this way).
  Vet reused code for **fidelity** as well as safety: a dependency's own
  compatibility list is not an oracle (LESSONS #043: piccolo's "implemented"
  base library had seven behaviours wrong). Count what the corpus reaches (Phase 2).
- Write a one-page **threat model** (`skeleton/THREAT-MODEL.md`): trust
  boundaries, privilege transitions, and — per untrusted input — the **time and
  memory bound** it must respect (availability; LESSONS #040).

**Entry criteria:** access to the C source and its build.
**Exit criteria:** module inventory table; C-flaw scan run and triaged; threat
model written, with a bound per untrusted input.
**Artifacts:** `progress` table, `c-flaw-scan` report, `THREAT-MODEL.md`.
**lsof failure modes this prevents:** discovering the scary module (the
`NtQueryObject` hang) mid-implementation instead of in the inventory.

---

## Phase 1 — Dependency graph & port order

**Goal:** an order that lets each module be tested against the oracle the moment
it lands.

**Do:**
- Build the module dependency graph (includes + call graph; `cflow`/`clangd` or a
  grep pass). Choose order by these criteria, in priority:
  1. **Roots before dependents** — port what others need first (in lsof: the
     process model before the files that hang off it).
  2. **Cheapest-and-safest-first among independents** — bank easy wins, harden
     the loop and harnesses on low-risk modules before the deep end.
  3. **Spike the known-scary module before you schedule it** (Phase 4) — do not
     let a hazard ambush you inside its port.
- Prefer *capability-phased* slices (a user-visible feature end-to-end) over
  strict leaf-first when the codebase is a tool — it keeps every phase shippable.

**Entry criteria:** Phase 0 inventory.
**Exit criteria:** ordered module list with a one-line rationale each; hazards
flagged for a pre-port spike.
**Artifacts:** ordered list in the `progress` table.
**lsof failure modes this prevents:** ad-hoc order that defers integration risk.

---

## Phase 2 — Establish the oracle (before any Rust)

**Goal:** a reference you can diff against — while remembering it may be wrong.
[`ORACLE-CHECKS.md`](ORACLE-CHECKS.md) has the procedure and evidence for the
checks marked ▸.

**Do:**
- Lock the C binary at a known commit. Capture golden outputs across a
  **documented input matrix** (`harnesses/differential/input-matrix.example.toml`)
  with `harnesses/golden/golden.py capture`. ▸ **Defaults are inputs:** each option
  gets a row where it is omitted, plus the combinations users run (a report to the
  terminal and a file at once). nmap's `-o` silenced the terminal from M1 and `-sU`
  scanned the TCP list from M4, because every row passed `-p` and `-oX -`
  (LESSONS #047).
- **Detect oracle nondeterminism up front** — `golden.py` runs each input N times
  and flags fields that vary; those feed `harnesses/differential/normalize.py`.
- If the reference **cannot run on your environment** (winlsof: C lsof doesn't run
  on Windows), use **structural golden tests** for format and **independent
  oracles** (native tools) for the data.
- **Harden the harness for its host** (LESSONS #1): kit harnesses are Python +
  POSIX sh, not the target's shell; pin the tool's default output encoding to the
  host shell's lowest common denominator (winlsof: ASCII default, UTF-8 opt-in).
- **An oracle COPIES the C — it never restates it.** Paste the function and diff
  it against the source; where impractical, say which *inputs* were substituted
  and that no logic was. nmap's retyped `apply_scale` lost a guard and the
  differential passed bit-exact while both sides were wrong (LESSONS #019).
- **Sanitize the pasted C and feed it TRUNCATED input** (LESSONS #020): a second
  build with `-fsanitize=address -g -O0`, driven with inputs cut short across each
  length check — a curated corpus stays inside defined behaviour and will not trip
  it. ▸ Build it in the **embedded library's own checking mode too**
  (`LUA_USE_APICHECK`): it caught nested-capture overflows ASan missed (LESSONS #051).
- ▸ **Every golden generated by running C is screened** under
  `-fsanitize=address,undefined -fno-sanitize-recover=all` plus the runtime's API
  checks. The screen's committed record carries a **digest of the corpus, the C
  sources and the flags**; the generator refuses a mismatch and CI checks it. **UB
  that looks deterministic is still UB:** nmap's tree golden held 14 signed-overflow
  rows justified as "modulo 2^32" (LESSONS #049). Store goldens greppable, or
  decode them before any sweep.
- Where the C is **undefined** for an input, record no golden: exclude the region,
  say so in the generator, and cover it from the Rust side (a rejecting test plus
  fuzz seeds at each boundary). **When a C flaw is found later, sweep the existing
  fixtures for inputs that reach it**: every new ledger entry for a C defect ends
  with a grep of the corpora and probes (LESSONS #033).
- **A golden encodes the host that generated it** (LESSONS #034). Fixtures print
  only facts true on every host the comparison runs on; capability-dependent
  scenarios are named in the generator and the docs say where they run;
  concurrent fixtures do not print each other's state.
- ▸ **Reach census:** count corpus rows per function the port exposes; **zero rows
  means unverified**, whatever the code or its dependency claims (LESSONS #043:
  0 rows for `rawlen`, `rawset`, `pairs`, `ipairs`, `collectgarbage`).
- ▸ **Sabotage the C to measure the corpus**: build variants that each break one
  behaviour; the corpus must catch every one (LESSONS #044: 16 variants of
  `lpeg.c`; one passed all 60,806 rows).
- Stand up the **intentional-divergence ledger** (`DIVERGENCES.md`, template in the
  skeleton), seeded from the Phase-0 flaw scan.

**Entry criteria:** ordered module list.
**Exit criteria:** golden corpus captured + versioned; nondeterminism map;
normalization rules; divergence ledger seeded; every pasted-C oracle diffed
against its source and, where it parses untrusted input, run under ASan over a
truncation sweep; every C-generated golden UB-screened with a current digest;
reach census and C-sabotage run.
**Artifacts:** `golden/corpus/`, `normalize.py` rules, `DIVERGENCES.md`, the screen record.
**lsof failure modes this prevents:** the empty-result "bare header" and the
bare-`n` `-F` field shipped because there was no format oracle pinning them.

---

## Phase 3 — Architecture skeleton (unsafe quarantine)

**Goal:** a workspace shape that makes safety structural, not a review burden.

**Do:** copy `skeleton/` (see [`ARCHITECTURE-TEMPLATE.md`](ARCHITECTURE-TEMPLATE.md)).
- **`core` crate: `#![forbid(unsafe_code)]`.** Pure logic, data model, the
  algorithm; testable everywhere, no FFI. Most of the port lives here.
- **`sys` crate: the only place `unsafe` is allowed.** Every raw FFI call wrapped
  in a small, audited safe function; every OS resource an RAII type — this kills
  use-after-free, leak, and privilege-held-too-long by construction.
- **`cli` crate:** thin; parse → build request → call core → render.
- **Scaffold observability on day one:** a `TRACE` env-gated phase logger.
- **Wire CI from `harnesses/ci/porting-ci.template.yml`**, each workflow path-scoped
  to what it builds **plus every file its oracle and goldens read** (LESSONS #005,
  #051: nmap's filter omitted `lpeg.c` and `liblua/**`, which its goldens compile).

**Environment preflight** (LESSONS #1): confirm the toolchain target links here
(winlsof: MSVC-vs-GNU) and the build dir is not a synced/locked folder (OneDrive
→ `os error 5`). **Pin the toolchain** (`skeleton/rust-toolchain.toml`; CI reads
it via `@master` + `toolchain:`) so local fmt/clippy match CI; a floating `@stable`
failed two M4 slices on lints nobody ran (LESSONS #16). Bump the pin in its own PR.

**Entry criteria:** oracle in place.
**Exit criteria:** workspace builds; `core` is `forbid(unsafe_code)`; unsafe-audit
gate wired into CI; trace logger present; environment preflight clean.
**Artifacts:** the workspace; the CI config.
**lsof failure modes this prevents:** scattered `unsafe` (winlsof: 144 blocks, 91
documented — the gate makes the gap a build failure); tracing added reactively.

---

## Phase 4 — The module port loop (per module)

**Goal:** each module ends safer than its C original, proven, before merge.

**Run each gate with the exact command CI runs, not a narrowed version of it.**
`cargo miri test -p one-crate` is a fast inner loop; `cargo miri test` is the gate.
`--all`, `--all-features` and package selectors are part of a gate's identity
(LESSONS #023, #026, #030). The declared MSRV is one of those gates: build
`--all-targets`, test code included, with the MSRV toolchain before pushing, and
re-run the full clippy sweep whenever the MSRV moves (LESSONS #036).

**No check run on the head SHA means no gate ran** (LESSONS #042). nmap's whole
M6.6 merged with zero check runs while its local stand-ins were scoped. When CI
cannot run, `make -C porting-kit ci-local` runs every workflow job unscoped; paste
its summary into the PR. A PR with neither is blocked, not annotated.

**Sabotage is a measurement with failure modes** (LESSONS #038, #044; protocol in
[`REVIEW-GATE.md`](REVIEW-GATE.md)): restore from a byte copy, never `git checkout`,
**and bump the mtime** — a restore that keeps the old mtime makes cargo test the
stale, sabotaged build; **only a named assertion counts as a catch** (a kill or
timeout is inconclusive); and each step gets an **independent** sabotage set (step
a: the author's 11 all caught, 8 of the reviewers' 34 missed by every gate).

For a hazardous module (flagged in Phase 1), **spike first**: a timeboxed
experiment on the one scary syscall/idiom — does it block? need privilege? vary by
version? — recorded *before* committing to a design. The highest-ROI habit.

**For a *research-grade* capability — one that might be impossible, not merely
hard** — run the **spike-and-gate ritual** (LESSONS #1): (a) rate effort (S/M/L)
and confidence (Low/Med/High); (b) write a **decision gate** before coding — the
signal that says "stop, document as a platform limit"; (c) on hitting it, do a
**pivot check** for an adjacent reachable goal (winlsof's ETW spike missed the real
FD but shipped raw/ICMP/AF_UNIX `-i`). A closed sub-goal must not kill the one beside it.

**A spike's decision gate covers the states the hot path never enters** (LESSONS
#17, #040): for a resource-holding or blocking-thread design, **"it can be stopped
while idle, cleanly, within a bounded time"**; for a pre-emptible design, **total
work and the slice bound**, not just "it yields". A stand-in for the real API must
reproduce the property under test — for liveness, how the call blocks *and*
unblocks (a `std` `recv` is not `pcap_next_ex`). M4's capture spike passed its
latency gate and shipped a shutdown deadlock; M6.6's pre-emption spike passed 8
criteria, none about total work, and the defects sat in the part it skipped. If
the stand-in cannot model the property, the spike is not discharged until the real
resource is tested (gate 4).

Then the loop — each step is a gate:

1. **Port** into `core` (or a safe wrapper in `sys`). Call-twice-for-size → a
   growing `Vec` with length checks; pointer arithmetic → slices + `repr(C)` with
   bounds; unions/FAMs → audited casts with a `// SAFETY:` proof; integer math →
   checked/`saturating`. **A C byte-at-a-time parser stays byte-oriented — port it
   over `&[u8]`, not `&str`/`chars()`** (LESSONS #12): decoding binary input to
   `&str` is wrong and adds a panic class C never had (nmap's `next_template`
   sliced mid-codepoint). `&str` only for proven text, via a fallible `from_utf8`.
2. **Differential-test** against the oracle (`harnesses/differential/diff_run.py`).
   A divergence is a *triage*: {Rust bug → fix} vs {C bug → log in
   `DIVERGENCES.md`, keep the safe behavior}. The verdict is **stdout AND exit
   code** (LESSONS #4; `--ignore-exit` opts out). The per-case timeout is the
   **liveness backstop** (LESSONS #1): a timeout is a design smell — avoid the
   blocking call, don't wrap it.
   - When the port **intentionally renders a subset** of the C output, diff a
     **canonical semantic projection** of both sides (for a scanner: host state,
     open-port state/reason, per-state counts) rather than ledgering whole cases
     (LESSONS #7). A projection that hides a temporary abbreviation needs an expiry
     in its ledger entry (LESSONS #031).
   - When both tools read a **versioned data file**, project only the
     version-independent finding (the service *name*, not the product string) and
     pin data-derived detail with goldens against a fixed DB snapshot (LESSONS #13).
     The differential compares what the port *computes*, not what it *looks up*.
   - **A tolerance is an exemption: scope it and pin its membership** (LESSONS
     #048). A rule that makes a ledgered difference compare equal fires only on
     the case ids it was ledgered for (`diff_run.py --tolerances`, `normalize.py`
     scoped rules), and a listed case that no longer needs it fails. nmap's
     unscoped classes reached 5,906 rows and passed an argument-number regression
     on all of them.
3. **Fuzz** the module's parse/input surface (`harnesses/fuzz/gen_fuzz_target.sh`).
   Any crash/panic on untrusted input blocks release. The gate is scoped to the
   **threat-model boundary** — N/A, not a missing tick, for a renderer or pure data
   model (LESSONS #9). Keep hand-authored seeds read-only: `cargo fuzz run <t>
   corpus/<t> seeds/<t>`. **A 60s smoke is a floor, not a proof** (LESSONS #15):
   commit every crashing input as a named seed, and give untrusted-boundary parsers
   a longer, forked run once per milestone. **Re-run every crash artefact on HEAD
   before deleting or dismissing it**: one filed as a sabotage leftover was a real C
   quirk the target's oracle did not model (LESSONS #039).
4. **Sanitize** (`harnesses/sanitizers/run_sanitizers.sh`): Miri over the pure
   logic; ASan (TSan if threaded) for the `sys` layer.
   - **Miri cannot run real I/O** — split the pure decision from the I/O
     (`verdict(outcome, elapsed)`), Miri the decision, and gate the I/O tests with
     `#[cfg_attr(miri, ignore = "…")]` (LESSONS #8).
   - **TSan is unsound over an async runtime** (LESSONS #10): prove race-freedom
     structurally (no shared mutable state + `Send`/`Sync` on `spawn`) and keep a
     multi-thread **liveness** test; reserve TSan for OS threads over shared state.
   - That liveness test catches what sanitizers cannot: **a defensive catch-all
     `break` in a work-scheduling loop drops work** (LESSONS #14); with work
     outstanding, retry/continue, and break only on a proven-terminal condition.
   - **A `sys` module that owns a blocking OS resource gets a root-only real-resource
     teardown test in its own slice** (`#[ignore]`; construct → no traffic →
     `Drop` returns in bounded time). A mock proves the plumbing, never the
     teardown (LESSONS #17).

   4b. **Resource bounds** ([`RESOURCE-BOUNDS.md`](RESOURCE-BOUNDS.md); LESSONS
   #040). **Pre-emptible is not bounded.** For each untrusted input edge, run the
   port in a release build at n, 2n, 4n and gate the time and peak-memory exponents
   against the declared bound and against C's
   (`harnesses/scaling/scale_check.py --oracle-cmd`); for self-metering code,
   assert work ≤ c·fuel per slice with work counted independently of the charge,
   plus a wall-clock longest-slice check; calibrate any step counter against wall
   clock once. M6.6's `json.parse` took 1,600× C's time with every other gate green.
5. **Unsafe-audit** (`harnesses/unsafe-audit/audit_unsafe.py`): every `unsafe`
   block has a `// SAFETY:` justifying its invariants — **hard fail** otherwise.
6. **Review, then merge** ([`REVIEW-GATE.md`](REVIEW-GATE.md); LESSONS #041). An
   independent review with two lenses — fidelity (adversarial rows beyond the
   corpus) and security (time, memory, totality) — plus an independent sabotage
   set, producing a severity table. The fix round lands in the same PR; the merge
   is blocked until each finding is fixed or ledgered. **Each finding's class joins
   the entry gates of every later step**; an out-of-scope finding gets a ledger or
   BACKLOG row the same day. Then confirm CI ran on the head SHA, and advance the
   `progress` table **with a stamp** (`progress.py set MODULE GATE --src crates`),
   so `audit --src` flags the tick once the code outgrows it (LESSONS #045).

**Entry criteria:** skeleton + oracle; the standing gates from earlier reviews.
**Exit criteria (per module):** all gates green; review findings fixed or
ledgered; check runs (or a `ci-local` summary) on the head SHA; `progress` row
ticked and stamped; `progress.py drift --src crates` clean (LESSONS #021).
**Artifacts:** the module, its fuzz target, its golden cases, its scale checks,
the review table, divergence entries.
**lsof failure modes this prevents:** the 7-commit hang (spike-first + liveness),
fidelity misses shipping before a test pinned them (gate 2 + golden), undocumented
unsafe (gate 5).

---

## Phase 5 — Cutover & retirement of the C

**Goal:** ship the Rust; retire the C without losing its guarantees.

**Do:**
- Gate cutover on: 100% of the target modules through all gates; the differential
  corpus green (modulo logged divergences); fuzz corpus seeded and clean;
  supply-chain gate clean (`harnesses/supply-chain/run_supply_chain.sh`).
- Keep the C runnable as the oracle through one release overlap; only then retire.
- Ship `DIVERGENCES.md` as user-facing release notes — the security fixes are a
  *feature*.

**Entry criteria:** all target modules merged & gated.
**Exit criteria:** Rust is the shipped artifact; supply-chain clean; divergences
published; C archived (not deleted until an overlap release proves parity).
**Artifacts:** release, `DIVERGENCES.md`, final `progress` table.
**lsof failure modes this prevents:** big-bang deletion before parity.

---

## Cross-cutting safety controls (apply continuously)

| Control | Harness / mechanism | Gate |
|---|---|---|
| No `unsafe` in pure logic | `#![forbid(unsafe_code)]` on `core` | compile |
| Every `unsafe` justified | `unsafe-audit/audit_unsafe.py` | **hard-fail CI** |
| No UB at the FFI boundary | `sanitizers/run_sanitizers.sh` (Miri, ASan/LSan/TSan) | CI |
| No panics on untrusted input | `fuzz/` (`cargo-fuzz`) | CI smoke + nightly deep |
| No super-linear time/memory on untrusted input | `scaling/scale_check.py` vs C (LESSONS #040) | CI |
| No vulnerable/untrusted deps | `supply-chain/run_supply_chain.sh` (`cargo audit`,`cargo deny`) | CI |
| No silent behavior drift | `differential/diff_run.py` + `DIVERGENCES.md`, tolerances scoped | CI |
| C goldens are defined behaviour | UB screen + digest record (LESSONS #049) | CI |
| Lints as errors | `clippy -D warnings` (+ overflow/cast lints) | CI |
| Don't re-port a C vuln | `c-flaw-scan/scan_c_flaws.py` at Phase 0 | review |
| Gates actually ran on this commit | check runs on HEAD, else `make ci-local` (LESSONS #042) | merge |
| Every module reaches DONE, ticks current | `progress/progress.py audit --require-done --src crates` | CI, retrospective |
| Signature checks reject forgeries | strict verification (e.g. Ed25519 `verify_strict`), small-order keys | review (LESSONS #037) |

See `harnesses/ci/porting-ci.template.yml` for the wiring and
`make -C porting-kit check-kit` to smoke-test every harness.

---

## The compounding loop

Every port **ends with a retrospective** (`PROMPTS/90-retrospective.md`) that
diffs lived experience against this playbook and patches it — harnesses, docs
**and skills** (`check-kit` fails when a skill omits a lesson that amended its
phase; LESSONS #046). New lessons append to `LESSONS.md` with the section they
amended. The kit is the running sum of every port it has survived.

The retrospective also checks the port's records against the code:
- list merged SHAs with **zero check runs**; each is a commit no gate ran on
  (LESSONS #042);
- run `progress.py audit --require-done --src crates`: a module below DONE needs
  its reason, and a stamped tick whose code changed needs its gate re-run
  (LESSONS #035, #045);
- re-scan the C with any scanner rules added since Phase 0; **decode** the goldens,
  re-run the UB screen and the reach census, and sweep for inputs that reach each
  new hit (LESSONS #032, #033, #043, #049);
- check that every count the docs quote matches the golden it describes (nmap's
  docs said 34 scenarios; the golden had 36).
