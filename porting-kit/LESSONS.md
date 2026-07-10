# LESSONS — append-only log

Every port appends here (via `PROMPTS/90-retrospective.md`). This is how the kit
compounds: each entry names a lesson, the codebase that taught it, and the
`PLAYBOOK.md`/harness section it amended. **Append only — never rewrite history.**

Format per entry:

    ## NNN. <one-line lesson>
    - **Date:** YYYY-MM-DD
    - **Codebase:** <project> (<language/domain>)
    - **What happened:** <the failure or insight, grounded in evidence>
    - **Kit change:** <the concrete PLAYBOOK/harness/template edit made>
    - **Section amended:** <file · section>

---

## 001. The kit's own dry-run against lsof's failure inventory

- **Date:** 2026-07-05
- **Codebase:** winlsof (C `lsof` → Rust, Windows) — Phase 3 self-validation
- **What happened:** Walking `PLAYBOOK.md` end-to-end against the
  `RETROSPECTIVE-lsof.md` §6 failure inventory surfaced five failures the
  playbook, as first drafted, would *not* have prevented. Each was fixed in the
  playbook and is recorded below. This is entry #1 because the first thing the
  kit did was find its own gaps.

  1. **The hang wasn't spiked because it wasn't *recognized* as hazardous.**
     The "spike the scary module first" rule can only fire on a hazard someone
     wrote down. The 7-commit `NtQueryObject` hang had no such note.
     → **Kit change:** Phase 0 now requires *classifying the FFI/syscall surface
     by failure mode* (blocks-indefinitely? needs-privilege? version-variant?),
     which is what arms the spike-first rule.
     → *Section amended:* PLAYBOOK · Phase 0 "Do".

  2. **Hangs are invisible to the safety gates.** A deadlock/blocking call is a
     liveness bug, not UB — Miri/ASan/TSan don't flag it, and "compiles + matches
     oracle" hides it. The playbook's gate set had no liveness check.
     → **Kit change:** documented that the differential harness's per-case
     timeout (`diff_run.py` → `<<TIMEOUT>>`) IS the liveness backstop, and a
     timeout is a design smell to be *designed out*, not wrapped.
     → *Section amended:* PLAYBOOK · Phase 4 gate 2.

  3. **The research-grade spike-and-gate ritual — winlsof's biggest win — was
     underweighted.** The draft only spiked *hazardous modules*, not *capabilities
     that might be impossible*. Those need effort/confidence ratings, a written
     decision gate, and a pivot check (winlsof's ETW pivot: couldn't get the real
     FD, but shipped raw/ICMP/AF_UNIX coverage instead).
     → **Kit change:** added the explicit spike-and-gate sub-process.
     → *Section amended:* PLAYBOOK · Phase 4 (research-grade capability).

  4. **The test harness's host fought back and the playbook didn't warn of it.**
     Six commits went to PowerShell-5.1 / Windows-1252 breakage *in the harness*.
     → **Kit change:** Phase 2 now has a "harden the harness for its host" step
     (write kit harnesses in a portable language — Python + POSIX sh, done — and
     pin the tool's default output encoding to the target's default shell).
     → *Section amended:* PLAYBOOK · Phase 2 "Do".

  5. **Environment friction (toolchain / synced build dir) ate time with no code
     cause.** MSVC-vs-GNU linker mismatch; OneDrive locking `target\`.
     → **Kit change:** Phase 3 gained an "environment preflight" exit criterion.
     → *Section amended:* PLAYBOOK · Phase 3.

- **Validation the kit already pays off:** running the new
  `unsafe-audit/audit_unsafe.py` against the shipped winlsof backend reported
  **131 real `unsafe` blocks, 51 undocumented** — empirically confirming the
  retrospective's inferred "144-vs-91" gap (the tool correctly excludes the
  comment/string matches that inflated the raw grep). The hard-fail gate would
  have prevented every one of those 51 from merging undocumented.
- **Still not prevented (the next port's target):** the kit cannot force the
  *design insight* that ended the hang (avoid the blocking call via a type-index
  pre-probe). It can make the hang *visible* early (classification + timeout
  gate) and buy time to find the insight, but inventing the safe design remains
  human/agent work. A future kit lesson may add a "hazardous-API pattern library"
  of known avoid-the-call recipes.

---

## 002. A noisy Phase-0 scanner is worse than none — it gets ignored

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 1 (kit run against lsof's *actual* C tree)
- **What happened:** Running `c-flaw-scan/scan_c_flaws.py` against real lsof
  (`lib/ src/`) returned **1044 hits, of which 828 were false "format-string"
  positives.** The check flagged arg 0 of every printf-family call, but the
  format string is not arg 0 for `fprintf`/`sprintf`/`snprintf`/`syslog`/`err`
  (it follows the stream / buffer / size / priority). So every
  `fprintf(stderr, "literal", ...)` — the overwhelmingly common, *safe* case —
  was flagged. A Phase-0 tool that cries wolf 828 times gets muted, and the
  ~215 real candidates (97 TOCTOU, 94 integer-overflow, 24 unbounded-copy) drown
  in the noise. That is the exact opposite of the tool's purpose: to *bootstrap
  the flaw inventory*. This is itself a lsof-class failure — a control so noisy
  it is ignored is a broken control (the retrospective's own "a skipped control
  is a broken control").
- **Kit change:** rewrote the format-string check to locate the *format-position*
  argument per function (a small arg-list parser + per-function format index)
  and flag only when that argument is a **non-literal**. Result on the same lsof
  tree: format-string **828 → 8** (all 8 genuine non-literal formats), total
  **1044 → 224**. Pinned with a self-test that asserts `fprintf(stderr, var, ...)`
  flags but `fprintf(stderr, "literal", ...)` and `snprintf(buf, n, "%d", ...)`
  do not.
- **Section amended:** harnesses/c-flaw-scan/scan_c_flaws.py (`FORMAT_FUNCS`,
  `_call_args`, `_scan_format_strings`); the general principle — *tune every
  Phase-0 scanner for signal-to-noise against the real target before trusting
  it* — belongs to PLAYBOOK · Phase 0.

---

## 003. A "delegated" control that nothing enforces is not a control

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 2 (kit run against lsof/winlsof's real code)
- **What happened:** The unsafe-audit harness documents that it covers `unsafe {}`
  blocks + `unsafe impl`, and *delegates* `unsafe fn` `# Safety`-doc coverage to
  "clippy's `missing_safety_doc`." But grepping the shipped winlsof backend found
  **11 `unsafe fn` / `unsafe extern fn` definitions** (ETW callbacks and TDH
  property parsers — real FFI-facing unsafe surface), and **neither the CI
  template nor the skeleton enabled that clippy lint** (it is allow-by-default).
  So the delegation was fiction: no tool, anywhere, checked that any `unsafe fn`
  had a safety contract. A control you point at another tool that you never turn
  on is worse than an acknowledged gap — it reads as covered.
- **Kit change:** wired the clippy half for real. `[workspace.lints]` in the
  skeleton now sets `clippy::missing_safety_doc` + `undocumented_unsafe_blocks`
  (plus `cast_possible_truncation` and `arithmetic_side_effects` — the C-idiom
  footguns), each crate opts in via `[lints] workspace = true`, and the CI
  clippy step passes `-D clippy::missing_safety_doc -D
  clippy::undocumented_unsafe_blocks` as belt-and-suspenders for repos that copy
  the CI without the lints table. Documented the two-layer split (harness =
  toolchain-free block gate; clippy = `unsafe fn` docs + block cross-check) in
  the harness docstring and SECURITY-CHECKLIST. Skeleton still builds offline.
- **Section amended:** skeleton/Cargo.toml (`[workspace.lints]`) + each crate's
  `[lints]`; harnesses/ci/porting-ci.template.yml (clippy step);
  SECURITY-CHECKLIST · per-module; audit_unsafe.py docstring.

---

## 004. Differential fidelity is stdout AND exit code, not stdout alone

- **Date:** 2026-07-05
- **Codebase:** winlsof — dry-run pass 3 (kit run against lsof's real behavior)
- **What happened:** `diff_run.py` *captured* both binaries' exit codes but its
  verdict was computed from normalized stdout only — the codes were reported and
  ignored. So a rewrite with identical output and a wrong exit status passed as
  MATCH. That is a real fidelity hole: lsof exits 1 on "no matching open files"
  and shell scripts branch on it (`lsof -t … || echo none`); winlsof itself had a
  documented exit-code-capture bug (commit `3a56937`). A harness that blesses the
  wrong status defeats the point of a differential.
- **Kit change:** the verdict is now `stdout_match AND exit_match`; an exit-only
  difference DIVERGEs with a note naming both codes; `--ignore-exit` opts out for
  tools without stable statuses. Pinned with a self-test (same stdout + different
  exit → DIVERGE; `--ignore-exit` → MATCH). PLAYBOOK Phase 4 gate 2 updated.
- **Section amended:** harnesses/differential/diff_run.py (`compare`, CLI,
  self-test); PLAYBOOK · Phase 4 gate 2.

## 005. Path-scope CI, or unrelated changes make PRs look "unstable"

- **Date:** 2026-07-05
- **Codebase:** winlsof / lsof — the repo's own CI, found while landing the kit
- **What happened:** The kit's PR merged from GitHub `mergeable_state: "unstable"`.
  Nothing was failing — all checks went green — but the C project's `build.yml`
  (a full autotools `configure`/`make`/`make check`/`distcheck` on ubuntu-24.04 +
  ubuntu-22.04 + macOS) triggered on **every push/PR with no path filter**, so a
  *docs-and-scripts-only* `porting-kit/` change (and every `winlsof/` change,
  which already has its own path-scoped CI) kicked off three heavyweight C builds
  and left the PR "unstable" until they drained. Wasted CI, and a merge state that
  reads as broken when it isn't. `mergeable_state: "unstable"` means *pending or
  failing non-required checks* — not necessarily failure.
- **Kit change:** added `paths-ignore: ['porting-kit/**', 'winlsof/**']` to the
  C workflow's `push` and `pull_request` triggers (mirroring the path-scoping the
  Rust CI already used), and taught the kit's CI template to scope each
  language/subtree's workflow to its own paths. In a gradual port — where C and
  Rust coexist in one repo — an unscoped `on: [push]` runs the heavy build on
  changes it cannot affect; scope it.
- **Section amended:** harnesses/ci/porting-ci.template.yml (`on:` triggers);
  the `porting-kit-audit` skill (CI-hygiene gate). General rule for PLAYBOOK ·
  Phase 3 (skeleton/CI): scope every workflow to the paths it actually builds.

## Meta — three dry-run passes, three distinct classes of gap

Running the kit against lsof's *actual* code three times (LESSONS #2–#4) found
three different failure classes, none of which the paper Phase-3 pass (#1) caught
— because #1 was a walk of the retrospective's narrative, and these only appear
when you *execute the harnesses against the real codebase*:
- **#2 — too noisy to trust:** a scanner with 828 false positives is muted.
- **#3 — claimed but unwired:** an unsafe-fn doc gate delegated to a lint nobody
  enabled.
- **#4 — checks less than it captures:** a differential that reads exit codes but
  judges on stdout alone.
The lesson about the lessons: **a dry-run that doesn't run the tools against the
real target is theater.** All three gaps were in the *harnesses* (the kit's own
code), not the playbook prose — evidence that a kit is only as good as its tools
are exercised. `PROMPTS/90-retrospective.md` already says "run against the real
code"; these passes prove that half is where the findings live, and it is now
the emphasized half.

---

# Milestone 1 — nmap C→Rust (unprivileged TCP connect scan MVP)

The kit's second port. Target: nmap (~55k LOC C++ core + bundled C libs) → Rust,
Windows. M1 is the vertical-slice MVP: `-sT` connect scan + host discovery +
normal/`-oX`/`-oG` output, shipped at **0 `unsafe`** in the whole workspace. These
entries are the M1 retrospective; each names the harness/playbook section patched.

## 006. A scanner that reads only .c/.h reports a C++ codebase as "0 flaws"

- **Date:** 2026-07-10
- **Codebase:** nmap (C++ `.cc` core) — Phase 0 flaw scan
- **What happened:** `scan_c_flaws.py`'s file walk globbed only `.c`/`.h`. nmap's
  entire core engine is C++ (`.cc`) — `services.cc`, `output.cc`, `scan_lists.cc`,
  `TargetGroup.cc`, ~9.4k LOC of it — so the Phase-0 scan returned **nothing** and
  read as *clean*. This is the #2/#3 class made worse: not a noisy control or an
  unwired one, but a control that **silently inspects an empty set and reports
  success**. A "0 flaws" on a large, old C++ tree is almost never real; it means
  the tool didn't read the code. Widening the extension set immediately surfaced
  the real sinks — `services.cc:134/140` (`strcpy` into a `GetSystemDirectory`
  buffer, CWE-120) and `output.cc:1564/2003/2027/2048` (`sprintf`/`strcat` of
  OS-detect fields) — which then seeded `DIVERGENCES.md`.
- **Kit change:** `C_SOURCE_EXTS` now covers C++ (`.cc/.cpp/.cxx/.c++/.hpp/.hh/
  .hxx/.h++`) alongside `.c/.h`; the classic sink patterns apply to C++ verbatim.
  Pinned with a self-test that asserts `iter_c_files` yields `.cc/.cpp/.hpp`
  sources and ignores non-source files. Phase 0 prose now says: *confirm the
  scanner reads the target's actual languages before believing a low count.*
- **Section amended:** harnesses/c-flaw-scan/scan_c_flaws.py (`C_SOURCE_EXTS`,
  `iter_c_files`, `_self_test`); PLAYBOOK · Phase 0 "Do".

## 007. A case-granular differential can't judge a port that renders a subset

- **Date:** 2026-07-10
- **Codebase:** nmap — M1 `core::output` / connect-scan differential
- **What happened:** The MVP output renderer intentionally abbreviates C nmap: it
  collapses non-open ports into one `<extraports>`/`Not shown` summary where nmap
  lists each port, and omits nmap's decorative XML preamble (`<!DOCTYPE>`,
  `<scaninfo>`, `<times>`, `reason_ttl`, …). A raw `diff_run.py` over full `-oX`
  output therefore DIVERGEs on **every** case — all of it intentional. And the
  ledger can't help: `diff_run.py` is **case-granular** (whole-case MATCH/DIVERGE),
  so ledgering `mixed-open-closed` as intentional suppresses the *entire* case,
  blinding it to a real regression inside it (an open port mis-reported closed
  would still read as ledgered). The harness had no way to compare *part* of a
  case. The load-bearing question — did we get every port's **state and reason**
  right? — was undiffable as written.
- **Kit change:** documented the **canonical-projection** pattern on top of the
  existing wrapper mechanism (`--oracle`/`--rust` are arbitrary binaries):
  point each at a thin wrapper that pipes its output through a project-specific
  filter emitting only the semantic result (for a scanner: `host <addr> <status>`,
  `open <port> <proto> <reason>`, per-state counts), canonicalizing *both* the
  per-port and the aggregated representations to the same lines. A genuine
  regression then breaks the match while the intentional abbreviation stays
  invisible — and the projection is unit-testable on its own (nmap-rs's
  `project.py` has a self-test proving an open→closed regression breaks the
  match). Full output-format parity becomes its own later, format-level matrix.
- **Section amended:** PLAYBOOK · Phase 4 gate 2 (differential); the pattern is
  demonstrated in `nmap-rs/tests/differential/{project.py,run_differential.sh}`.

## 008. Miri can't run real I/O — split the pure decision from the syscall

- **Date:** 2026-07-10
- **Codebase:** nmap — M1 `sys::net` (tokio TCP connect) sanitize gate
- **What happened:** `cargo miri test` on the `sys` layer **aborted**: Miri has no
  real network/OS and cannot execute a tokio `TcpStream::connect`/`lookup_host` —
  the test dies in the `syscall` shim, not on a bug. Taken naively this reads as
  "the sanitize gate doesn't apply to `sys`," which would leave the I/O layer with
  *no* Miri coverage at all. Compounding it, the sandbox's own network is a liar:
  it completed connects to non-routable addresses and lost zero-timeout races to
  loopback, so real-network *assertions* were flaky regardless of Miri.
- **Kit change:** Phase 4 gate 4 now states Miri's real-I/O limitation and the fix
  it forces — **split the pure decision from the I/O**: factor the branch logic
  into a pure fn (`verdict(outcome, elapsed) -> ConnectResult`) that Miri fully
  covers, and gate the thin I/O tests behind `#[cfg_attr(miri, ignore = "…")]`.
  This also removed the flakiness (the deterministic `verdict` test replaced the
  environment-dependent real-connect assertions). The rule: "Miri can't run this
  test" must never silently become "this module has no Miri coverage."
- **Section amended:** PLAYBOOK · Phase 4 gate 4 (sanitize).

## 009. The six-gate model assumes every module has a fuzzable input edge

- **Date:** 2026-07-10
- **Codebase:** nmap — M1 gate closure across 9 modules
- **What happened:** The gate ladder (`ported → differential → fuzzed → sanitized →
  unsafe_audited`) is linear, and `progress.py` treats a module's status as the
  highest *consecutive* gate cleared — which implies **every** module must pass a
  fuzz gate to reach DONE. But fuzzing targets an **untrusted-input boundary**;
  M1's parser modules (`targets`, `ports`) have one, while `output` (a renderer),
  `model` (a pure data type), `timing`, and the connect driver do not. Marking a
  renderer "fuzzed" would mean fabricating a token target just to tick the column
  — theater. Separately, standing up the fuzz corpus, a real gotcha bit: running
  `cargo fuzz run <t> seeds/<t>` made libFuzzer **write every discovered input back
  into the seeds dir**, turning a curated 5-file seed set into thousands of files
  staged for commit.
- **Kit change:** (a) documented that the fuzz gate is **threat-model-scoped** —
  N/A (not a missing tick) for modules with no untrusted-input edge; a port's
  `THREAT-MODEL.md` designates which modules require it. (b) `gen_fuzz_target.sh`'s
  guidance now shows `cargo fuzz run <t> corpus/<t> seeds/<t>` (first dir writable,
  rest read-only) and warns that passing only the seeds dir balloons it.
- **Section amended:** PLAYBOOK · Phase 4 gate 3 (fuzz);
  harnesses/fuzz/gen_fuzz_target.sh (Next-steps guidance).

## Meta — M1's gaps were all "a control that inspects less than it claims"

Three of the four M1 lessons (#6, #7, #8) are the same shape as winlsof's dry-run
trio (#2–#4): a control that **passes while inspecting less than it purports to** —
a scanner reading an empty file set (#6), a differential judging whole cases it
can't decompose (#7), a sanitizer silently skipping the I/O layer (#8). The kit's
recurring failure mode is not a *missing* gate but a gate whose **coverage is
narrower than its green checkmark implies**. The standing defense — from
`PROMPTS/90-retrospective.md` step 0 — is unchanged and vindicated again: **run
every harness against the real target and eyeball what it actually inspected**, not
just whether it passed. #6 was caught exactly that way (a 0-flaw result that
couldn't be true); #7 and #8 surfaced the moment the harnesses met real nmap output
and a real socket. The single failure the kit *still* would not have prevented:
nothing forced the *insight* that the differential needed a semantic projection —
the kit made the problem visible (every case DIVERGEd) but inventing the projection
was human/agent work, the same "kit buys time, not the design" limit as #1.
