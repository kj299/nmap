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

---

# Milestone 2 — nmap C→Rust (async engine + full ultra_scan)

The connect scan cut over from a fixed prime/refill loop to nmap's real
`ultra_scan`: AIMD congestion control, adaptive RTT timeouts, retransmission, a
cross-host group window, and `--min-rate`/`--max-rate` pacing — driven by a tokio
event loop over a pure decision core. Whole workspace still **0 unsafe**; the
differential matches C nmap 7.94 on all 8 cases (incl. multi-host + rate-limited).
These entries are the M2 retrospective.

## 010. ThreadSanitizer is an unsound gate over an async runtime

- **Date:** 2026-07-18
- **Codebase:** nmap M2 — the tokio host-group scan driver (`sys::scan`)
- **What happened:** The M2 concurrency lives in a tokio driver, so the retrospective
  plan added a `tsan` CI job (`-Zsanitizer=thread -Zbuild-std`) to prove the
  fan-out/collect is race-free. It went **red in CI while every test passed**: TSan
  reported a data race inside `core::sync::atomic::compare_exchange` reached
  *through* `tokio::runtime`'s multi-threaded work-stealing scheduler — a
  false-positive in the runtime's own lock-free code, not ours. Locally it had
  passed (TSan on the scheduler is timing-dependent), so the gate was also flaky.
  The deeper problem: because *all* app code runs inside the runtime, a TSan
  suppressions file can't separate a runtime false-positive from a real app race
  (any real race's stack also contains `tokio::runtime` frames). So full-program
  TSan of an async-runtime app is not a sound race gate — it gates the runtime.
- **Kit change:** documented the caveat where the temptation arises — PLAYBOOK
  Phase 4 gate 4 and the `run_sanitizers.sh` header + a stderr warning on its
  `tsan` path. The guidance: for async-driven concurrency, prove race-freedom
  **structurally** (no shared mutable state + the compiler's `Send`/`Sync` bounds
  on `spawn`, which reject shared mutable state at compile time) plus Miri on the
  pure logic, and keep a multi-thread **liveness** test (must complete, no hang —
  the winlsof class). Reserve TSan for code that spawns OS threads over genuinely
  shared state. nmap-rs dropped the TSan job accordingly; its driver has zero
  shared mutable state by construction.
- **Section amended:** PLAYBOOK · Phase 4 gate 4; harnesses/sanitizers/
  run_sanitizers.sh (header caveat + `tsan` warning).

## 011. A differential must reject a non-file "binary" — a directory passes `-x`

- **Date:** 2026-07-18
- **Codebase:** nmap M2 — the connect-scan differential, found mid-cutover
- **What happened:** Running the oracle with `NMAP_RS=$(pwd)` (a *directory*, by a
  copy-paste slip) did not error — a directory has the execute bit, so both the
  shell wrapper's `-x` test and Python's `os.access(_, X_OK)` pass. The "binary"
  reached `exec`, produced empty output, and surfaced two layers downstream as a
  confusing XML **parse-error / spurious divergence** rather than "that's not a
  binary." Same family as #6: a check that inspects less than it claims and fails
  unhelpfully.
- **Kit change:** `diff_run.py` gained `require_binary(path, label)` (called for
  `--oracle` and `--rust` before any case runs) that requires a *regular file*
  (`os.path.isfile`, not just `X_OK`) and is executable, exiting with a clear
  message otherwise; `run_one` also now catches `IsADirectoryError`/
  `PermissionError` at exec. Pinned with self-tests (rejects a directory, rejects a
  missing path, accepts a real executable). The project's own
  `run_differential.sh` got the matching `-f && -x` guard.
- **Section amended:** harnesses/differential/diff_run.py (`require_binary`,
  `run_one`, `_self_test`).

## 012. Binary input stays bytes — a `char`-at-a-time C parser ported through `&str` re-adds a panic class

- **Date:** 2026-07-19
- **Codebase:** nmap M3 — `core::probedb`, the `nmap-service-probes` parser
- **What happened:** The C reads a probe's regex delimiter one byte at a time
  (`*p`) and never assumes UTF-8 — the file (and any `--versiondb` override) is
  binary. The Rust port, reaching for ergonomic string handling, read the delimiter
  as `c as char`, computed `len_utf8()` from it, and sliced the pattern at that
  offset. On a **multibyte lead byte** the char was mis-decoded, `len_utf8` was
  mis-sized, and the slice landed **mid-codepoint → panic** — a crash the
  byte-oriented C could not have. CI fuzz found it (and, per #015, only two modules
  later). The same UTF-8-on-binary reflex showed up twice more in M3, caught in
  design review: the matcher *must* be `regex::bytes` (Unicode off) because banners
  are binary, and `fancy-regex` being `&str`-only forced an explicit latin-1
  bijection for the backtracking minority.
- **Kit change:** PLAYBOOK Phase 4 gate 1 now states the rule directly — a C
  byte-at-a-time parser ports over `&[u8]`, not `&str`/`chars()`; `&str` is for
  *proven* text and only via `from_utf8` returning an error, never slice-and-hope.
  The pattern generalizes hard to M4 (every raw-packet parser is binary), which is
  why it is stated as a porting rule, not a probedb footnote.
- **Section amended:** PLAYBOOK · Phase 4 gate 1 (Port).

## 013. A signature-DB-driven differential must compare findings, not data-file lookups

- **Date:** 2026-07-19
- **Codebase:** nmap M3 — the `-sV` differential (`tests/differential/project.py`)
- **What happened:** `-sV` output carries a service *name* plus a *product/version*
  string, all derived from `nmap-service-probes`. The obvious differential —
  project the whole service line and diff it against C nmap — would have compared
  **product/version strings that are a function of each tool's shipped DB version**,
  not of the port's correctness. C nmap 7.94 and nmap-rs ship different probe DBs,
  so the gate would flag a "divergence" on every version-detected port: a false
  failure that trains you to `--ignore` the case, blinding it to real regressions
  (the #007 family — a differential that judges the wrong thing). This is
  structurally certain to recur at M5 (`nmap-os-db`, `nmap-mac-prefixes`).
- **Kit change:** `project.py` projects only the version-independent finding —
  the detected service *name* on a `method="probed"` port — and explicitly excludes
  product/version (pinned by four self-test checks incl. "two tools agree on service
  despite differing product versions"). PLAYBOOK Phase 4 gate 2 generalizes it: the
  differential compares *what the port computes*; anything the port merely *looks up*
  from a versioned DB belongs in a golden test against a fixed snapshot, not the
  oracle.
- **Section amended:** PLAYBOOK · Phase 4 gate 2 (Differential); the port's
  `tests/differential/project.py` (service-name projection + self-tests).

## 014. A defensive catch-all `break` in a scheduler loop is a liveness bug

- **Date:** 2026-07-19
- **Codebase:** nmap M2 rate-limited group loop (`sys::scan`), surfaced by an M3
  module-5 test
- **What happened:** The concurrent group driver had a `match` on the scheduler
  state ending in `_ => break` — a "if something unexpected happens, stop" guard.
  Under a timing skew between `launch_ready`'s rate check and the outer loop's rate
  check, the loop hit that arm **with ports still unscanned** and abandoned 2 of 8
  as neither open nor closed. It is not UB, not a panic, and not a hang — so no
  sanitizer sees it; only the multi-thread **liveness** test prescribed by #010
  ("every unit of work reaches a terminal state") caught it, one milestone after
  the bug shipped. The defensive `break` — meant to be safe — was the failure.
- **Kit change:** PLAYBOOK Phase 4 gate 4 now names the class: in a work-scheduling
  loop the safe default with work outstanding is **retry/continue (re-poll,
  sleep-then-continue), never `break`**; reserve `break` for a proven-terminal
  condition (queue empty), not for "confused." Reinforces #010's standing
  prescription to keep a liveness test — here it is what paid out.
- **Section amended:** PLAYBOOK · Phase 4 gate 4 (Sanitize / liveness).

## 015. A time-bounded fuzz smoke is a floor, not a proof — seed what it finds late

- **Date:** 2026-07-19
- **Codebase:** nmap M3 — the `probedb` fuzz target vs the 60s CI smoke
- **What happened:** The multibyte-delimiter panic (#012) lived in `probedb`, which
  **passed its own module's 60s fuzz smoke and merged clean**. The crash only
  surfaced on a *later, unrelated* module's fuzz run, because a 60s libFuzzer budget
  reaches a low-probability branch nondeterministically. Reading the smoke's green
  tick as "this parser is panic-free" is the trap — it means "no panic found in 60s
  this run." This is not a hole the kit can close (exhaustive fuzzing isn't on the
  table); the lesson is what to *do* about the residual.
- **Kit change:** PLAYBOOK Phase 4 gate 3 now frames the smoke as a floor: when a
  crash surfaces (whenever it surfaces), **commit the exact input as a named seed**
  so it is deterministically re-checked forever after (nmap did — the CI crash input
  is a committed `probedb` seed), and give untrusted-boundary parser modules a
  budget beyond the 60s smoke at least once per milestone. The seed corpus is the
  port's accumulating regression memory.
- **Section amended:** PLAYBOOK · Phase 4 gate 3 (Fuzz).

## 016. Pin the toolchain — a floating `@stable` in CI fails PRs on a version you never ran

- **Date:** 2026-07-21
- **Codebase:** nmap M4 — raw-packet infrastructure (CI `dtolnay/rust-toolchain@stable`)
- **What happened:** Two separate M4 slices went green locally and **red in CI on a
  formatting/lint rule the author never saw**: module 4 (`headers::tcp`) hit a
  rustfmt reflow, module 12 (`recv_validate`) a new `collapsible_match` clippy lint.
  Both because CI installed `dtolnay/rust-toolchain@stable`, which floats to whatever
  stable is current the day the job runs, while local dev sat on an older stable. The
  M3 retrospective had already *noted* "pin a rust-toolchain.toml" as a to-do; it was
  never wired, so the same skew recurred a milestone later. A CI-only fmt/clippy
  failure is pure friction — the code is correct, the machine disagrees with itself.
- **Kit change:** `skeleton/` now ships a **`rust-toolchain.toml` pinning an exact
  stable** (`channel`, `components = [clippy, rustfmt]`); `rustup` reads it for every
  in-tree `cargo` call, so local `cargo fmt`/`clippy` == CI. The CI template's stable
  jobs switched from `@stable` to `@master` + an explicit pinned `toolchain:` that
  reads the file. Nightly gates (miri, fuzz) stay `@nightly` — `cargo +nightly`
  overrides the pin. Bump the pin deliberately, in its own PR, never by drift.
- **Second-order catch (found by this very patch):** a `rust-toolchain.toml` is a
  *directory override*, which **outranks a `rustup default nightly`**. So a
  nightly-only CI job that leans on the *default* being nightly — the fuzz gate ran
  bare `cargo fuzz run`, not `cargo +nightly fuzz run` — breaks the instant the pin
  lands: cargo-fuzz's inner build picks the pinned stable and dies on
  `-Zsanitizer=address` ("`Z` is only accepted on the nightly compiler"). The PR that
  added the pin caught its own regression (#49 fuzz failure). Fix: every nightly gate
  selects the toolchain **explicitly** (`cargo +nightly …`, which sets
  `RUSTUP_TOOLCHAIN` and beats the directory override) rather than relying on the
  rustup default; the template's fuzz job and the skeleton toml comment now say so.
- **Section amended:** `skeleton/rust-toolchain.toml` (new); `harnesses/ci/porting-ci.template.yml` (stable pin + `+nightly` on the fuzz gate); PLAYBOOK · Phase 3 preflight.

## 017. A liveness spike must gate on *teardown*, and its stand-in must match how the real API blocks

- **Date:** 2026-07-21
- **Codebase:** nmap M4 — `sys::capture` (pcap-in-async, spike `SPIKES.md` M4-1)
- **What happened:** The top M4 hazard — bridging a no-readiness-fd pcap source into
  tokio — was correctly spiked *before* scheduling, and its written decision gate
  (latency < 2 ms, no busy-spin, no readiness fd) was met by a **BlockingThread →
  channel** design with an RAII `Drop`-join. It still shipped a **shutdown
  deadlock**: a blocking capture thread against an *idle* link cannot be woken for
  its join, so `Drop` hung forever. Two blind spots combined: (a) the gate measured
  the *hot path* and never named *teardown*, the one state a throughput test can't
  enter; (b) the spike's `std`-socket stand-in silently had cancellation the real API
  lacks (libpcap's blocking read ignores its timeout on an idle link). Worse, the
  capture module passed all six gates against a **mock** source and merged (#47) — the
  hang lived in the *real* source's `Drop` path, which the unprivileged differential
  (the kit's liveness backstop) structurally cannot reach, and only surfaced two
  slices later in a root-only e2e (#48). Fix: `setnonblock` + a bounded idle poll
  (essentially the PollTask fallback the spike had rejected on latency).
- **Kit change:** the spike-and-gate ritual now **requires a teardown criterion**
  ("prove it can be stopped while idle, cleanly, within a bounded time") for any
  resource-holding/blocking-thread design, and **requires the stand-in to reproduce
  the property under test** — for a liveness spike, how the call blocks *and unblocks*
  (a `std` `recv` is not a model of `pcap_next_ex`). Gate 4 adds: a `sys` module that
  owns a blocking OS resource needs a `#[ignore]` **root-only real-resource teardown
  test in its own slice** — a mock proves the plumbing, never the teardown of what it
  stands in for.
- **Section amended:** PLAYBOOK · Phase 4 (spike-and-gate ritual; gate 4 liveness).

## 018. The safest `unsafe` is the one you never write — classify "is there a safe crate?" at Phase 0

- **Date:** 2026-07-21
- **Codebase:** nmap M4 — `sys::netif`/`capture`/`rawio` (the "unsafe lives here" milestone)
- **What happened:** M4 was scoped as the milestone where hand-written FFI `unsafe`
  finally lands (interface enumeration, raw send, capture) and budgeted accordingly.
  A **mid-milestone review — prompted by the user, not the kit** — found that
  `netdev`, `socket2`, and `pcap` already wrap that exact surface safely and are
  maintained/audit-clean, so the default build shipped with **0 first-party `unsafe`**
  (11 documented blocks, all in an optional `getifaddrs` escape hatch that is off by
  default). The right outcome, reached by luck of a review rather than by process:
  nothing in Phase 0 asked "does a vetted safe crate already cover this?" so the
  default assumption was hand-FFI.
- **Kit change:** Phase 0's FFI classification gains a **fourth property per FFI item
  — "does a vetted, maintained, safe crate wrap it?"** — and if yes, that crate is the
  **default backend**, hand-FFI a feature-gated audited escape hatch with a
  cross-check test (the **Option-C pattern**, now in `ARCHITECTURE-TEMPLATE.md`).
  A wrapper crate that clears the supply-chain gate and removes first-party `unsafe`
  is a net safety win, not a new liability — so this is classified up front, not
  discovered after the `unsafe` is written.
- **Section amended:** PLAYBOOK · Phase 0 (Do); `ARCHITECTURE-TEMPLATE.md` (conventions).

## 019. An oracle that restates the C proves only self-consistency — and a lesson written in the port's backlog never reaches the kit

- **Date:** 2026-08-30
- **Codebase:** nmap — M5 `core::fpmodel` / `core::fp6::vectorize` (IPv6 OS classifier)
- **What happened:** The `apply_scale` oracle was **retyped** from nmap's C rather than
  pasted, and lost the C's `if (val < 0) continue;` guard — under a comment claiming it
  was verbatim. The differential then passed **bit-exact while both sides were wrong**,
  and the fidelity bug shipped in #70. It surfaced only when the next module
  (`fp6::vectorize`) made the sentinel's meaning matter, and was fixed in #71 — a
  standalone "the real fix" commit, the highest-signal artifact in the whole milestone.
  A gate that compares the port against a *paraphrase* of the C is not a gate.
  **The compounding failure is worse than the bug:** the team did write the lesson
  down — in `nmap-rs/BACKLOG.md`, the port's own file — where it sat for nine PRs and
  never reached `porting-kit/LESSONS.md`. A lesson recorded outside the kit does not
  compound; the next port inherits nothing. Retrospectives must sweep the port's own
  notes for lessons already learned locally, not just reconstruct from git.
- **Kit change:** PLAYBOOK Phase 2 gains "**an oracle COPIES the C — it never restates
  it**": paste the function and diff it against source; where impractical (headers,
  globals, member state), state in a comment exactly which *inputs* were substituted
  and that no logic was. Mirrored into `porting-kit-oracle` (step 5a). The
  retrospective skill now says to sweep the port's own backlog/notes for
  locally-recorded lessons before reconstructing from history.
- **Section amended:** PLAYBOOK · Phase 2 (Do, Exit criteria); `skills/porting-kit-oracle/SKILL.md` step 5a; `skills/porting-kit-retrospective/SKILL.md` step 1.

## 020. The Phase-0 flaw scanner finds API misuse, not guard placement — ASan the pasted oracle over *truncated* input

- **Date:** 2026-08-30
- **Codebase:** nmap — M5 `core::ndp` (IPv6 neighbor discovery, `libnetutil/netutil.cc`)
- **What happened:** M5 found two real, remotely-reachable defects in nmap's neighbor
  discovery: `read_ns_reply_pcap` bounds-checks `caplen` inside an `if` and then does a
  16-byte `memcpy` of the target address **outside** that `if` (a heap overread any
  on-link host can trigger with a truncated ICMPv6 type-136 frame); and `doND` passes
  `has_mac` to that function and **never reads it**, so a legal advertisement carrying
  no link-layer option leaves the caller's MAC buffer uninitialised and still reports
  success — `getNextHopMAC` then caches those stack bytes as a next hop.
  `scan_c_flaws.py` run on that exact file reports **2 format-string hits and neither
  defect**. Both are structurally outside its model: one is a relationship between two
  lines, the other a dataflow fact. A `memcpy`-with-constant-size rule was measured as
  a candidate and **rejected** — 155 hits across nmap's C tree, which is precisely the
  noise that buried real findings in LESSONS #2. What actually found them was pasting
  the C verbatim for the oracle (which forces line-by-line reading) and then compiling
  that pasted C under AddressSanitizer with **truncated** input, which reported
  `heap-buffer-overflow ... READ of size 16 ... 4 bytes after a 58-byte region`.
  Critically, the *curated* corpus would not have tripped it: a corpus is built to stay
  inside the C's defined behavior, so the truncation sweep has to be written on purpose.
- **Kit change:** PLAYBOOK Phase 2 gains "**sanitize the pasted C, and feed it truncated
  input**" plus "record no golden where the C is undefined — exclude the region, say so
  in the generator, and cover it from the Rust side with a test and fuzz seeds at each
  boundary." Mirrored into `porting-kit-oracle` (steps 5b, 5c). `scan_c_flaws.py` gains
  a **"What this CANNOT find"** section naming both classes with this evidence, so a
  clean scan is read as "no API-misuse flaw found", never "this file is safe".
- **Section amended:** PLAYBOOK · Phase 2 (Do, Exit criteria); `harnesses/c-flaw-scan/scan_c_flaws.py` (docstring); `skills/porting-kit-oracle/SKILL.md` steps 5b–5c.

## 021. "Keep the tracker current" was a habit, not a control — and the retrospective depends on it

- **Date:** 2026-08-30
- **Codebase:** nmap — M5 (whole milestone)
- **What happened:** `CLAUDE.md` says "keep `progress.json` current". It rotted. M5
  added ten modules (`fpmodel`, `fp6`, `fp6_match`, `build6`, `ndp`, `osscan`,
  `fpengine`, `sys::ndp`, `sys::osscan`, …) and **not one** reached the table; finished
  modules still read `differential` long after they were fuzzed and audited. Twelve of
  51 shipped modules were untracked. This is LESSONS #003 ("a delegated control that
  nothing enforces is not a control") turned on the kit's own bookkeeping — and it bites
  hardest *here*, because the retrospective procedure names `progress.json` as a primary
  artifact to reconstruct from. A stale tracker does not merely fail to help the review
  that is supposed to catch drift; it misleads it.
- **Kit change:** `progress.py` gains a **`drift --src DIR ...`** subcommand that parses
  every `pub mod` from each crate's `lib.rs` and **exits 1** on any shipped module absent
  from the table (absorbing both real-world naming conventions: sub-module-instead-of-
  parent, and an omitted crate prefix). Wired into the CI template and named in the
  module loop's exit criteria, so the table cannot silently rot. Its `--file`-before-
  subcommand usage line — which contradicted its own argparse layout and cost a failed
  invocation during this retrospective — is fixed.
- **Section amended:** `harnesses/progress/progress.py` (new `drift` cmd + usage fix); PLAYBOOK · Phase 4 (exit criteria); `CLAUDE.md` (working notes); README harness table.

## 022. Sixteen references to `make check-kit`, and no Makefile — the integrity checker validated paths but not commands

- **Date:** 2026-08-30
- **Codebase:** nmap — M5 retrospective (the kit itself)
- **What happened:** Step 0 of the retrospective skill says to run the harnesses before
  reading any prose. The very first command it prescribes — `make -C porting-kit
  check-kit` — failed with *"No rule to make target"*. **There was no Makefile in the
  kit at all**, and never had been, while `check-kit` was cited in sixteen places:
  README, `CLAUDE.md`, `PLAYBOOK.md`, `OPERATING-GUIDE.md`, both PROMPTS, and all six
  skills. Every harness had a working `--self-test`; nothing ran them together, so the
  kit's advertised self-check had never once executed. `check_skills.py` — the control
  whose entire job is catching this drift, and which CLAUDE.md claims "hard-fails on a
  dangling reference" — passed clean, because it validated `porting-kit/<path>`
  references and **not the command it was itself wired into**.
- **Kit change:** Added `porting-kit/Makefile` with a real `check-kit` (every python
  harness's `--self-test`, `bash -n` over the shell harnesses, then the skills check;
  python3 + bash only, no toolchain, so a vendoring repo can actually run it).
  `check_skills.py` gains check 4: **every `make <target>` a skill cites must exist in
  the kit's Makefile** — scanning code spans only, since a first pass flagged the prose
  "make the edits" as an invocation. Verified by removing the Makefile and watching all
  six skills fail, then restoring it.
- **Section amended:** new `porting-kit/Makefile`; `skills/check_skills.py` (check 4 + self-tests).

## 023. The fuzz crate is outside the workspace lint sweep — compile it before fuzzing it, in its own step

- **Date:** 2026-08-30
- **Codebase:** nmap — M5, completing IPv4 `-O`
- **What happened:** `cargo clippy --workspace --all-targets` does **not** build `fuzz/`:
  it is a separate crate, compiled only by `cargo +nightly fuzz build`. So adding a
  field to a type a fuzz target constructs passes fmt, all three clippy configurations,
  both feature test suites and Miri — and then fails the fuzz job on a plain compile
  error. It happened **three times**: once on #69 (a field on `osscan::Report`), then
  twice in consecutive PRs while finishing `-O` (a field on `SeqReport`, each time).
  Every occurrence was caught locally by the mandatory build sweep, so none reached a
  reviewer — but in CI the error is buried *inside* the ~35-minute smoke job, surfacing
  only after the first target has already fuzzed for its full 60 seconds.
  The note lived in the port's own `BACKLOG.md` from the first occurrence and never
  reached the kit, which is LESSONS #019's failure repeating: a lesson recorded outside
  the kit does not compound, and the next two occurrences were the price.
- **Kit change:** the CI template's fuzz job gains a **`fuzz targets compile` step that
  runs `cargo +nightly fuzz build` (no target name — builds them all in one invocation,
  sharing codegen) before any target is run**. A compile break now fails the job in
  about a minute instead of tens of minutes, and as its own named step rather than
  buried in a fuzzing log. The smoke run becomes a separate named step so the two
  failure modes are told apart at a glance in the job list.
- **Section amended:** `harnesses/ci/porting-ci.template.yml` (fuzz-smoke job).

## 024. A per-target time-boxed gate is a job that grows without anyone deciding to grow it

- **Date:** 2026-08-30
- **Codebase:** nmap — CI fuzz job
- **What happened:** The fuzz smoke runs each target for 60 seconds. That reads as a
  fixed cost, but it is per *target*, and targets accumulate one per ported module —
  nmap reached **38 of them**, so the job quietly grew to ~38 minutes of pure fuzzing
  plus toolchain overhead. Nobody chose a 45-minute job; it arrived one module at a
  time. The gate was still correct, just slow enough that a red result came back long
  after the developer had moved on, which is how a control stops being used well.
- **Kit change:** the CI template's fuzz job is **sharded across a matrix**
  (`fail-fast: false`, so one shard's crash does not cancel the others and every
  failure is visible in one run). Targets are split round-robin by line number with
  the divisor taken from **`strategy.job-total`**, so the split follows the matrix
  automatically: changing the shard count is a one-line edit and no target can be
  silently dropped or run twice. Wall-clock becomes a slice plus fixed overhead
  instead of the whole battery.
  Two things worth knowing when tuning it: each shard still runs `cargo fuzz build`
  for *all* targets (one invocation, shared codegen) so it stays self-contained with
  no artifact plumbing and keeps the fail-fast compile check of #023; and past roughly
  6–8 shards the per-job overhead (checkout, `cargo install cargo-fuzz`, build)
  dominates, so more shards stop helping.
- **Section amended:** `harnesses/ci/porting-ci.template.yml` (fuzz-smoke job).

## 025. `push` + `pull_request` without a branch filter runs the whole pipeline twice, forever, silently

- **Date:** 2026-08-30
- **Codebase:** nmap — CI workflow (and the kit's own template, which had it worse)
- **What happened:** The workflow triggered on `push` (branches `master` **and**
  `claude/**`) *and* on `pull_request`. Every PR from a topic branch therefore ran the
  entire safety pipeline **twice** — six jobs became twelve checks. It shipped that way
  for five milestones without being noticed, because "12 checks" looked like a plausible
  number and was mistaken (repeatedly, in this session's own reporting) for *six jobs
  across two feature configurations* — which the workflow does not even do. The
  duplication only became visible when sharding the fuzz job turned 12 checks into 22
  and the runner pool started queueing. The kit's template had the same bug and worse:
  its `push` had no branch filter at all, so it fired on every push to every branch.
  Cost: 100% of CI, doubled, for five milestones.
- **Kit change:** the template scopes `push` to the **default branch only**
  (`[main, master]`), leaving `pull_request` to cover topic branches — which it does
  better anyway, testing the merge commit rather than the branch head in isolation, and
  re-running on force-push via the default `synchronize` activity. Also adds a
  **`concurrency` group** that supersedes a PR's in-flight run when it is force-pushed,
  with `cancel-in-progress` expression-gated to pull requests only so a default-branch
  run is never cancelled (an intermediate merge commit's run is the only evidence that
  commit was green). Trade-off recorded in the template comment: a topic branch pushed
  with no open PR is not built until a PR exists.
  The general lesson beyond the fix: **count your checks against your jobs.** A check
  count that is a clean multiple of the job count is a duplicate-trigger smell, and it
  hides in plain sight because it looks like a matrix.
- **Section amended:** `harnesses/ci/porting-ci.template.yml` (`on:` triggers, new `concurrency`).

## 026. A cfg-gated module is invisible to every default-feature gate — including the gates aimed at it

- **Date:** 2026-09-12
- **Codebase:** nmap — M7.1, closing the `sys` coverage gap
- **What happened:** The kit's whole unsafe strategy is *quarantine*: push every
  `unsafe` into one crate, wrap it in audited safe functions, and point the safety
  gates at it. nmap did that well — all 11 `unsafe` blocks in a 39,000-line port live
  in one file, `crates/sys/src/netif/ffi.rs`, a `getifaddrs(3)` linked-list walk. It
  was also, correctly by the kit's own Option-C advice, put behind a non-default
  feature (`raw-ffi`) so the default build carries a safe `netdev` backend instead.
  Those two good decisions combined into a blind spot nobody chose. A cfg-gated module
  is not compiled unless something asks for the feature, and **not one gate asked**:
  - `cargo test --all` ran 93 tests. With `--features raw-ffi` it runs 94. The 94th is
    the only test in the project that executes any `unsafe`, and no CI job ran it.
  - `cargo clippy --all-targets` mentioned `ffi.rs` **0 times** — so the workflow's
    `-D clippy::undocumented_unsafe_blocks`, escalated to a hard error specifically to
    police this code, was pointed at a file clippy never compiled.
  - `miri` runs **0** of those tests even with the feature enabled, because the module
    is `#[cfg(all(test, not(miri)))]`. That cfg is *right* — Miri cannot call a foreign
    function — but it means Miri can never be the gate for the one thing it was
    credited with covering.
  - `msrv`'s `cargo check --all-features` type-checked it. Nothing was codegen'd, and
    nothing ran.
  - `unsafe-audit` greps source text, so it alone saw the file. Text only.

  So the port's entire residual unsafe surface was type-checked once and grepped once,
  and had never been executed under any dynamic check. Nothing was broken — ASan over
  it passes clean, 94/94, leak detection included — but that was luck confirmed after
  the fact, not a property anything had been testing. The milestone analysis that
  opened M7 recorded the symptom as "`sys` has 0 fuzz targets" and credited Miri with
  partial coverage; both were wrong in the same direction, and the reason is that
  **coverage was counted by reading the job list rather than by running the jobs and
  counting what executed.**
- **Kit change:** two edits, one narrow and one general.
  1. The CI template's lint and test steps take **`--all-features`**, and the template
     comment says why in the form "this flag is what makes the unsafe lints mean
     anything". A safety lint that cannot compile its target is worse than no lint,
     because it reports green.
  2. The Phase-4 gate checklist gains a step: **for each declared gate, name the
     specific line of code it executes, and prove it by making that code fail.** A
     gate's worth is what it runs, not what its name claims. The cheap version of this
     proof is a count — 93 vs 94 tests — and it takes one command.
  Also recorded in the template: **rustc has no UndefinedBehaviorSanitizer.**
  `-Zsanitizer` accepts `address`, `leak`, `memory`, `thread`, `cfi` and friends;
  `undefined` is rejected outright. "ASan/UBSan" is a C/C++ pairing, and carrying it
  into a Rust kit document promises a gate that cannot be built — this port's own M7
  analysis had it in a table before anyone tried to run it.
- **Section amended:** `harnesses/ci/porting-ci.template.yml` (lint/test feature flags,
  new ASan job, UBSan note), `SECURITY-CHECKLIST.md` (Phase-4 gate-verification step).

## 027. A progress gate that reports GREEN while seeing two-thirds of the tree

- **Date:** 2026-09-12
- **Codebase:** nmap — M7.2, reconciling the tracker before cutover
- **What happened:** LESSONS #021 added `progress.py drift` because "keep the table
  current" was a habit and habits rot. The control was right; three things made it
  worthless anyway, and each of them failed *green*.
  1. **The port never wired it.** The kit template carries the drift step; nmap's
     workflow was written separately and simply did not have it. Five milestones, no
     check. A control that exists in the template and not in the workflow is not a
     control.
  2. **The harness only read `lib.rs`.** Sub-modules declared in a `mod.rs` were
     outside the walk entirely — in nmap that was **25 modules** (`headers::*`,
     `osdb::*`, `osprobe::*`, `nse::*`, `sigstore::*`), which is where a maturing port
     puts most of its code. It reported "56 shipped modules, 0 untracked" and both
     numbers were wrong. One genuinely missing module, `core::osprobe::demux`, was
     also the only byte parser in the port with no fuzz target (#026 / M7.1) — the two
     blind spots had quietly overlapped on the same code.
  3. **Coverage was inferred, never recorded.** The M7 analysis stated "19 modules are
     covered but unrecorded" in a milestone document used for a go/no-go decision. The
     real number was **14**. Six were credited because a fuzz target shared a *name*
     with the module — `sys::ndp` counted against `ndp_advert`, which fuzzes
     `core::ndp`; the sys module is an I/O driver that parses nothing. One was missed
     the other way: `core::osdb::parse` *is* covered, by a target importing
     `osdb::model::FingerPrintDb`, because an inherent impl need not live in the module
     its type is declared in. **No heuristic over import paths gets both directions
     right.** Write the mapping down.
- **Kit change:**
  - `shipped_modules()` walks `mod.rs` as well as `lib.rs` and builds the full
    `crate::a::b` path. nmap went from 56 modules seen to 81.
  - New `exempt MODULE GATE --reason ...`, `cover MODULE --targets ...`, and an
    `audit` subcommand that hard-fails on an exemption without a real reason, an
    exemption naming an unknown module or gate, a coverage claim naming a
    non-existent fuzz target, and the contradiction of a module being exempt from
    `fuzzed` while also claiming fuzz coverage. Wired into the template next to
    `drift`.
  - **No blanket `n/a` module state, deliberately.** A module is not inapplicable; a
    specific *gate* is inapplicable to it, and collapsing that loses which gates still
    apply — a scheduler exempt from fuzzing must still be differential-clean and
    unsafe-audited. And one escape hatch broad enough to silence a module is broad
    enough to silence the module you should have looked harder at: nmap's `output`
    renders attacker-controlled hostnames and service banners into XML, sits on the
    same "not really a parser" list as the schedulers, and is the one entry on it that
    genuinely needs a fuzz target. It is left un-exempt and visibly short of the gate,
    which is the tracker doing its job.
  - `show` renders an exempt gate as `[-]`, never `[x]`, and counts it separately. An
    exemption is a recorded argument, not evidence of a pass, and must not read like
    one at a glance.
- **The second lesson, which cost a real bug in this very change:** while adding the
  `[-]` marker the `[x]` branch was dropped, so the table rendered **every gate of
  every module as unticked** — and the whole self-test suite stayed green, because
  every render assertion in it checked for `DONE`, a count, or the new `[-]`, and not
  one asserted the marker that had been there since the beginning. **A test suite
  tends to assert the feature being added and to leave the thing it replaced
  unasserted.** When you change how something is rendered or computed, add an
  assertion for the *old* behaviour you intend to keep, not only the new one. Three
  such assertions are now in the self-test.
- **Section amended:** `harnesses/progress/progress.py` (mod.rs walk, exempt/cover/
  audit, `[-]` rendering, self-test), `harnesses/ci/porting-ci.template.yml` (audit
  step).

## 028. A shared test fixture with an undrained queue makes adding a case break an unrelated one

- **Date:** 2026-09-20
- **Codebase:** nmap — M7.7, the `-T` timing group
- **What happened:** The differential harness binds loopback listeners to stand in
  for "open" ports, then runs every matrix case against that one fixture. The
  listeners for the plain state-fidelity ports were `listen(16)` with **no accept
  loop at all** — nothing ever drained the queue. That is fine while the matrix is
  small. It stops being fine at the 17th connection to a port, which is silently
  dropped rather than answered.
  M7.7 added four cases, one of which passes `--max-retries 2`. At case 14 of 16 the
  backlog was exhausted, that case gave up after three attempts where the default
  eleven would have papered over it, and the harness reported a port that is plainly
  open as `filtered`. **Deterministically** — it reproduced on every run, which is
  what made it look like a real fidelity bug in the port.
  It was not. The tell was that it would not reproduce against a hand-rolled
  listener with the same options, only inside the matrix — which is the signature of
  a *shared* resource, not of the code under test.
- **Cost:** About half an hour, all of it spent suspecting the wrong thing: the
  newly written timing code, in a milestone whose whole subject is timeouts and
  retries. A retry-sensitive case failing in a retry-related milestone is about as
  convincing a false positive as this project has produced.
- **Root cause:** The fixture encoded "this port is open" as *a socket exists*, when
  what the scanner actually observes is *a SYN gets a SYN-ACK*. Those agree only
  while the accept queue has room. The fixture's meaning therefore depended on how
  many cases had run before — a hidden coupling between cases that nothing in the
  matrix expressed.
- **Fix:** Give every listener a drain thread (`accept()` then immediate `close()`)
  and raise the backlog. The fixture's meaning is now independent of how many cases
  precede a case, so adding one can never again break another.
- **Kit change:** `harnesses/differential/README.md` — a shared fixture must be
  **stateless across cases**. Anything with a bounded queue (listen backlogs, thread
  pools, connection limits, temp-file quotas) has to be drained or reset between
  cases, or the matrix acquires an ordering dependency that nobody wrote down and
  that only shows up as a mysterious failure in whichever case is most sensitive.
  The generalisation worth keeping: **when a differential case fails deterministically
  but will not reproduce outside the harness, suspect the harness's shared state
  before the code under test.** Deterministic is not the same as caused-by-the-diff.

## 029. A differential against a data-driven tool must pin the DATA, not just the binary

- **Date:** 2026-09-20
- **Codebase:** nmap — M7.8, `--top-ports` / `--port-ratio` / `-F`
- **What happened:** `--top-ports N` returns the N most common ports according to
  ratios in the `nmap-services` data file. To check the port's ranking, the exact
  sets C selects were captured from the real binary with `--packet-trace` — a good
  oracle, better than transcribing `gettoppts`. Ten values of N were compared.
  Eight matched exactly. **N=500 and N=1000 did not**, each off by two ports, and
  the disagreeing ports all sat at identical ratios — the signature of a
  tie-break bug. C sorts a `std::list` with `a.ratio > b.ratio` and
  `std::list::sort` is stable, so ties keep file order; the Rust used a stable
  sort too, so the hunt was on for how the orders had come apart.
  They had not. The installed `nmap` reads `/usr/share/nmap/nmap-services`; the
  port reads the one in the source tree. **They are different files.** `wsman`
  (5985/tcp) carries ratio 0.000076 in one and 0.000380 in the other, which moves
  it across the N=500 boundary. Re-running the comparison with both sides on the
  same file: ten of ten exact, no tie-break bug, nothing to fix.
- **Cost:** Maybe twenty minutes, and it came within one edit of "fixing" a
  correct stable sort into an incorrect one to match golden data that was never
  comparable. That is the expensive failure mode here — not the lost time, but a
  differential that argues you into breaking working code.
- **Root cause:** The oracle was pinned (a specific binary) and the *input matrix*
  was pinned (specific arguments), but the tool's third input — its data files —
  was left to whatever the binary happened to find. For a data-driven tool that is
  most of its behaviour. Nothing in the harness expressed the dependency, so
  nothing could flag it.
- **Fix:** Generate every golden with the data file pinned (`nmap --datadir
  <repo>`), pass the same flag in the differential harness's oracle wrapper so
  every case compares like with like, and say in the test module why the flag is
  there — the next person to regenerate goldens will not otherwise know.
- **Coda, the same day:** the *integration* tests for the same feature walked
  into the other half of this. They run the built binary, which searches for
  `nmap-services` and falls back to `/usr/share/nmap/nmap-services`. On this
  machine, with nmap installed, they read the installed database — passing while
  comparing against goldens from a different file. On a CI runner without nmap
  they found nothing at all, fell back to a 1-1024 port sweep, and reported 1024
  ports for `--top-ports 10`. Pinning the golden generation was necessary and
  not sufficient: **the thing under test has to be pinned to the same data as
  the oracle**, which for a binary means setting its data-directory variable in
  the test harness, not trusting its search path.
- **Kit change:** `harnesses/differential/diff_run.py` — before trusting a
  divergence, confirm both sides read the same data files (databases, signature
  files, dictionaries, locale, timezone), and pin the *rewrite's* lookup as
  explicitly as the oracle's. A search path that ends in a system location is a
  silent dependency on the developer's machine. The tell that saves the time:
  **a divergence that appears only past some threshold — the tail of a ranking,
  the long inputs, the rare branch — is more often a data mismatch than a logic
  bug**, because shared data usually agrees on the common cases and diverges at
  the margins. Pin the data, re-run, and only then start reading code.

## 030. Running a gate scoped to the crate you changed is not running the gate

- **Date:** 2026-09-20
- **Codebase:** nmap — M7.8, port selection
- **What happened:** M7.8 added unit tests inside the CLI binary crate that read
  golden files from disk. Every other filesystem- or process-touching test in the
  repository carries `#![cfg(not(miri))]`, because Miri's isolation blocks `open`.
  These did not, and CI's Miri job went red on a PR that had passed every check
  run locally.
  The local Miri run had been `cargo +nightly miri test -p nmap-core <filter>` —
  scoped to the crate the previous milestone touched, because that is the crate
  whose module was new and because a full Miri run takes many minutes. CI runs
  `cargo +nightly miri test`, unscoped. The habit of narrowing a slow gate to
  "the part I changed" is exactly what let a test in a *different* crate reach CI
  unchecked.
- **Cost:** One red CI cycle and one extra push. Cheap this time, and only because
  the failure was loud. A gate narrowed for speed fails silently far more often
  than it fails loudly.
- **Root cause:** Two different commands were both called "running Miri". The
  scoped one is a fast inner-loop check; the unscoped one is the gate. Nothing
  distinguished them, so the fast one felt like the gate had run.
- **Fix:** Gate the new module with `#[cfg(all(test, not(miri)))]`, and say in the
  comment *why* the guard is there — naming the trap ("the CI job runs
  `cargo miri test` over the whole workspace while it is tempting to run it
  locally scoped to the crate you just changed") so the next person adding a
  filesystem test in a new crate sees it.
- **Kit change:** `PLAYBOOK.md` Phase 4 — **before a PR, run each gate with the
  exact command CI runs, not a narrowed version of it.** Narrowing for the inner
  loop is correct and fast; the pre-push run is not the inner loop. The general
  shape, of which this is the third instance in this port (see #023, #026):
  *a gate you have customised for convenience is a different gate.* `--all`,
  `--all-features`, and an unscoped package selector are part of the gate's
  identity, not decoration on it.

## 031. A ledgered "intentional abbreviation" is a divergence with an expiry date nobody set

- **Date:** 2026-09-20
- **Codebase:** nmap — M7.10, `--open` / `--reason`
- **What happened:** M1 shipped a renderer that collapsed every non-open port into a
  single "Not shown" summary, where the C lists them individually until a per-state
  count crosses a threshold. This was **known**: it was written into
  `DIVERGENCES.md` as an "intentional MVP renderer abbreviation", and the
  differential's projection was *deliberately* built to canonicalize both
  representations to a per-state count so the abbreviation would not show up as a
  divergence. Both of those were reasonable calls for an MVP whose contract was
  "did we get every port's state and reason right".
  The abbreviation then survived nine milestones. Nobody revisited it, because it
  was not failing anything — the projection had been taught not to look. What
  finally exposed it was implementing **`--open`**, the flag whose entire purpose
  is to collapse non-open ports: the port had been behaving as though `--open` were
  permanently on, for every scan, for the whole project.
- **Cost:** No incident — the port states were always right, only their rendering
  was narrower. But every operator reading this scanner's output had been getting
  `--open` semantics without asking for them, and the differential could not have
  told anyone.
- **Root cause:** A ledger entry records a decision; it does not record *when the
  decision stops being right*. "Intentional MVP abbreviation" is a statement about
  a milestone that ended eight milestones ago. Worse, the harness had been adapted
  to the abbreviation, so the one mechanism that could have flagged it had been
  explicitly configured not to.
- **Fix:** Implement the real rule (nmap's 25-per-state threshold, scaled by
  verbosity), stop canonicalizing the two representations in the projection, and
  compare each non-open port's identity and reason. The differential got strictly
  stronger: same 20/20, now port-by-port.
- **Kit change:** `PLAYBOOK.md` and the divergence-ledger template — a ledger entry
  that records a **temporary** simplification must name the milestone that retires
  it, and the retrospective must re-read the ledger for entries whose stated scope
  has passed. Two sharper rules fall out:
  1. **When a harness is taught to tolerate a divergence, the tolerance is part of
     the divergence.** Write it in the same ledger entry, so removing one forces
     removing the other.
  2. **Implementing a flag is a good moment to check whether its behaviour is
     already the default.** A flag that turns out to be a no-op is not a cheap win;
     it is evidence that the unflagged path was wrong all along.

## 032. The flaw scanner knew libc's contracts, not the embedded interpreter's

- **Date:** 2026-10-04
- **Codebase:** nmap — M6 (NSE), retrospective after M6.4d
- **What happened:** The NSE port found four memory-safety defects in nmap's C
  glue to Lua:
  - `condvar`'s option list has no terminating `NULL`, so `luaL_checkoption`
    reads past it;
  - `set_port_version`'s list has the same flaw;
  - `receive_buf` copies `l-1` bytes as a `size_t`;
  - `port_set_output` dereferences an unchecked lookup.

  They were found by reading the C while porting it. `scan_c_flaws.py`, run
  over the three files that hold them, reported **0 sites**. LESSONS #020
  already explained the last two: a guard and a dataflow fact. The first two
  are not that kind of flaw. They are single-line API misuse, the scanner's
  stated domain, but of the *Lua C API*, which the scanner had never heard
  of. The same pattern caught a `luaL_argerror` passed a literal `%s`, which
  that function never formats.
- **Measured before wiring:** two rules, driven by per-API tables, over nmap's
  774 C/C++ files. They gave five hits and five true positives, with no false
  positives:
  - four unterminated `luaL_checkoption` lists. Two are in modules not yet
    ported (`nmapdb`, `zlib`). One had gone unnoticed even though the port
    had already reimplemented its function (`set_port_version`; see #033).
  - the literal-`%s` `luaL_argerror`.

  A third candidate, `%f` given an `int` in `luaL_error`, was measured and
  left out. It needs the argument's type, and two of its four hits were
  doubles.
- **Root cause:** "Scan the C for vulnerability classes" was read as "scan
  for libc's". An embedded runtime brings its own contracts, and a port of
  the glue around it is exactly where they are broken.
- **Kit change:** `scan_c_flaws.py` gains the `unterminated-list` (CWE-170)
  and `nonformatting-format` (CWE-628) categories. They are driven by
  `SENTINEL_LIST_ARGS` and `NON_FORMATTING_ARGS`, which the Lua C API seeds,
  with self-tests and a sabotage check. PLAYBOOK Phase 0 now says to extend
  the tables for each embedded library. The cflaw-scan skill names both
  categories.
- **Section amended:** PLAYBOOK · Phase 0; `harnesses/c-flaw-scan/scan_c_flaws.py`; `skills/porting-kit-cflaw-scan/SKILL.md`.

## 033. A golden recorded undefined behaviour because the flaw was found after the golden

- **Date:** 2026-10-04
- **Codebase:** nmap — M6.3 probe, found in the M6.4d retrospective
- **What happened:** M6.3's nmap probe called `set_port_version(host, port,
  "matched")` to pin the unknown-option error. In nmap that call reads past an
  unterminated option list (#032), and then past the parallel enum array. The
  golden recorded `invalid option 'matched'` only because the bytes after the
  list happened to hold a `NULL`. The port, which raises that error by
  design, matched for a milestone and a half. PLAYBOOK Phase 2 already said
  "record no golden where the C is undefined". It could not fire, because
  nobody knew the input was undefined when the probe was written.
- **Root cause:** The UB rule is applied once, when a corpus is built. Flaws
  found later never flow back to the corpora built before them.
- **Fix:** The case was removed from the probe, the golden regenerated, and
  the port's error pinned by a unit test. Ledgered as
  `nmaplib-set-port-version-option-overread`.
- **Kit change:** PLAYBOOK Phase 2 now says every new ledger entry for a C
  defect ends with a grep of the corpora for inputs that reach it. The
  retrospective prompt and skill re-scan with new rules and sweep the
  goldens. The cflaw-scan skill has the sweep as step 5.
- **Section amended:** PLAYBOOK · Phase 2, compounding loop; `PROMPTS/90-retrospective.md`; `skills/porting-kit-retrospective/SKILL.md`; `skills/porting-kit-cflaw-scan/SKILL.md`.

## 034. A golden encodes the host that generated it

- **Date:** 2026-10-04
- **Codebase:** nmap — M6.4d (`nse_net_differential`) and M6.3 (`nmaplib_differential`)
- **What happened:** Three variants turned up in one milestone.
  1. `nmap.resolve("localhost")` gave one address where the golden was
     generated and two on CI, whose runners list `localhost` twice in
     `/etc/hosts`. The port passed locally and failed in CI.
  2. A fixture printing `connect_waiting` read the state of *another* fixture
     running at the same time. That fixture was added later, and the
     generator's runs disagreed with each other.
  3. M6.3's docs said "ten scenarios" for a golden that had always had nine,
     because the IPv6 scenario needs IPv6 loopback and the generating host had
     none. IPv6 was checked only by CI's live regeneration. That turned out to
     be fine, but no document said so.
- **Root cause:** The generator's host is invisible in review. A golden looks
  like a property of the oracle, but it is a property of the oracle on one
  machine.
- **Kit change:** PLAYBOOK Phase 2 says what a fixture may print: only facts
  that hold on every host. Capability-dependent scenarios are named in the
  generator, and the docs say which goldens lack them and where they run.
  Concurrent fixtures must not print each other's state. The retrospective
  checks quoted counts against the goldens. That check found a second drift:
  `scripts_differential` was documented as 34 scenarios and had 36.
- **Section amended:** PLAYBOOK · Phase 2, compounding loop; `PROMPTS/90-retrospective.md`.

## 035. A module sat below DONE for eight milestones because nothing asked why

- **Date:** 2026-10-04
- **Codebase:** nmap — `core::output`
- **What happened:** `core::output` (normal, grepable and XML rendering) was
  marked `differential` in M1 and never moved. Every later `progress.py show`
  printed "103/104 modules fully gated". `drift` passed, because the module
  was tracked. `audit` passed, because it checks only exemptions and
  coverage. Closing the gap took ten minutes: Miri on its 28 tests, a check
  for `unsafe` (none), and a fuzz exemption with its reason written down.
  This is #021 and #027 again from the other side. Those made the table
  complete; nothing made it *finished*.
- **Kit change:** `progress.py audit` lists every module not done, and
  `--require-done` makes that a failure. nmap's CI runs it, since that table
  is now 104/104. The retrospective prompt and skill run it. PLAYBOOK's
  cross-cutting table gains the row.
- **Section amended:** `harnesses/progress/progress.py`; PLAYBOOK · Cross-cutting controls, compounding loop; `PROMPTS/90-retrospective.md`; `skills/porting-kit-retrospective/SKILL.md`.

## 036. The MSRV is a gate: build tests with it, and re-lint when it moves

- **Date:** 2026-10-04 (the first half is promoted from nmap's BACKLOG, written at the MSRV correction)
- **Codebase:** nmap — MSRV correction to 1.88; M6.4d
- **What happened:** Two incidents.
  - **The MSRV correction.** When the declared MSRV was corrected to a
    measured 1.88, the build passed but the full clippy sweep then raised ten
    findings across six files (`is_multiple_of`, `repeat_n`). BACKLOG noted
    it as "worth a LESSONS entry" and it was never promoted.
  - **M6.4d.** A shared test runner used `use super as nse_host;`, which
    current stable accepts and 1.88 rejects. Only CI's MSRV job caught it,
    after the push.
- **Kit change:** PLAYBOOK Phase 4's "run each gate as CI runs it" names the
  MSRV build of `--all-targets`, test code included, as a pre-push gate, and
  a full clippy sweep whenever the MSRV moves.
- **Section amended:** PLAYBOOK · Phase 4.

## 037. Signature verification must be strict, and a reference implementation is not a strictness oracle

- **Date:** 2026-10-04 (promoted from nmap's BACKLOG, written in Workstream S)
- **Codebase:** nmap — Workstream S (`core::sigstore::verify`)
- **What happened:** Workstream S measured Ed25519 verification against a
  small-order public key. These all accept forged signatures:
  - OpenSSL;
  - python-cryptography;
  - RFC 8032's reference implementation;
  - `ed25519-dalek`'s non-strict `verify`.

  Only `verify_strict` rejects them. The RFC's reference `verify()` also
  builds a bad-length exception and never raises it, so it accepts a 65-byte
  signature and cannot serve as an oracle for length handling. All of this
  was recorded in the port's BACKLOG with "worth a LESSONS entry" and stayed
  there (#019's failure, again).
- **Kit change:** PLAYBOOK's cross-cutting table gains "signature checks
  reject forgeries": strict verification, tested with small-order keys. When
  a port's oracle is a reference implementation, its *rejections* must be
  tested, not assumed.
- **Section amended:** PLAYBOOK · Cross-cutting controls.

## 038. A sabotage check that restores with `git checkout` discards the work it is checking

- **Date:** 2026-10-04
- **Codebase:** nmap — M6.4d
- **What happened:** A sabotage helper mutated a file, ran the gate, and
  restored the file with `git checkout -- file`. The file held an
  uncommitted security fix, `receive_buf`'s clamp of an end index before the
  buffer. The restore silently reverted it to the last commit, and the next
  sabotage run measured the old code. It was noticed only because `git
  status` no longer listed the file. The fix was re-applied and committed
  before any further sabotage.
- **Root cause:** "Restore the original" and "restore the last commit" are
  the same thing only on a clean tree.
- **Kit change:** PLAYBOOK Phase 4: a sabotage check saves the file's bytes
  before mutating and puts them back from that copy.
- **Section amended:** PLAYBOOK · Phase 4.

## 039. A fuzz artefact filed as a sabotage leftover was a real finding

- **Date:** 2026-10-11
- **Codebase:** nmap — M6.6 step d
- **What happened:** A crash file in `fuzz/artifacts/nse_lpeg_match/`, written
  during step c's fix round while sabotages were running, was recorded as a
  sabotage leftover and left in place. When step d's fix round was told to
  confirm that and delete it, it reproduced on the unsabotaged code: LPeg
  0.12's `coderep` passes `opt` into a loop body coded with a test, so an
  optional choice there partially commits the enclosing one, and C answers
  4 where PEG semantics give 5. The port matched C; the fuzz target's
  reference interpreter did not model the quirk. A real C behaviour sat
  unpinned and unledgered for a day because of a label nobody had checked.
- **Root cause:** An artefact's origin was inferred from when it was
  written, not established by running it on the code as it stands.
- **Kit change:** PLAYBOOK Phase 4, step 3: re-run every crash artefact on
  HEAD before deleting or dismissing it; one that reproduces is triaged like
  any other finding (pinned, seeded, ledgered).
- **Section amended:** PLAYBOOK · Phase 4.

# M6.6 — nmap's `nmapdb`, LPeg 0.12, and a first-party Lua base library

Nineteen commits (#129–#137, 2026-10-09 to 10-12). Every automated gate was green
at every step commit, and every step that was reviewed still had defects. Of about
15 substantive review findings, 9 were resource defects, including the milestone's
only High. The whole milestone merged with zero CI runs. These entries are the M6.6
retrospective. The evidence is in the port's commit messages, its per-step review
reports, and four retrospective audits (history, harnesses, step e, consistency).

## 040. Pre-emptible is not bounded: gate the work a slice does, and how total work and memory scale, on the port, by wall clock

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6
- **What happened:** The LPeg port runs in a pre-emptible VM, and the plan gated
  exactly that: "the match returns `Pending` on schedule". It did. The step
  reviews still found nine resource defects at steps a to d:
  - **step a:** 20 MiB of bad lines peaked at 1 GB. A FIFO data file blocked
    forever, and `/dev/zero` looped to 2.07 GB.
  - **step b:** a grammar build ran as one 13.66 s slice using 4.3 GB. In-flight
    buffers were not counted (31 MB under a 16 MiB budget).
  - **step c:** `/string` re-copied its format on every step. A 2 MB format took
    ≈140 s against C's 0.033 s. Byte work cost one unit of fuel, giving a 1.04 s
    slice. One slice reached 5.4× the memory budget (344 MB), and `Ct` peaked at
    1.22 GB.
  - **step d (High):** `json.parse` of a 1.8 MB network body took 270 s against
    C's 0.17 s, about 1,600×. The cause was an uncharged per-poll walk of the heap
    accounting. Strings were retained at 525 MB against C's ~4 MB. The same walk
    had already run once per slice at step c: `Ct(Ct(C(1))^0)` at 999k took
    34.6 s against 0.36 s, and step c's own security review missed it.

  The meters could not see these costs. Step 0b's linearity search counted the
  instrumented C's steps, and step e's ceiling `K` counted the port's VM steps.
  One VM step scans a whole run of bytes, so a quadratic pattern read as a flat
  6.00 steps per byte while CPU time grew 30×. Step 0b's spike passed 8
  requirements, and none was about total work or the slice bound. Step d's
  defects sat in the part the spike skipped (capture evaluation).
- **Root cause:** The kit had no resource-bounds control at all. A grep of
  PLAYBOOK, SECURITY-CHECKLIST and the CI template for DoS, complexity or
  exhaustion found nothing. LESSONS #001's timeout backstop fires only on a hang
  inside a small corpus case. The threat model named time as a threat, and the
  kit gave no shape for gating it. A meter counts only what it is instrumented to
  count. Wall clock and RSS count everything.
- **Kit change:**
  - PLAYBOOK Phase 4 gains **step 4b, Resource bounds**. For each untrusted edge,
    run the port in a release build at n, 2n and 4n, and gate the time and
    peak-memory exponents against the declared bound and against C's. For
    self-metering code, assert work ≤ c·fuel per slice, with the work counted
    independently of the charge, plus a wall-clock check on the longest slice.
    Calibrate any step counter against wall clock once.
  - The spike ritual's decision gate now covers **total work and the slice bound**
    for a pre-emptible design, next to #017's teardown criterion.
  - Phase 0 classifies path inputs as possibly blocking, and the threat model
    records a time and memory bound per untrusted input. `skeleton/THREAT-MODEL.md`
    has an availability column.
  - New [`RESOURCE-BOUNDS.md`](RESOURCE-BOUNDS.md) holds the procedure and this
    evidence.
  - New `harnesses/scaling/scale_check.py` runs a command template at n, 2n,
    4n, ... It measures wall time and the per-run peak RSS through `os.wait4`,
    children included; `RUSAGE_CHILDREN` would report the maximum over every
    earlier run. It fits exponents on successive differences, which cancels
    start-up time and the interpreter's own RSS high-water mark; a floor
    subtraction could not, because a 4 MiB allocation under a 12 MiB start-up
    peak does not move the peak. It fails on a declared bound, on C's exponent
    plus a tolerance, on a port/C ratio, or on an absolute RSS ceiling.
    `--self-test` uses synthetic linear and quadratic commands (sleeps for time,
    resident allocations for memory), against a declared bound and against an
    "oracle". It is in `make check-kit`.
  - SECURITY-CHECKLIST, the cross-cutting table and the CI template each gain a
    resource-bounds row or step.
- **Still not prevented:** a super-linear cost on an input shape nobody listed.
  Step 0b's adversarial search hunted for slow inputs on the C, not on the port.
  The missing tool is a differential performance search: hill-climb inputs,
  seeded from the fuzz corpus, to maximise port time ÷ oracle time and port
  peak ÷ oracle peak. It is recorded here and in OPERATING-GUIDE §5, and not
  built.
- **Section amended:** PLAYBOOK · Phase 0 (path inputs, threat model), Phase 4 (spike ritual; step 4b), cross-cutting controls; `RESOURCE-BOUNDS.md`; `harnesses/scaling/scale_check.py`; `Makefile`; `SECURITY-CHECKLIST.md`; `skeleton/THREAT-MODEL.md`; `harnesses/ci/porting-ci.template.yml`.

## 041. Review each step for fidelity and security before the next; each finding's class becomes a standing gate

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6
- **What happened:** Each of steps a to d was followed by its own "review fixes"
  commit, and every review found real defects. The fix rounds were 57%, 57%, 28%
  and 34% of their step's Rust churn, before counting the 2,473-line base-library
  port that step d's review triggered. About 14.5 h of the ~66 h wall clock went
  to fix rounds [INFERRED from commit times]. Two PRs merged before their reviews
  ran: #130 and #134, whose bodies say "A review round … follows on this PR". The
  step c defects sat on master from 17:30 to 20:52, and step e had no review
  round at all. Step b's review recorded "fuel is charged per call, not per unit
  of work", and the class recurred at steps c and d because each fix gated only
  its own step's code. Step b's fidelity review also found that `next({})`
  returns 2 values and that `tostring` skips the `__tostring` result check. It
  filed them as "Incidental, not LPeg, not ledgered", and the base library stayed
  wrong until step d's review found it again.
- **Root cause:** PLAYBOOK gate 6 read "Review & merge. Update the `progress`
  table". It defined no review, blocked no merge, and carried nothing forward.
  LESSONS #018 had already noted that a user-prompted review found what the kit
  did not.
- **Kit change:**
  - Gate 6 is rewritten. An independent reviewer applies two lenses, fidelity
    (adversarial rows beyond the corpus) and security (time, memory and
    totality), plus an independent sabotage set, and produces a severity table.
    The fix round lands in the same PR, and the merge is blocked until each
    finding is fixed or ledgered.
  - **Each finding's class joins the entry gates of every later step**, and Phase
    4's entry criteria name those standing gates.
  - An out-of-scope finding gets a ledger or BACKLOG row the same day.
  - New [`REVIEW-GATE.md`](REVIEW-GATE.md) holds the detail and a reviewer brief
    to paste. PROMPTS/10 step 6 and the module skill's gate 6 now point at it.
- **Section amended:** PLAYBOOK · Phase 4 (gate 6, entry and exit criteria); `REVIEW-GATE.md`; `PROMPTS/10-module-port.md`; `skills/porting-kit-module/SKILL.md`.

## 042. A gate wired into CI is a gate only on commits CI ran on

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6
- **What happened:** The last nmap-rs-ci run was on 2026-10-05 at 19:11Z (run
  37361585230, on 1f3184592). Every M6.6 SHA from #130 to #137 has
  `check-runs total_count 0`. Four workflow edits, 88 lines of regen checks,
  `--check-794` and fixture ports, have never executed. The docs and every PR
  body from #131 on said "CI has not run since 5 October", and the merges went
  ahead. The local runs that stood in for CI were scoped, which is #030's exact
  trap:
  - Miri ran on `lpeg::` only ("43 passed … 930 filtered out", 727 s);
  - fuzzing ran on the changed targets only;
  - no commit mentions `cargo deny` or the ASan job.
- **Root cause:** The kit treats CI as the enforcement point and never checks
  that CI ran. #030 ("run the gate as CI runs it") and #027.1 ("a control in the
  template but not the workflow") both presume a CI run as the backstop, so
  neither fired. A PR body saying "CI did not run" was an annotation, not a block.
- **Kit change:**
  - PLAYBOOK Phase 4: **no check run on the head SHA means no gate ran.** When CI
    cannot run, `make -C porting-kit ci-local` runs every workflow job unscoped,
    and its summary goes into the PR. A PR with neither is blocked. The rule is
    also a merge precondition in REVIEW-GATE.md and a row in the cross-cutting
    table.
  - New `harnesses/ci/ci_local.py`. It reads the workflow without PyYAML,
    through a subset parser covering block maps and lists, multi-line flow
    lists, and `|` and `>` scalars. It runs every job and matrix leg's `run:`
    steps with the workflow's working directories, env, `strategy.job-total` and
    step outputs. It lists every action and conditional step it did not run.
    Its summary names the HEAD SHA and any uncommitted changes. Its self-test
    parses the kit's own template and executes a synthetic workflow. It parses
    nmap's real 710-line `nmap-rs-ci.yml` into 13 job legs.
  - `make ci-local` (deliberately not part of `check-kit`).
  - The retrospective's step 0 lists merged SHAs with zero check runs, and the
    audit skill reports "CI ran on HEAD" as a gate row.
- **Section amended:** PLAYBOOK · Phase 4, cross-cutting controls, compounding loop; `harnesses/ci/ci_local.py`; `Makefile`; `REVIEW-GATE.md`; `PROMPTS/90-retrospective.md`; `skills/porting-kit-{audit,module,retrospective}/SKILL.md`.

## 043. A dependency's own compatibility list is not an oracle: census what the corpus reaches

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (base library of the vendored `piccolo` VM)
- **What happened:** At M6's Phase 0, the vendored VM's base library was credited
  from its own `COMPATIBILITY.md`, which marks it "implemented". Step d's fidelity
  review found that:
  - `pcall` raises on a non-callable;
  - `pairs` and `ipairs` return 2 values;
  - `#t` picks border 4 where C gives 8;
  - `rawlen` and `rawset` are unchecked;
  - `__metatable` is ignored;
  - `collectgarbage` raises;
  - `isyieldable` and `close` are missing.

  The fix was first-party base and coroutine libraries (51bae54d2, 2,473 Rust
  lines). The corpora had **0 rows** for `rawlen(`, `rawset(`, `pairs(`,
  `ipairs(`, `collectgarbage` and `{...}`. The `vmbase` named tolerance class
  absorbed the symptom from step b to step d.
- **Root cause:** In piccolo's docs, "implemented" means present, and
  COMPATIBILITY.md's own footnote hedges with "near 1:1". #018 vets reused crates
  for safety only. M3's positive validation already said "library compatibility
  estimated by grep is unreliable", and it was never made a rule.
- **Kit change:**
  - PLAYBOOK Phase 0: vet reused code for **fidelity** as well as safety.
  - Phase 2 gains a **reach census**: count the corpus rows for each function the
    port exposes. Zero rows means unverified.
  - ORACLE-CHECKS.md §2 adds that a tolerance class covering a dependency's
    divergence triggers an audit of that dependency's sibling functions.
  - The oracle and kickoff skills carry both rules.
  - `progress.py drift` still skips vendored trees, and reports them. The census,
    not the tracker, is where a dependency's surface is counted.
- **Section amended:** PLAYBOOK · Phase 0, Phase 2; `ORACLE-CHECKS.md`; `skills/porting-kit-{oracle,kickoff}/SKILL.md`.

## 044. Sabotage is a measurement with failure modes of its own

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (steps a, b and d; step 0b)
- **What happened:**
  1. **A stale build.** Step a's review restored sabotaged files with
     `shutil.copy2`, which keeps the old mtime. Cargo's fingerprint saw no change,
     so the next run tested the stale, still-sabotaged build (the port's
     `tests/differential/m6/README.md:461-469`). #038's fix, "put back the saved
     bytes", causes this whenever it is done with `cp -p` or `copy2`.
  2. **A kill counted as a catch.** Step b's S2 had been counted as caught by a
     117 s kill. After its fix it "fails by assertion in 29 s".
  3. **The author's blind spots.** At step a, the author's 11 sabotages were all
     caught. Of the reviewers' independent 34, **8 were missed by every gate**.
     Step d's S08 was unsound.
  4. **No port sabotage probed inside a tolerance class's spans**, which is where
     #048's argument-number regression hid.

  One practice worked. At step 0b, 16 sabotaged builds of `lpeg.c` measured the
  corpus, and one of them (keeping dynamic captures on backtrack) passed all
  60,806 rows. At HEAD the harness runs 17 variants over 62,599 rows and catches
  every one (455 s).
- **Root cause:** The kit treated sabotage as a habit, not as a measurement with
  failure modes. #038 fixed one failure mode (the restore source) and introduced
  another (the mtime).
- **Kit change:** PLAYBOOK Phase 4 amends #038 with four rules:
  - restore from the byte copy **and bump the mtime**;
  - **only a named assertion counts as a catch**, and a kill, timeout or harness
    crash is inconclusive;
  - each step gets **an independent sabotage set** with its catch rate reported;
  - sabotage inside every tolerance.

  Phase 2 adds **sabotage the C to measure the corpus**. REVIEW-GATE.md holds the
  protocol, ORACLE-CHECKS.md §4 the C side. The module and oracle skills carry
  both.
- **Section amended:** PLAYBOOK · Phase 4, Phase 2; `REVIEW-GATE.md`; `ORACLE-CHECKS.md`; `skills/porting-kit-{module,oracle}/SKILL.md`.

## 045. A gate tick outlives the code it vouches for

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (`core::nse::stdlib::base`)
- **What happened:** `progress.json` maps `core::nse::stdlib::base` to the fuzz
  target `nse_tail`, which exercises only `chunk_id` and `strrep`. In 51bae54d2,
  base.rs grew from 756 to 2,499 lines and gained `str2int`, the byte parser
  behind `tonumber(s, base)`, and nothing fuzzes it. The module's "fuzzed" tick
  stayed, and `audit` stayed green, because `audit` checks that a mapping names a
  real target, not that the target reaches the code.
- **Root cause:** #027 records coverage once and never re-checks it. A tick is a
  claim about code at a moment, and the table stored the claim without the moment.
- **Kit change:**
  - `progress.py stamp MODULE GATE --src crates` records a sha256 over the
    module's source files: `a/b.rs` and everything under `a/b/`, path and
    content, relative to its crate's `src/`. `set ... --src` stamps as it ticks.
  - `audit --src crates` fails with `STALE-TICK` once a stamped module's files
    change, a new file in a directory module included, until the gate is re-run
    and re-stamped. That is the moment to ask whether the target still reaches
    the new entry points.
  - Stamps are opt-in. nmap's current table, which has none, audits exactly as
    before (26 exemptions, 40 mappings, OK). The self-test covers all of this.
  - PLAYBOOK gate 6 and the compounding loop now say to stamp and to audit
    `--src`, and the CI template's audit step passes `--src crates`.
  - **Next step, not done:** proving that a fuzz target reaches a module's *new*
    entry points needs coverage instrumentation (`cargo fuzz coverage`). The
    stamp forces the question, and the review lens answers it.
- **Section amended:** `harnesses/progress/progress.py`; PLAYBOOK · Phase 4 (gate 6), cross-cutting controls, compounding loop; `harnesses/ci/porting-ci.template.yml`; `skills/porting-kit-{module,retrospective}/SKILL.md`.

## 046. The skills lag the PLAYBOOK

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (the kit itself)
- **What happened:** No skill cited #030, #036, #038 or #039. All four are Phase-4
  rules, and #039's in-flight patch touched only LESSONS.md and PLAYBOOK.md. An
  agent driven by `porting-kit-module` therefore ran a loop four lessons behind
  the book. The new check, run on the kit before the back-fill, found more:
  - `porting-kit-module` and PROMPTS/10 each missed 16 Phase-4 lessons (#001,
    #004, #007 to #010, #012 to #015, #017, #021, #030, #036, #038, #039);
  - the oracle skill missed #001, #033 and #034;
  - kickoff missed #006, #018 and #032;
  - cflaw-scan missed #001, #006 and #018.
- **Root cause:** `check_skills.py` validated that a skill's paths and `make`
  targets exist, not what the skill says. This is #022's shape again: an
  integrity check that inspects less than its name claims.
- **Kit change:**
  - `check_skills.py` gains **check 5**. Every LESSONS entry whose "Section
    amended" names `PLAYBOOK · Phase N` must be cited by number in that phase's
    skills: Phase 4 in `porting-kit-module` and PROMPTS/10, Phase 2 in
    `porting-kit-oracle`, Phase 0 in `porting-kit-kickoff` and
    `porting-kit-cflaw-scan`.
  - An entry with no "Section amended" field is read by its "Kit change" field,
    since LESSONS is append-only. This is how #030 counts. The self-test covers
    wrapped fields, ranges like `#2–#4`, and a phase named outside a PLAYBOOK
    clause.
  - The skills and PROMPTS/10 are back-filled through #051.
- **Section amended:** `skills/check_skills.py`; `skills/*/SKILL.md`; `PROMPTS/10-module-port.md`; `CLAUDE.md` (Skills); PLAYBOOK · compounding loop.

## 047. A matrix of explicit options never tests the defaults

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 side fixes (782a00881, 4fbc629c8)
- **What happened:** Two defects lived for milestones and surfaced as M6.6 side
  fixes:
  - `cli-stdout-silenced-by-output-files`, present since M1: the terminal report
    went silent whenever `-o` wrote a file;
  - `udpscan-tcp-port-list`, present since M4: `-sU` scanned the TCP port list.

  Every differential matrix passed `-p` and `-oX -`, so neither default was ever
  exercised.
- **Root cause:** A matrix of explicit options tests the options, never their
  absence. #031's "implementing a flag is a good moment to check its default" is
  adjacent, but it fires only when a flag is being implemented.
- **Kit change:**
  - PLAYBOOK Phase 2: each option gets a row where it is omitted, plus the
    combinations users run, such as a report to the terminal and to a file at
    once.
  - ORACLE-CHECKS.md §1 holds the detail.
  - `input-matrix.example.toml` gains both kinds of row.
  - The oracle skill carries the rule.
- **Section amended:** PLAYBOOK · Phase 2; `ORACLE-CHECKS.md`; `harnesses/differential/input-matrix.example.toml`; `skills/porting-kit-oracle/SKILL.md`.

## 048. A tolerance class is an exemption: scope it to the rows it was ledgered for and pin its membership

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (`lpeg_corpus_differential.rs`)
- **What happened:** The LPeg corpus gate's `compare()` tried its `position`,
  `argname` and `method` normalisations on **every** differing row. Only `cdepth`
  was limited to rows tagged for it. `report()` printed each class's members and
  asserted nothing about them, so the ledger's "argname 2, method 1, cdepth 7"
  was not enforced. The retrospective measured the reach directly. The
  argname/method regex touches **5,906 of 62,599** golden rows, and a one-character
  function-name change or an argument number off by one is accepted on all of
  them. The position class touches 175 rows. On the real gate, a sabotage of
  `Fail::arg(1, "value expected")` to `Fail::arg(2, …)` **passed**, and `method`
  silently grew to three members. The control, `"value"` changed to `"valuf"`,
  failed on 2 rows. The gate was sound outside the class spans and blind inside
  them. The 7.94 check's `DRIFT_CLASSES` is unscoped the same way.
  `lpeg_callback_quirks` did it right, with classes keyed per id. The port's own
  fix is tracked separately.
- **Root cause:** #007 and #013 framed normalisation as noise removal or
  projection. #031 made the tolerance part of the divergence, but about expiry,
  not reach. Nothing said a tolerance must be scoped or its membership pinned.
- **Kit change:**
  - `normalize.py` gains scoped rules, `scoped_rule(name, regex, repl, cases,
    ledger)`, loaded from `[[tolerance]]` TOML or JSON. A rule with no cases is
    refused. The self-test checks that a scoped rule does not fire on another
    case.
  - `diff_run.py --tolerances` applies them per case. It reports
    `MATCH(tolerated)`, fails with `STALE-TOLERANCE` when a listed case matches
    without its tolerance, and refuses a tolerance that names a case missing from
    the matrix. These have self-tests and were exercised end to end.
  - PLAYBOOK gate 2 states the rule, ORACLE-CHECKS.md §5 holds the evidence, and
    REVIEW-GATE.md's sabotage protocol adds "sabotage inside every tolerance".
- **Section amended:** `harnesses/differential/{normalize.py,diff_run.py}`; PLAYBOOK · Phase 4 (gate 2); `ORACLE-CHECKS.md`; `REVIEW-GATE.md`; `skills/porting-kit-{module,oracle}/SKILL.md`.

## 049. Every golden generated by running C is UB-screened, and the screen's record digests what it screened

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (`m66b_tree_golden.txt`, `screen_m66_lpeg.py`)
- **What happened:**
  - **UB in the tree golden.** The golden is hex-encoded, so a text grep for
    `block too big` found nothing. The retrospective built the tree's own
    `liblua` and `lpeg.c` with `-fsanitize=undefined -fno-sanitize-recover=all`
    and ran all 5,710 tree rows, which took 3 s. **14 rows are UB**, from signed
    `int` overflow at `lpeg.c:2374, 2377, 2643, 2655, 2977`. The other 5,696 are
    clean and byte-identical. The 14 rows were added on purpose ("the C's int size
    wraps") and ledgered as "the C's arithmetic modulo 2^32". That made what
    `gcc -O1` happened to do into the spec, and CI regenerates them from that
    build on every run.
  - **UB in four pins.** Separately, a pin generator leaves `(size_t)(-ii)` and
    `lua_tointeger(...) - 1` undefined, and four pins take their answers from
    that build.
  - **The screen's wiring.** The screen for the main corpus,
    `screen_m66_lpeg.py`, uses ASan, UBSan and `LUA_USE_APICHECK`, but nothing
    runs it. Its only wiring is a digest check, and the digest covers the
    corpus, not `lpeg.c`, `liblua/`, the glue, the screen or the flags. The
    second C-generated corpus had no screen.
  - **A sweep not run.** One #033 sweep was never done: "whether json.parse
    reaches doublecap's over-read: not run under ASan".
- **Root cause:** PLAYBOOK Phase 2's #020 sanitized *pasted oracle functions*
  under ASan. It said nothing about every C-generated golden, about UBSan, or
  about what the screen's record must cover. #033's sweep is a text grep, and a
  hex-encoded golden defeats it. The kit's `run_sanitizers.sh` covers Rust only.
- **Kit change:**
  - PLAYBOOK Phase 2 rule and exit criterion: every golden generated by running C
    is screened under `-fsanitize=address,undefined -fno-sanitize-recover=all`
    plus the runtime's API checks.
  - The screen's committed record carries a digest of the corpus, the C sources
    and the flags. The generator refuses a mismatch, and CI checks it.
  - UB that looks deterministic is still UB. Drop the row, or generate it from a
    defined variant and pin the answer as semantic.
  - Store goldens greppable, or decode them before any sweep.
  - ORACLE-CHECKS.md §3 holds the recipe, and the cross-cutting table has a row.
    The oracle, cflaw-scan and retrospective skills and PROMPTS/90 carry the
    decode step.
  - A generic `screen_oracle.py`, modelled on nmap's screen, is a candidate
    harness and is not built.
- **Section amended:** PLAYBOOK · Phase 2, cross-cutting controls, compounding loop; `ORACLE-CHECKS.md`; `PROMPTS/90-retrospective.md`; `skills/porting-kit-{oracle,cflaw-scan,retrospective}/SKILL.md`.

## 050. The flaw scanner found 1 of 22, and the miss was known at Phase 0

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6 (`lpeg.c`, `nse_db.cc`, `protocols.cc`, `services.cc`)
- **What happened:** `scan_c_flaws.py lpeg.c nse_db.cc nse_db.h nse_lpeg.cc
  nse_lpeg.h` reported one hit, `nse_db.cc:52`, which #032's sentinel rule found
  as that entry predicted. M6.6 ledgered 22 C defects, and the scanner found
  nothing in `lpeg.c`'s 3,694 lines. `docs/M6.6-ANALYSIS.md` §7 had recorded
  "0 hits on lpeg.c" at Phase 0. No rule followed and no lesson was written, so
  the miss was known for the whole milestone (#019's pattern). The audit also
  found three problems in the scanner itself:
  - `int-overflow-mul` hard-coded `malloc|calloc|realloc` on one line. It could
    not see LPeg's five size overflows, which allocate through `newtree` and
    `lua_newuserdata`, or nbase's `safe_*` wrappers.
  - The same regex reported dereferences and casts (`sizeof(*p)`,
    `realloc((char *) ptr, n)`) as products, and missed every product written
    sizeof-first.
  - The docstring listed an `unchecked-malloc` category that had never been
    implemented.
- **Root cause:** Rules were added only at retrospectives. A flaw that a step
  found and the scanner missed was written into the analysis document, not
  measured against the scanner.
- **Kit change:** `scan_c_flaws.py` gains:
  - five rules from the retrospective's measured prototypes, each with a
    self-test case and a near miss it must not flag:
    - `scanf-narrow-int` (CWE-190);
    - `index-rewind-in-stride-loop` (CWE-823);
    - `negation-to-unsigned` (CWE-190);
    - `narrow-field-store` (CWE-197), which skips constants, masked values and
      stores with `SHRT_MAX` within 3 lines;
    - `ctype-signed-char` (CWE-758, weak).
  - a per-target `ALLOC_FUNCS` table seeded with libc's allocators,
    `lua_newuserdata[uv]` and nmap's `safe_malloc`/`safe_zalloc`/`safe_realloc`.
    Calls are parsed across lines, only a binary `*` counts, and all-constant
    products are skipped. `--config FILE.json` and `--alloc-func NAME[:ARG]`
    extend it and the other two contract tables per target.
  - `--inventory recursion`, which lists the functions on a call-graph cycle with
    no depth guard. It uses an iterative Tarjan SCC per file.
  - comment stripping that keeps line numbers;
  - an extended "What this CANNOT find" section, and the phantom category is
    removed.

  Each new rule was then sabotaged against its self-test. The self-test caught
  11 of 13 sabotages. The fixture was fixed for one survivor; the other was a
  check that is redundant by construction. PLAYBOOK Phase 0 and the cflaw-scan
  skill now say to **measure a rule when a later step finds a flaw the scanner
  missed**, then, not at the retrospective.
- **Measured (re-run on the tree for this entry):**
  - **Recall on M6.6's 22 defects:** 1 before. 8 now with the default tables, 10
    with LPeg's file-local allocator added (`--alloc-func newtree:1`), and 12
    counting the recursion inventory. The inventory lists 18 functions in
    `lpeg.c`, including every walker the ledger names. Of the other 10, three
    candidate rules were measured and rejected as noise (a pointer difference as
    a length, a Lua push in a loop, an array sized `UCHAR_MAX`). Seven are
    outside any line rule, and the docstring names their classes.
  - **The five M6.6 files:** 1 hit before, 21 now, 27 with `newtree`.
    - `narrow-field-store`: 13, 9 of them at ledgered sites.
    - `int-overflow-mul`: 2, or 8 with `newtree` (5 ledgered).
    - `negation-to-unsigned`: 2.
    - `ctype-signed-char`: 2.
    - `index-rewind-in-stride-loop`: 1.
    - `unterminated-list`: 1.
  - **The other 772 C/C++ files: 430 hits before, 482 now (+52).**
    - `ctype-signed-char`: +39 in 14 files. All 5 of 5 sampled are true CERT
      STR37-C instances.
    - `scanf-narrow-int`: +2. Both, `protocols.cc:121` and `services.cc:159`, are
      ledgered M6.6 defects.
    - The other three new rules: 0. `pcap-dag.c:534`'s masked store is no longer
      a false positive.
    - `int-overflow-mul`: 75 to 86. Over libc's allocators alone, the parsed rule
      gives 41: it drops 55 dereferences, casts and constant products the regex
      reported, and adds 21 sizeof-first and multi-line products the regex
      missed. The `safe_*` seeding adds 45 more. `lua_newuserdata` adds none,
      because both of `nse_nsock.cc`'s calls have constant sizes.
    - The audit's estimate was +42. The new rules give +41, since the masked
      false positive is gone, and the `ALLOC_FUNCS` rework adds a net +11.
  - **Recursion inventory, rest of the tree:** 72 functions in 29 files.
  - **Speed:** the whole 775-file tree scans in 5.6 s.
- **Section amended:** `harnesses/c-flaw-scan/scan_c_flaws.py`; PLAYBOOK · Phase 0; `skills/porting-kit-{cflaw-scan,kickoff}/SKILL.md`.

## 051. Small amendments: the runtime's own checking mode, path filters for oracle inputs, citations by revision and ID

- **Date:** 2026-10-13
- **Codebase:** nmap — M6.6
- **What happened:**
  1. **ASan saw nothing on 40 to 299 nested captures**, and `LUA_USE_APICHECK`
     caught the Lua stack overflow they cause (the port's M6.6 analysis §7). ASan
     watches the C heap, and the runtime's checks watch the runtime's own
     invariants.
  2. **The CI path filter missed the oracle's inputs.** A `build.yml` comment says
     nmap-rs-ci is scoped "plus the C-tree files its goldens read". Its `on:` block
     omits `lpeg.c`, `nse_lpeg.cc`, `nse_lpeg.h`, `nse_lua.h` and `liblua/**`,
     which are exactly the files the LPeg and Lua oracle checks compile. A change
     to `lpeg.c` would not have run them.
  3. **Citations drifted.** 35c0e07ab fixed about 80 citations and 14 drifts
     mid-milestone. The consistency audit still found about 45 wrong `file:line`
     citations in code comments: 24 in `stdlib/base.rs`, checked against the
     tree's Lua 5.4.8, and about 20 in `lpeg/`. It also found three ledger IDs
     named in docs but never ledgered, one ledgered under a different ID, and
     PLAN.md:22 out of date again.
- **Root cause:** (1) #020 named ASan only. (2) #005 scoped workflows to the paths
  they *build*, not to the paths their oracles *read*. (3) Line numbers move
  unless a revision pins them, and prose names are not checked against the
  ledger.
- **Kit change:**
  1. PLAYBOOK Phase 2: build the oracle in the embedded library's own checking
     mode too (ORACLE-CHECKS.md §3).
  2. PLAYBOOK Phase 3 and the CI template: path filters include every file the
     goldens read.
  3. CLAUDE.md working notes: cite C as `rev:path:line` against a pinned
     revision, and cite the ledger by ID.
- **Section amended:** PLAYBOOK · Phase 2, Phase 3; `ORACLE-CHECKS.md`; `harnesses/ci/porting-ci.template.yml`; `CLAUDE.md` (working notes).

## Meta — M6.6's gates were green and its reviews were not

Every automated gate passed at every step commit, and every review found defects.
The four largest kit gaps share one shape: **a property the kit assumed rather
than measured**. It assumed that yielding bounds the work (#040), that CI runs
(#042), that a dependency does what its docs say (#043), and that a tick stays
true (#045). The fixes measure instead: wall clock and RSS against C, check runs
on the SHA, rows per exposed function, a digest per tick. The single failure the
kit still would not prevent is the one #040 records: a super-linear cost on an
input shape nobody chose to scale. Its tool, a differential performance search
that hill-climbs inputs to maximise port ÷ oracle time and memory, is the next
port's target. It is recorded, not stubbed.

## Positive validations (habits that paid off, no change needed)

- **Spike-with-a-decision-gate changed the plan before it cost a wall.** M3's whole
  engine choice rested on "Rust's linear `regex` carries the bulk of
  `nmap-service-probes`; backtracking is a small minority." A *paper feature-grep*
  put the backtracking need at ~7%. The spike (`SPIKES.md` M3-1) refused the grep
  estimate and **compiled all 12,171 patterns through the real engine** — finding
  only 77.5% compiled, a 3× miss, and that the gap was PCRE-vs-Rust *syntax*, not
  semantics. That surfaced an entire new module (`core::pcre_translate`, a syntax
  preprocessor) *before* scheduling, not as a wall at 77.5% mid-port. The durable
  note (now in the spike's own record): **library-compatibility estimated by grep is
  unreliable — compile the corpus through the actual engine to know the real fit.**
- **Spike-the-scary-module worked cleanly.** The congestion/retransmission math was
  the flagged hazard; the timeboxed spike (`SPIKES.md` M2-1) read `timing.cc`,
  confirmed textbook AIMD, found the two divide-by-zero footguns the C guards with
  an `assert`, and graduated straight into `core::congestion` with **High**
  confidence and no pivot. The kit's #1 habit did exactly what it promises.
- **The pure/impure split scaled to a whole engine.** Every scheduling *decision*
  (congestion window, host scheduler, group window, rate limiter) ported into pure,
  Miri-checked `core` with the clock/sockets injected by the thin `sys` driver.
  That is *why* M2 stayed at 0 unsafe, kept full Miri coverage over the engine, and
  made #010's "structural race-freedom" argument available at all — the concurrency
  shell has no logic and no shared state to race. LESSONS #8's split is not just a
  Miri workaround; it is the property that lets a safety rewrite reason about an
  async engine at all.
- **Sabotage caught missing fixtures, not just weak assertions** (nmap M6.4d).
  Two of nine mutations survived the first run: `socket_unlock` disabled, and
  `condvar` signal order reversed. Neither failed anything, because no fixture
  held more than 20 sockets or had more than one waiter. Writing those two
  fixtures, checked first against nmap, turned both into catches. A surviving
  mutant is usually a missing *case*, not a missing assertion.
- **Phase 0's decisions gate held** (nmap M6.6). The analysis ended with "No
  port code until §9 approved" and three adversarial reviews, which overturned
  10 claims before any Rust was written. The milestone's defects came later, in
  code, and not from a design decision taken on an unexamined claim.
- **A scanner rule written for one milestone paid out in the next** (nmap
  M6.6). #032's sentinel-list rule named `nmapdb` as an unported module with an
  unterminated list. M6.6's Phase 0 found `nse_db.cc:52` with it, and the port
  rejects the unlisted option by design.
- **Phase 2's discipline held under load** (nmap M6.6). The tree's own `liblua`
  and `lpeg.c` were the spec (#019). 164 rows were quarantined, each with exactly
  one pin (#033). Host-dependent drift got named classes (#034). Sabotaging the C
  measured the corpus: at step 0b, one of 16 variants exposed a behaviour the
  corpus could not tell apart, and at HEAD all 17 variants are caught. That
  practice is now a rule (#044).
