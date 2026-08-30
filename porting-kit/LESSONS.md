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
