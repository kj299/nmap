# nmap-rs — safety-first Rust rewrite of nmap (Windows-targeted)

A ground-up rewrite of nmap from C/C++ to Rust, driven by the **Porting Kit**
(`../porting-kit/`, vendored from `kj299/c2rust-port`). The C tree beside this
workspace stays runnable as the **differential oracle** until cutover — nothing in
the C tree is modified. Full plan & milestone ladder: see the approved project plan.

## Prime directive
The Rust must be **safer and more secure than the C, not merely equivalent**. The C
is a specification that may itself be buggy; every deliberate behavioral difference
is triaged and recorded in `DIVERGENCES.md`, never silently matched.

## Layout (unsafe isolation is structural)
- `crates/core` — `#![forbid(unsafe_code)]`. MOST logic: target/port parsing, scan
  model, timing math, output rendering. Testable on any host; fuzzed; Miri-clean.
- `crates/sys` — the **only** first-party crate permitted `unsafe`. It holds the
  async sockets and scan drivers (tokio), raw I/O and capture (libpcap/Npcap
  behind the `pcap` feature), interface queries (with a hand-FFI cross-check
  behind `raw-ffi`), and the real file system NSE scripts see, behind the script
  file policy. Every `unsafe` carries a `// SAFETY:` (the unsafe-audit gate
  hard-fails otherwise).
- `crates/cli` — thin: argv → request → core+sys → render. Binary: `nmap-rs`.
- `crates/vendor/piccolo` — the Lua VM NSE runs on, vendored at a pinned
  upstream commit plus a numbered patch series (`PROVENANCE.md`,
  `check_vendor.sh`).

## Status
The authoritative tracker is the STATUS TRACKER at the top of [`PLAN.md`](PLAN.md);
per-module gate status is in [`progress.json`](progress.json)
(`python3 ../porting-kit/harnesses/progress/progress.py --file progress.json show`).
In brief:

- **Milestones 0–5 are done.** `nmap-rs` runs `-sT`, `-sS`, `-sU`, the six TCP
  flag scans, `-sV` and `-O` (IPv4 and IPv6), `-sL`, the `-T` templates, port
  selection and all four output formats. An option it cannot honour is refused,
  not ignored.
- **Workstream S** (signature-database maintenance): every unblocked slice is merged.
- **M6, NSE, is in progress.** Done so far:
  - `.nse` metadata and `--script` selection;
  - the vendored Lua VM (`crates/vendor/piccolo`, eleven local patches), with
    PUC-Lua's errors, limits and memory budget;
  - the first-party standard library;
  - `--script-args` and the `nmap` module's non-I/O half;
  - the NSE state, in which all `nselib/` libraries load as under nmap 7.94
    except those waiting on unported C modules. File access goes through the
    script file policy (`docs/M6-ANALYSIS.md`, Decision 2);
  - running scripts: `nse_main.lua`'s own scheduler, with results printed as
    nmap prints them;
  - sockets, timers, `resolve`, `mutex` and `condvar`, over a tokio host
    (`sys::nsenet`). TLS, packet capture and raw `dnet` sends are pending;
  - `--script`, `-sC`, `--script-args` and `--script-timeout` on the
    command line, with results in normal and XML output as nmap prints them.
    Data files and scripts come from nmap's data directories, never the
    working directory.

  What remains of NSE is ledgered in `DIVERGENCES.md`: TLS, packet capture,
  raw `dnet` sends, `-sV`'s version scripts, and the unported C modules.
- **M7, cutover,** is in progress in parallel.

## The gates (CI-enforced; `.github/workflows/nmap-rs-ci.yml`)
```
cargo fmt --all -- --check
cargo clippy --all-targets --all-features -- -D warnings -D clippy::missing_safety_doc -D clippy::undocumented_unsafe_blocks
cargo test --all --all-features
python3 ../porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/   # hard-fail on undocumented unsafe
cargo +nightly miri test                                                # UB in unsafe
cargo audit && cargo deny check                                         # supply chain
```
Beyond these:

- **Fuzzing.** Every untrusted-input parser has a cargo-fuzz target in `fuzz/`,
  smoke-run in six CI shards. `fuzz/check-seeds.sh` checks seed hygiene.
- **Differential tests** against the C oracle live in `tests/differential/`.
  Each corpus has a `regen_*.sh --check` that re-derives it from the oracle.
  Live runs against nmap itself are in CI's differential job.
- **Vendored code.** `crates/vendor/piccolo/check_vendor.sh` proves the
  vendored tree is upstream plus its patch series.
- **Tracker drift.** `progress.py drift` and `audit` keep `progress.json` in
  step with the shipped modules and fuzz targets.

## Windows build (target platform)
Target **`x86_64-pc-windows-msvc`** — matches nmap's own MSVC Windows build and the
Npcap SDK needed from Milestone 4 (avoids the winlsof MSVC-vs-GNU linker time-sink,
kit LESSONS #1). `core` builds and tests on the Linux CI runner every push regardless
of target. Environment preflight: ensure `target/` is not on a synced/locked folder.

## Observability
Set `NMAP_RS_TRACE=1` to emit phase-boundary trace lines to stderr (scaffolded on
day one per the kit retrospective — the first hang should be diagnosable in minutes).
