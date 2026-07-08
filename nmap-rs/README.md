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
- `crates/sys` — the **only** crate permitted `unsafe`. Async sockets (tokio) now;
  Npcap FFI + the `windows` crate (IP Helper) later. Every `unsafe` carries a
  `// SAFETY:` (the unsafe-audit gate hard-fails otherwise).
- `crates/cli` — thin: argv → request → core+sys → render. Binary: `nmap-rs`.

## Status
- **Milestone 0 (foundation): in progress** — workspace, gates, CI, TRACE logger.
- Milestone 1 (next): unprivileged TCP connect scan → output. Placeholder CLI today.

## The six gates (CI-enforced; `.github/workflows/nmap-rs-ci.yml`)
```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings -D clippy::missing_safety_doc -D clippy::undocumented_unsafe_blocks
cargo test --all
python3 ../porting-kit/harnesses/unsafe-audit/audit_unsafe.py crates/   # hard-fail on undocumented unsafe
cargo +nightly miri test                                                # UB in unsafe
cargo audit && cargo deny check                                         # supply chain
```
Fuzz + differential gates activate in Milestone 1 (they self-skip until then).

## Windows build (target platform)
Target **`x86_64-pc-windows-msvc`** — matches nmap's own MSVC Windows build and the
Npcap SDK needed from Milestone 4 (avoids the winlsof MSVC-vs-GNU linker time-sink,
kit LESSONS #1). `core` builds and tests on the Linux CI runner every push regardless
of target. Environment preflight: ensure `target/` is not on a synced/locked folder.

## Observability
Set `NMAP_RS_TRACE=1` to emit phase-boundary trace lines to stderr (scaffolded on
day one per the kit retrospective — the first hang should be diagnosable in minutes).
