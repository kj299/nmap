# Intentional divergences from the C original

Every place the Rust port **deliberately** behaves differently from the C. The
differential harness (`diff_run.py --ledger DIVERGENCES.md`) reads this file:
a case listed here as `- [x]` is a *known-intentional* divergence and is
suppressed (reported as `DIVERGE(ledgered)`, not a failure). Everything else that
diverges is an unexplained regression and fails CI.

**This file is a feature, not an apology.** The prime directive is that the C may
be buggy; where you fixed a C defect, the Rust *should* diverge — record it here
and ship it as a release note. Seed this from the Phase-0 C-flaw scan.

Format — one bullet per case name, ticked when reviewed and accepted:

```
- [x] <matrix-case-name>: <why the Rust intentionally differs; CWE if a security fix>
```

## Security fixes (C defect closed by the port)

### Milestone 1 (planned — from the Phase-0 `scan_c_flaws.py` triage; `nmap-rs/m1_cflaw.json`)
Unchecked `[ ]` = planned (Rust not yet written); ticked `[x]` when the owning
module lands and the fix is in the tree. These are *internal* hardenings — most
produce no observable output divergence (so no differential case), but each is a
C sink the port must not re-implement. Case names prefixed `sec-` for the ones
that could surface in a differential.

- [ ] `sec-services-path` (`services.cc:134/140`, owner `core::ports`): C builds
      the fallback services-file path with `GetSystemDirectory(buf,480)` then
      `strcpy(buf+len, "\\drivers\\etc\\services")` — a latent CWE-120 overflow
      resting on a hardcoded `480` "be safe" assumption. Rust uses
      `PathBuf::join`, so the bound is structural and the overflow class is gone.
- [ ] `sec-proto-name` (`output.cc:719`, owner `core::output`):
      `strcpy(protocol, IPPROTO2STR(...))` into a fixed buffer (CWE-120). Rust
      renders protocol names as `String`/`&str` with no fixed-size destination.
- [ ] `sec-log-format` (`output.cc:923/928`, owner `core::output`):
      `vfprintf(fmt, …)` with a non-literal `fmt` (CWE-134 format-string). Rust's
      compile-time-checked `format!`/`write!` makes the whole class unexpressible.

> **Deferred (not M1):** `output.cc:1564/2003/2027/2048`
> (`strcat`/`sprintf` of OS-detect sequence/IP-ID/timestamp values, CWE-120) live
> on the osscan output path — logged here for **Milestone 5**, not ported in M1.

## Behavioral improvements (not security, but deliberate)

_(none yet for M1 — add as the module loop surfaces them)_

## Platform / environment differences

- [ ] `version`: `nmap-rs --version` carries Rust build metadata and notes it is the
      port; the differential normalizes the version line. (Seeded; confirm at M1 CLI.)
