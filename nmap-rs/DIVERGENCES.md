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

- [x] `services-parse-degrade` (`services.cc` `nmap_services_init`, owner
      `core::ports`): the C `fatal()`s and aborts the whole scan on a malformed
      `nmap-services` line (bad ratio, `/0` denominator, unknown protocol). The
      Rust `ServiceTable::parse` **skips** the offending line and keeps going, so
      a corrupt or partially-edited data file degrades gracefully instead of
      taking the tool down (availability hardening). Verified: real 3.9 MB
      `nmap-services` parses to 27,461 entries; `top_ports(tcp,8)` matches nmap's
      canonical `[80,23,443,21,22,25,3389,110]`.

## Deferred `-p` syntax (rejected explicitly, never silently ignored)

`core::ports::parse_port_spec` returns `PortSpecError::Unsupported` for syntax
accepted by nmap but not yet ported — `[...]` top-ports brackets, `*`/`?`
wildcard service masks, and `P:` protocol scan. Numeric ranges/lists,
`T:`/`U:`/`S:` prefixes, open ranges, and exact service names are supported.
These land in a later slice; until then they error rather than mis-scan.

## Platform / environment differences

- [ ] `version`: `nmap-rs --version` carries Rust build metadata and notes it is the
      port; the differential normalizes the version line. (Seeded; confirm at M1 CLI.)
