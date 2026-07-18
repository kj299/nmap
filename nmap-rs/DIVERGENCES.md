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

- [x] `sec-services-path` (`services.cc:134/140`, owner `core::ports`): C builds
      the fallback services-file path with `GetSystemDirectory(buf,480)` then
      `strcpy(buf+len, "\\drivers\\etc\\services")` — a latent CWE-120 overflow
      resting on a hardcoded `480` "be safe" assumption. Rust uses
      `PathBuf::join`, so the bound is structural and the overflow class is gone.
- [x] `sec-proto-name` (`output.cc:719`, owner `core::output`):
      `strcpy(protocol, IPPROTO2STR(...))` into a fixed buffer (CWE-120). Rust
      renders protocol names as `String`/`&str` with no fixed-size destination.
- [x] `sec-log-format` (`output.cc:923/928`, owner `core::output`):
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

## M1 output-format abbreviation (confirmed by the differential oracle)

The M1 differential (`tests/differential/`) compares the **semantic** scan result
— host status + open-port state/reason + closed/filtered counts — via
`project.py`, and all matrix cases MATCH C nmap 7.94. The comparison deliberately
projects away the following **intentional MVP renderer abbreviations**, documented
here so the format-level differential planned for M2/M3 treats them as known and
not as regressions. None is a fidelity bug in *what was scanned*; each is a
narrower *rendering* of the same result.

- **Collapsed non-open ports.** C nmap lists every scanned port individually (incl.
  `closed`/`filtered`) until a per-state count crosses its "Not shown" threshold;
  the MVP always collapses non-open ports into a single `<extraports>` / `Not shown`
  summary. `project.py` canonicalizes both to a per-(state,proto) count, so the
  *set* is verified even though per-closed-port identity is not rendered.
- **No decorative XML preamble.** The MVP omits `<!DOCTYPE nmaprun>`,
  `<?xml-stylesheet?>`, `<scaninfo>`, `<verbose>`, `<debugging>`, `<hostnames>`,
  `<times>`, `reason_ttl`, and `startstr`/`xmloutputversion` attributes. These are
  non-load-bearing for the connect scan and land with the output-fidelity pass.
- **Unknown-service labelling.** In `-oN` the MVP prints `unknown` in the SERVICE
  column (matching nmap); in `-oX`/`-oG` nmap emits an *empty* service field / no
  `<service>` element for an unknown port, whereas the MVP currently emits
  `name="unknown"`. Excluded from the projection (M1 does no `-sV`); flagged to
  reconcile in the output-fidelity pass so `-oX` consumers aren't misled.
- **`# Nmap ...` file banners / done-line.** nmap's `-oN`/`-oX`/`-oG` file format
  wraps output in `# Nmap <ver> scan initiated ... as: ...` / `# Nmap done at ...`
  comments and omits the interactive `Starting Nmap` line; the MVP uses its own
  banner/`Nmap done:` line. `project.py` and the format's comment convention make
  this invisible to the semantic diff.

- [x] `no-op-dns-flag` (`cli`, owner `core::options`): nmap-rs accepts `-n`
      (never-do-DNS) but prints a `warning: ignoring unrecognized option '-n'` to
      stderr because forward resolution is only performed for hostname targets
      under `-Pn` anyway — so `-n` is a semantic no-op in M1, not silently honored.
      Stderr-only; does not affect scan output or the differential projection.

## Milestone 3 — service/version detection (`-sV`)

- [x] `probedb-parse-degrade` (`core::probedb`, ports the parse half of
      `service_scan.cc`): the C parser `fatal()`s (aborts the whole process) on the
      first malformed byte of `nmap-service-probes` — a bad protocol, a missing
      delimiter, an unsupported probe-string escape, an out-of-range
      `rarity`/`totalwaitms`/`tcpwrappedms`, an unknown directive, a second NULL
      probe (`assert`), a second `Exclude`, or an `Exclude` after a Probe. Because
      `--versiondb <file>` makes this file **untrusted-shaped input**, the port
      instead *localizes* every failure: the offending line (or probe) is skipped,
      a `ProbeWarning{line, message}` is recorded, and parsing continues. A hostile
      or corrupt database degrades to "fewer probes" rather than aborting the scan,
      and never panics (proved by the `services_probes_parse` fuzz target). This is
      the same deliberate, safer-than-C divergence M1 made for `nmap-services`
      (`services-parse-degrade`). On the *shipped, well-formed* file the behavior is
      identical to C — the corpus differential parses it with **zero warnings** and
      the exact C structural counts (186 non-NULL probes + 1 NULL, 12,171 match
      rules), so the divergence is observable only on malformed input.
- [x] `probedb-waitms-rarity-keep-default` (`core::probedb`): where the C aborts on
      an out-of-range `rarity` (not `1..=9`) or `totalwaitms`/`tcpwrappedms` (not
      `[100, 300000]`), the port keeps the field's **default** value and warns,
      rather than clamping (which would silently alter timing) or aborting. A
      sub-case of `probedb-parse-degrade`, called out because it changes a value
      rather than dropping a whole line.
- [x] `probedb-fallback-unresolved` (`core::probedb`): the C `compileFallbacks()`
      resolves each `fallback` name to a probe pointer at load time and `fatal()`s
      on an unknown name. The port stores fallback **names** (comma/space-split,
      capped at `MAXFALLBACKS`=20) and defers resolution to the probe scheduler
      (a later M3 module), so a probe DB naming a not-yet-defined fallback loads
      instead of aborting. Not a behavior change for the shipped file; a robustness
      improvement for hand-edited databases. Resolution + its own divergence entry
      land with the scheduling slice.

## Platform / environment differences

- [x] `version`: `nmap-rs --version` carries Rust build metadata and notes it is the
      port; the differential compares the semantic projection, which excludes the
      version banner entirely. (Confirmed at M1 CLI.)
