# Milestone 3 — Service / Version Detection (`-sV`): Phase-0 Analysis

*A safety-first pre-mortem, written before any Rust, so the code has a thesis to
answer to. Shareable narrative version:*
<https://claude.ai/code/artifact/1d88f202-ac67-492a-b65e-5866ba961027>

Status: **Phase 0 (analysis) — proposed port order below awaits approval before
any Rust is written** (kit requirement).

---

## 1. What M3 is

Port nmap's `-sV` service/version detection: send probes to open ports and match
the replies against `nmap-service-probes` to identify the product, version, and
CPE. It rides the Milestone-2 connect engine — **no new privilege, no raw
packets, no Npcap** — which keeps the scariest work (raw scanning, M4) deferred.

**C sources.** `service_scan.cc` (2,896 LOC), `service_scan.h` (335),
`nmap_ftp.cc` (355, the FTP-bounce helper). Data file `nmap-service-probes`
(2.5 MB, 17,154 lines).

---

## 2. Threat model — the risk class changed

Unlike M1/M2 (parsing + concurrency), M3's residual risk is **algorithmic** and
**hostile-input parsing**, not memory corruption.

- **Boundary A — service banners (network, untrusted).** Every byte the regex
  engine matches is chosen by whoever runs on the target port. The match engine
  and version substitution are the #1 fuzz target: no panic, no unbounded
  allocation, and **no unbounded backtracking** (ReDoS against the scanner).
- **Boundary B — the probe DB (data, untrusted-shaped).** `--versiondb` can point
  at an arbitrary file. Same shape as M1's `nmap-services` parser → **degrade on
  malformed lines, never `fatal()`** (reuse the ported skip-and-continue
  divergence).
- **Privilege:** none.

**Phase-0 flaw scan** (`scan_c_flaws.py` over `service_scan.cc` + `nmap_ftp.cc`):
**0 classic sinks** — modern C++ over `std::string`, not `strcpy`-era C. Confirms
the risk is the regex engine and the parsers, not buffer handling.

---

## 3. The empirical census — the decision input

nmap already runs **PCRE2** (`pcre2_compile`/`pcre2_match`) and has to leash it
against catastrophic backtracking: `match_limit = 50000`,
`recursion/depth_limit = 1000` (`service_scan.cc:461–467`). That is the honest
cost of a backtracking engine — the bound can't be *proven*, so it's *imposed*.

Rust's `regex` crate is a finite-automaton engine: **no backreferences, no
lookaround, and a linear-time guarantee** — ReDoS is unexpressible. The Phase-0
question is therefore empirical: *how much of the real corpus fits inside that
guarantee?*

Parsing all `match`/`softmatch` lines and classifying each regex by the features
that **force** a backtracking engine:

| Backtracking-only feature | syntax | patterns |
|---|---|---:|
| Negative lookahead | `(?!…)` | 671 |
| Atomic group | `(?>…)` | 83 |
| Possessive quantifier | `a++`, `.*+` | 77 |
| Backreference | `\1`–`\9` | 16 |
| Positive lookahead | `(?=…)` | 13 |
| Named backreference | `\k<n>` | 7 |
| Lookbehind | `(?<=…)` | 2 |

- **Total match patterns: 12,171** (11,968 hard + 203 soft).
- **Need a backtracking engine: 853 (7.01%)** — distinct patterns using ≥ 1 of the
  features above (the per-feature counts sum higher because a few patterns use more
  than one).
- **Fit pure-Rust `regex`: 11,318 (92.99%)** — provably linear-time, ReDoS-immune.
- Inline flags `(?i)` and Unicode classes `\p{…}`: **0 occurrences**, and both are
  supported by `regex` regardless.

> Reproduce: `python3 nmap-rs/docs/service_probes_regex_census.py nmap-service-probes`

---

## 4. The decision — a hybrid, quarantined engine

The number decides the architecture:

- **Default path (~92.9%): pure `regex`.** Compile every pattern here first; the
  overwhelming majority succeed. Strictly safer than the C — the hazard the
  `match_limit` leash exists to contain *cannot occur*.
- **Fallback path (~7.1%): `fancy-regex`.** It wraps the same `regex` for the
  linear core and adds bounded backtracking only for lookaround/backrefs, with an
  explicit **backtrack-step limit** — the direct analog of nmap's `match_limit`.
  The unsafe-by-nature engine is confined to a measured minority, and still
  bounded.
- **Rejected: PCRE2 via FFI.** Faithful, but re-imports exactly what the rewrite
  exists to shed — C memory management, `unsafe` in `sys`, and unbounded
  backtracking for *all* patterns. Kept only as a documented break-glass option if
  a specific probe proves un-portable.

**Net effect:** 12,171 regexes, and the dangerous engine now runs on 853 of them
instead of all of them; the other ~93% carry a guarantee the original couldn't
state. Any pattern neither engine accepts, or whose semantics differ, is logged in
`DIVERGENCES.md` — never silently dropped; the corpus-validation spike turns
"which patterns differ" into a committed list.

---

## 5. Proposed port order (leaf-first; each module through the six gates)

0. **Spike — corpus validation** (before scheduling): compile all 12,171 patterns
   through `regex`, rejects through `fancy-regex`; emit exact accept/reject/deferred
   lists + confidence rating on the 7%.
1. **`core::probedb`** — the `nmap-service-probes` parser (Probe / match / softmatch
   / ports / rarity). *Fuzzed* (untrusted-shaped); degrade on malformed lines.
2. **`core::matcher`** — the hybrid regex engine + soft/hard-match state machine.
   *Fuzzed* (hostile banners — the #1 target) + *sanitized*.
3. **`core::versioninfo`** — `$1`/`$P`/`$SUBST` capture substitution into
   product/version/CPE. *Fuzzed*; overflow-checked, no fixed buffers.
4. **`sys`** — probe scheduling (rarity/intensity) over the M2 connect engine; read
   banners, feed the matcher. *Differential*.
5. **`cli`** — wire `-sV`, `--version-intensity`, and the VERSION output columns
   (normal/XML/grep). *Differential* vs C `nmap -sV`.

**Oracle:** local listeners emitting fixed banners (HTTP server line, SSH ident,
FTP greeting); `nmap -sV` vs `nmap-rs -sV` on the semantic projection
(product / version / CPE), exact-or-ledgered.

---

## 6. What this milestone is meant to teach (transferable)

1. **Measure the corpus before choosing the tool.** "Can Rust `regex` replace
   PCRE?" is unanswerable in the abstract and a two-minute script in the concrete.
2. **A rewrite shrinks the hazard surface, it doesn't relocate it.** The win is
   that the backtracking engine runs on 7% of inputs instead of 100%.
3. **Quarantine the unavoidable risk and bound it** — one path, one crate, one
   explicit step-limit, the same discipline as isolating `unsafe` to one crate.

The milestone's retrospective will patch the kit with what the 7% actually cost.
