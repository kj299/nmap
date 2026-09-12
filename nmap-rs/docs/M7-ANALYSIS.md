# M7 — cutover readiness: what actually blocks replacing C nmap

Phase-0 analysis for Milestone 7. Written before any M7 porting work, in the
same shape as `M6-ANALYSIS.md`: measure first, then propose an order, then stop
for approval.

The question M7 has to answer is narrow and unforgiving. Not "is the Rust
good?" — the six gates already answer that per module — but **"can a person
replace `nmap` with `nmap-rs` on their machine and not be surprised?"** Almost
everything below follows from taking that question literally.

---

## 1. Where the port stands

| | |
|---|---|
| C nmap (`*.cc` + `*.h`) | 55,402 lines |
| `nmap-rs` core / sys / cli | 32,797 / 6,392 / 958 lines |
| modules tracked | 81 (73 at the start of M7; `drift` could not see 25 sub-modules — see §3d) |
| modules through every gate that applies | 79 of 81 (44 at the start of M7) |
| fuzz targets | 48 (47 at the start of M7; `osprobe_demux` added in M7.1) |
| `unsafe` blocks | 11, all documented, **all in `sys`** |
| supply chain | `cargo audit` + `cargo deny` clean (advisories, bans, licenses, sources) |

Zero `unsafe` in `core` and `cli` is a real result and worth stating plainly:
the 32,797-line parsing-and-logic crate contains none, and the entire residual
risk surface is 11 blocks in one 6,392-line crate.

---

## 2. The finding that matters most: the CLI ignored its own safety options

Found by running the binary rather than reading it.

`nmap-rs` implements **14 of C nmap's 100 long options**. Until this milestone
it handled the other 86 by printing a warning and **scanning anyway**. Two
things went wrong at once, and the second is worse than the first:

1. Most unimplemented options *constrain* a scan — `--exclude`,
   `--excludefile`, `--scan-delay`, `-T`, `--max-retries`, `--max-parallelism`,
   `--host-timeout`, `--top-ports`. Ignoring a constraint scans **more hosts, or
   faster**, than the operator asked for.
2. An unimplemented option that takes a value left that value in `argv`, where
   the positional handler collected it as a **target**.

Put together:

```console
$ nmap-rs -sT -p 80 127.0.0.1                          # 1 host scanned
$ nmap-rs --exclude 127.0.0.2 -sT -p 80 127.0.0.1      # 2 hosts scanned
Nmap scan report for 127.0.0.2      <-- the address named in --exclude
Nmap scan report for 127.0.0.1
```

**Naming a host in `--exclude` was the thing that got it scanned.** For a
network scanner that is the worst available failure direction: the operator
took an explicit step to protect a host and the tool read it as a request.

This was also an **unledgered divergence from the C**. nmap does not warn and
continue — an unrecognised option reaches `case '?'` in the `getopt_long_only`
loop (`nmap.cc:653`) and calls `error()` then `exit(-1)`, scanning nothing.

**Fixed in this milestone**: `nmap-rs` now refuses to scan, names the offending
options, and exits non-zero. Pinned by `crates/cli/tests/fail_closed.rs`, whose
three behavioural tests all fail against the old code.

The general rule this establishes, and which the rest of M7 should follow:
**a scanner fails closed.** When in doubt, scan less.

---

## 3. The gate gap, honestly split

The tracker shows 29 of 73 modules short of the final gate. That number is
misleading in both directions, so it is worth splitting three ways.

> **M7.2 correction.** The three-way split below was derived by reading names, and
> two of its three numbers were wrong. The tracker showed 73 modules; the port ships
> **81**, because `drift` only ever read `lib.rs` and 25 sub-modules (`headers::*`,
> `osdb::*`, `osprobe::*`, `nse::*`, `sigstore::*`) were outside its walk — it
> reported "56 shipped, 0 untracked" and was wrong twice over. This workflow had also
> never wired the drift step at all. "19 covered but unrecorded" was really **14**:
> six modules were credited to a fuzz target that merely shared their name
> (`sys::ndp` to `ndp_advert`, which fuzzes `core::ndp` — the `sys` module parses
> nothing), and one, `core::osdb::parse`, was missed in the other direction because an
> inherent impl need not live in the module its type is declared in. The counts below
> are left as written; §3d records what the table says now.

### 3a. Met in fact, unrecorded — 19 modules

These sit at `differential` or `fuzzed` in `progress.json`, but a fuzz target
covering them already exists and runs in CI:

`core::macvendor`, `core::servicefp`, `core::osdb::{expr,parse,score,model}`,
`core::osprobe::{analyze,build,seq,icmpreply,tcpreply}`,
`core::fingerprint_store`, `core::sigstore`, `options`, `sys::fpengine`,
`sys::ndp`, `sys::osscan`, `sys::scan`, `sys::sigstore`.

Likewise `sanitized`: Miri runs workspace-wide in CI and passes (733 tests, no
UB), and `unsafe_audited` is satisfied globally (11/11 documented). So most of
this is bookkeeping debt, not engineering debt.

**But bookkeeping debt is a cutover risk in its own right.** The whole point of
`progress.json` is to answer "is this ready?" without re-deriving it. A tracker
that lags reality cannot be used for a go/no-go decision, which is exactly what
cutover needs it for. It should be reconciled before, not during, cutover.

### 3b. No fuzz target, and probably correctly so — 10 modules

`cli`, `congestion`, `connect_scan`, `core::log`, `core::trace`, `engine`,
`model`, `net`, `output`, `timing`.

None is an untrusted-input parser; they are scheduling, rendering and state.
The kit's gate has no "not applicable" state, so they will sit at
`differential` forever and quietly drag the headline number down. **Decision
needed**: either add an explicit `n/a` state to the tracker with a recorded
reason per module, or write thin fuzz targets for the ones that do consume
attacker-influenced data (`output` renders hostnames and banners into XML —
that one probably *should* be fuzzed for injection, see §4).

### 3c. A real gap: the unsafe layer is the least-tested code

This is the one that should worry us — though **not for the reason stated here
originally**. M7.1 measured it and the first version of this section was wrong
twice. Both corrections are kept visible rather than quietly edited out, because
how the measurement went wrong is the more useful finding.

**What this section said first:**

> | | `core` | `sys` |
> |---|---|---|
> | fuzz targets exercising it | **47** | **0** |
> | ASan / UBSan | via cargo-fuzz | **none** |
> | Miri | yes | yes, but cannot execute FFI |
>
> All 47 fuzz targets import `nmap_core`; not one imports `nmap_sys`.

**Correction 1 — "`sys` has 0 fuzz targets" counts the wrong thing.** It is true
and it is close to meaningless. `sys` barely parses: it delegates to `core` and
keeps the I/O. `match_reply` is a five-line wrapper over `core::synscan::
match_syn_response`; `record` wraps `core::osprobe::demux::demux`; the NDP driver
wraps `core::ndp::resolve_from_frame`. That split is the unsafe-quarantine design
working exactly as intended, and a fuzz target per `sys` wrapper would measure the
wrapper, not the parser.

Cross-referencing every `core` function that takes raw bytes against what the 47
targets actually import gives the honest list. Almost everything is covered,
including transitively: `headers::icmpv6` and `headers::ipv6ext` via `parse_packet`,
`icmp_quote` via `match_syn`/`match_udp`/`match_flag`, and `sigstore::install`'s
path-traversal contract via `sigstore_manifest` — which already asserts the
single-component invariant `install` relies on, joined-path escape check included.

One genuine gap survived: **`core::osprobe::demux::{demux, tcp_timestamp}`**, called
from exactly one place — `sys/osscan.rs:39` — and fuzzed by nothing. It looks like an
internal helper of the `sys` driver and is in fact a frame parser whose own module
doc says its input is "entirely attacker-chosen". M7.1 adds `osprobe_demux`; it
survives 10,025,242 executions clean.

**Correction 2 — the unsafe was not under-tested, it was untested, and the reason
is a feature flag.** All 11 `unsafe` blocks are in `crates/sys/src/netif/ffi.rs`
behind `#[cfg(all(feature = "raw-ffi", unix))]`, and `raw-ffi` is off by default.
Follow that through every job that appeared to cover it:

| job | what it did with the 11 `unsafe` blocks |
|---|---|
| `cargo test --all` | compiled them out — 93 tests ran, the FFI test is the 94th |
| `cargo clippy --all-targets` | mentioned `ffi.rs` **0 times**, so `-D clippy::undocumented_unsafe_blocks` was a hard error aimed at code it never compiled |
| `miri` | runs **0** of those tests even with the feature on: the module is `#[cfg(all(test, not(miri)))]`, correctly, since Miri cannot call a foreign function |
| `msrv` | `cargo check --all-features` type-checked them; nothing ran |
| `unsafe-audit` | greps source text — the only gate that saw the file at all |

So the entire residual unsafe surface was type-checked once and grepped once, and
had never been executed under any dynamic check. Nothing turned out to be broken —
ASan over it passes 94/94 with leak detection on — but that is luck confirmed after
the fact, not a property anything was testing.

**And there is no UBSan.** rustc's `-Zsanitizer` accepts `address`, `leak`,
`memory`, `thread`, `cfi` and friends; `undefined` is rejected outright. The row
above promised a gate that cannot be built. Worse, the kit shipped a
`run_sanitizers.sh ubsan` mode that invoked exactly that flag — dead on any Rust
project, and unnoticed because no port had ever wired the kit's sanitizers job.

**Corrected picture:**

| | `core` | `sys` |
|---|---|---|
| lines | 32,797 | 6,392 |
| `unsafe` blocks | **0** | **11**, all in one file, behind a non-default feature |
| byte-consuming parsers without a fuzz target | **1** (`osprobe::demux`, now closed) | 0 — it delegates to `core` |
| tests executing any `unsafe` | n/a | **1**, which no CI job ran |
| ASan | via cargo-fuzz | **now gated in CI, `--all-features`** |
| UBSan | does not exist for Rust | does not exist for Rust |
| Miri | yes | yes on the safe Rust; can never execute the FFI |

This was the top technical item for M7, and M7.1 closes it.

---

### 3d. What the tracker says after M7.2

**79 of 81** modules are complete on every gate that applies. The two that are not are
the deliverable of this section, not an oversight:

| module | why it is still short |
|---|---|
| `output` | renders attacker-controlled hostnames, service banners and TLS subjects into XML and grepable formats. C nmap has had escaping bugs here. **It needs a fuzz target** (§4, M7.4) and is deliberately left un-exempt so the table keeps saying so. |
| `options` | argv is operator-supplied rather than attacker-supplied, which is the usual argument for exempting it — but M7.3 adds `-iL` and `--excludefile`, which read *files*. Exempting it now would be exempting it a milestone before the premise stops holding. |

`output` is also the answer to why there is **no blanket `n/a` state** (Q2). It sits on
the same "not really a parser" list as the schedulers and renderers, looks exactly as
exemptable as they do, and is the one entry on that list that genuinely needs fuzzing.
An escape hatch wide enough to silence a module is wide enough to silence that one. So
exemptions are **per gate** and carry a **reason**, in the same shape as the divergence
ledger: 14 modules are exempt from `fuzzed` only, each with a written argument, each
still required to clear `differential`, `sanitized` and `unsafe_audited`. `show`
renders an exempt gate as `[-]`, never `[x]`.

The other half of the fix is that coverage is now **recorded rather than inferred** —
20 module→target mappings, checked in CI against the `[[bin]]` entries in
`fuzz/Cargo.toml`. That is what stops "19" and "14" from being arguable again.

## 4. Cutover criteria, walked

From `PLAN.md` §"Milestone 7" and the kit's Phase 5.

| criterion | status |
|---|---|
| all target modules through six gates | ⚠️ 44/73 recorded; see §3 for the honest split |
| differential green modulo ledgered divergences | ✅ every milestone's differential runs in CI |
| fuzz seeded + clean | ✅ 48 targets; the one uncovered byte parser (`osprobe::demux`) closed in M7.1 — see §3c for why "nothing for `sys`" was the wrong measurement |
| supply-chain clean | ✅ audit + deny clean |
| least-privilege verified | ❌ not yet assessed — see below |
| ASCII-default output | ❓ unverified |
| SBOM (`cargo cyclonedx`) | ❌ not wired |
| auditable build (`cargo auditable`) | ❌ not wired |
| signed releases | ⚠️ `core::sigstore` exists and is gated, but nothing signs a release |
| reproducible + checksummed | ❌ not attempted |
| Windows code-signing | ❌ not attempted |
| `DIVERGENCES.md` as release notes | ⚠️ 183 entries, written for engineers, not release-note shaped |

**Least privilege** deserves its own note. C nmap drops privileges in specific
places and supports `--privileged` / `--unprivileged` to override its own
detection. `nmap-rs` implements neither flag, and (before §2's fix) ignored
them. What the port actually does with capabilities on Linux, and whether it
holds `CAP_NET_RAW` longer than C does, is unmeasured. It should be measured
before cutover, not asserted.

**Output injection** is the other thing worth checking during cutover rather
than after: `output` renders attacker-influenced strings — hostnames, service
banners, TLS subjects — into XML and grepable formats. C nmap has had escaping
bugs here historically. There is no fuzz target for it.

---

## 5. Proposed order

Leaf-first and risk-first, same discipline as M6:

1. **M7.0 — fail closed on unimplemented options.** ✅ Done in this milestone
   (§2). Small, safety-critical, and it unblocks honest parity work by making
   the gap visible instead of silent.
2. **M7.1 — close the `sys` coverage gap** (§3c). Fuzz targets for the parsing
   that `sys` does over network-supplied bytes, and an ASan/UBSan CI job over
   `sys`'s tests. This is where the unsafe is; it should not be the least-tested
   crate at cutover.
3. **M7.2 — reconcile `progress.json`** (§3a/3b), including a decision on an
   `n/a` gate state. Cheap, and cutover needs the tracker to be trustworthy.
4. **M7.3 — CLI parity triage.** ✅ Done — `docs/M7.3-CLI-PARITY.md`. All 102
   unimplemented options sorted into 24 MUST / 21 SHOULD / 51 REFUSE, with the
   MUST tier derived from a proposed **capability profile** rather than from a
   flag count (which is also the proposed answer to §6 Q1). Six options left the
   refusal set in the process at zero risk: `-r`, `--release-memory` and
   `--log-errors` join the `ALREADY_SATISFIED` carve-out (the last two are
   no-ops in C nmap *itself*), and `--oN`/`--oX`/`--oG` turned out to be a real
   parity bug — the long spellings of three implemented output formats were
   refused because the matcher tested only the short one.
5. **M7.4 — output-injection review** of the XML/grepable writers, with fuzzing
   (§4).
6. **M7.5 — release engineering.** SBOM, `cargo auditable`, reproducible build,
   signing, and turning `DIVERGENCES.md` into release notes.
7. **M7.6 — subprojects**, `ncat` and `nping`, each its own kit cycle. Genuinely
   separable and lowest priority.

---

## 6. Open questions for approval

Per the kit, these need answering before M7 porting work proceeds beyond
M7.0/M7.1.

1. ~~**What does "cutover" mean for this project?**~~ **M7.3 proposes an answer,
   and it is neither (a) nor (b) — both measure cutover in flags, and flags are
   the wrong unit.** (b) full parity is a second project: a third of the 86
   missing options are blocked behind subsystems this port has deliberately not
   built. (a) "drop-in for the flags it supports" is true of any program if you
   pick the flags afterwards; operators type the invocation their runbook already
   contains, and `-iL targets.txt --exclude 10.0.0.5 -T4` is an ordinary one that
   (a) refuses three times over.
   The proposal is a **capability profile** — a written statement of the scanning
   `nmap-rs` is a genuine drop-in for, everything outside it refused — from which
   a finite, testable 24-option MUST tier falls out. Full triage of all 102
   unimplemented options, the profile, and a five-step order in
   **`docs/M7.3-CLI-PARITY.md`**. It still needs an owner's yes, and it surfaces
   one question a triage cannot settle alone: whether the evasion suite (decoys,
   source and MAC spoofing, fragmentation) is "not yet" or "not ever" — see §5
   of that document.
2. ~~**Does the `n/a` gate state get added to the kit?**~~ **Answered by M7.2: no —
   a per-gate exemption with a written reason instead.** A module is not
   inapplicable; a specific *gate* is inapplicable to it, and a module-level flag
   throws away which gates still apply (a scheduler exempt from fuzzing must still be
   differential-clean and unsafe-audited). The decisive argument against the blanket
   state is `output`: it sits on §3b's "not really a parser" list, looks exactly as
   exemptable as the schedulers beside it, and is the one entry on that list that
   genuinely needs a fuzz target. One escape hatch wide enough for the schedulers is
   wide enough for it. Exemptions therefore name a gate, carry a reason CI checks, and
   render as `[-]` rather than `[x]`. Coverage is recorded rather than inferred for
   the same reason — see §3d.
3. ~~**Is `sys` fuzzing in scope for M7, or its own milestone?**~~ **Answered by
   M7.1, and the question was based on a wrong premise.** It assumed fuzzing `sys`
   meant building a synthetic packet-injection harness around raw sockets and
   capture — a milestone's worth of work. It does not, because `sys` does not parse:
   every byte-level decision it appears to make is delegated to a pure function in
   `core` that a plain `fuzz_target!` can call directly. One target (`osprobe_demux`)
   closed the only real gap, in an afternoon rather than a milestone. What `sys`
   actually needed was not fuzzing at all but a **sanitizer that compiles its
   feature-gated `unsafe`** — see §3c.
4. **Still unanswered from M6**: the M6.0 port order, and whether M6 resumes
   after M7. M6.1 and M6.2 are merged and were deliberately chosen to be
   independent of the Lua-runtime decision; **M6.3 is not**, so M6 is blocked at
   that decision regardless of what M7 does.
