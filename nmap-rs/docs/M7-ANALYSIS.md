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
| modules tracked | 73 |
| modules through all six gates | 44 |
| fuzz targets | 47 |
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

This is the one that should worry us.

| | `core` | `sys` |
|---|---|---|
| lines | 32,797 | 6,392 |
| `unsafe` blocks | **0** | **11** |
| fuzz targets exercising it | **47** | **0** |
| ASan / UBSan | via cargo-fuzz | **none** |
| Miri | yes | yes, but cannot execute FFI |

All 47 fuzz targets import `nmap_core`; **not one imports `nmap_sys`**. CI has
no ASan or UBSan job at all. TSan's absence *is* considered and documented
(LESSONS #10 — unsound over a tokio runtime), but ASan/UBSan's absence is not
recorded anywhere.

So the crate holding 100% of the `unsafe`, the raw sockets, the FFI and the
packet-capture bindings has the weakest dynamic coverage in the project, and
its only sanitizer is the one that cannot run its FFI paths. That inverts what
the kit's threat model assumes.

This is the top technical item for M7.

---

## 4. Cutover criteria, walked

From `PLAN.md` §"Milestone 7" and the kit's Phase 5.

| criterion | status |
|---|---|
| all target modules through six gates | ⚠️ 44/73 recorded; see §3 for the honest split |
| differential green modulo ledgered divergences | ✅ every milestone's differential runs in CI |
| fuzz seeded + clean | ✅ for `core` (47 targets); ❌ nothing for `sys` |
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
4. **M7.3 — CLI parity triage.** Not all 86 missing options are equal. Sort
   them into: *must implement before cutover* (the constraint options —
   `--exclude`, `-T`, `--scan-delay`, `--max-*`, `-iL`, `--top-ports`),
   *should implement* (output formats `-oA`/`-oS`/`-oM`, `--open`, `--reason`),
   and *may stay unimplemented and refused* (`--thc`, `--nogcc`,
   `--deprecated-xml-osclass`). With §2 in place, an unimplemented option is
   now honest rather than dangerous, so this can be staged.
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

1. **What does "cutover" mean for this project?** `PLAN.md` says "keep C nmap as
   oracle through one overlap release, then archive". But `nmap-rs` implements
   14/100 long options. Cutover cannot mean "replaces nmap for everyone" yet.
   Is the target (a) a *drop-in* replacement for the flags it supports, refusing
   the rest — which is roughly where §2 leaves it today; or (b) full CLI parity
   first? These are very different amounts of work, and everything in §5 after
   M7.2 depends on the answer.
2. **Does the `n/a` gate state get added to the kit?** It affects the kit
   itself, not just this port, so it is a kit-level decision.
3. **Is `sys` fuzzing in scope for M7, or its own milestone?** Fuzzing raw-socket
   and capture code needs harness work (synthetic packet injection) that is
   closer to a milestone than a task.
4. **Still unanswered from M6**: the M6.0 port order, and whether M6 resumes
   after M7. M6.1 and M6.2 are merged and were deliberately chosen to be
   independent of the Lua-runtime decision; **M6.3 is not**, so M6 is blocked at
   that decision regardless of what M7 does.
