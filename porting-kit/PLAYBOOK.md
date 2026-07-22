# PLAYBOOK — porting a C codebase to Rust, safely

A repeatable, codebase-agnostic procedure for rewriting C in Rust with **safety
and security as the primary goal** — distilled from the winlsof port (see
[`RETROSPECTIVE-lsof.md`](RETROSPECTIVE-lsof.md)) and designed to compound after
every use (see [`CLAUDE.md`](CLAUDE.md) and [`LESSONS.md`](LESSONS.md)).

**Prime directive.** The Rust rewrite exists to be *safer and more secure* than
the C, not merely equivalent. Two consequences run through every phase:

1. **The C is a specification, not an authority.** It may contain
   vulnerabilities, UB, and latent bugs. Faithfully re-implementing a CVE is a
   failure, not fidelity. Every divergence from C behavior is triaged, and the
   intentional ones (where C was wrong) are recorded — never silently matched.
2. **Every module clears the safety gates before it merges.** Compiling and
   matching the oracle is the floor, not the bar. The bar is: unsafe audited,
   fuzzed, sanitizer-clean, supply-chain-clean.

Nothing here assumes a target OS or that the port is cross-platform. If your port
*is* cross-platform, keep a platform seam — but that is an isolation detail, not
this playbook's focus.

Read [`SECURITY-CHECKLIST.md`](SECURITY-CHECKLIST.md) alongside this; it is the
per-module control ledger the phases refer to.

---

## Phase 0 — Inventory & threat model

**Goal:** know the terrain and the risk before writing Rust.

**Do:**
- Enumerate the C: modules, LOC, external deps, the syscall/ioctl/FFI surface,
  global mutable state, macros, the build system. `harnesses/progress/progress.py
  --init` seeds the module table from this.
- **Scan the C for vulnerability classes** — `harnesses/c-flaw-scan/scan_c_flaws.py`
  flags the classic sinks (unchecked `memcpy`/`strcpy`/`sprintf`, `alloca`,
  integer-overflow-before-`malloc`, `system`/`popen`, format-string,
  `gets`, TOCTOU pairs). Every hit becomes a note on the owning module: *do not
  port this bug — fix it, and log the fix as an intentional divergence.*
  A scanner is only useful if it is *trusted*: tune it for signal-to-noise
  against the real target before relying on it — a check that cries wolf gets
  muted, and the real flaws drown (LESSONS #2: the format-string check once
  produced 828 false positives on lsof, burying ~215 real candidates).
  **Confirm the scanner actually reads the target's languages before believing a
  low count.** A "0 flaws" result on a large codebase usually means the scanner
  glob missed the files, not that the code is clean — a scanner that reads nothing
  is worse than none because it reports *clean* (LESSONS #6: `scan_c_flaws.py`
  globbed only `.c`/`.h` and silently skipped nmap's ~9.4k LOC of C++ `.cc`,
  reporting nothing until the extension set was widened).
- **Classify the FFI/syscall surface by failure mode** (LESSONS #1). For each
  external call the port will make, record three properties: can it **block
  indefinitely** (→ needs a timeout / worker thread / a design that avoids it),
  does it need **privilege**, does its behavior **vary by OS/version**? This is
  what makes Phase 1's "spike the scary module" rule actually fire. The winlsof
  hang cost seven commits precisely because `NtQueryObject`'s blocking behavior
  was never classified up front — the spike-first rule can't trigger on a hazard
  no one wrote down.
- **For each FFI item, record a fourth property: does a *vetted, maintained, safe*
  crate already wrap it? — and if so, make that crate the default backend, hand-FFI
  a feature-gated escape hatch** (LESSONS #18). The prime directive is *safer than
  the C*, and the safest `unsafe` is the one you never write: a well-audited wrapper
  crate moves the `unsafe` (and its upstream fuzzing/CI/soak time) out of your tree
  entirely. M4 was scoped as "the milestone where `unsafe` lives" and budgeted a
  hand-FFI raw layer; a mid-milestone review found `netdev`/`socket2`/`pcap` already
  cover interface enumeration, raw L3 send, and L2 capture safely, and the default
  build shipped with **0 first-party `unsafe`** (11 documented blocks, all in an
  *optional* `getifaddrs` escape hatch that is off by default). That the review was
  *user-prompted*, not kit-prompted, is the gap this closes — the safe-crate check
  belongs in the Phase-0 classification so the next FFI milestone starts
  safe-crate-first instead of discovering it after writing the `unsafe`. Vet the
  crate like any dependency (maintained, audited, license/advisory-clean via the
  supply-chain gate); reserve hand-FFI for the surface no safe crate covers (an
  Npcap-class driver), and keep it behind a feature flag with a cross-check test
  against the safe default. This is the **Option-C pattern**; see
  `ARCHITECTURE-TEMPLATE.md`.
- Write a one-page **threat model**: trust boundaries (untrusted input, privilege
  transitions, IPC, parsing of external data), and what "secure" means for this
  tool. `SECURITY-CHECKLIST.md` has the template.

**Entry criteria:** access to the C source and its build.
**Exit criteria:** module inventory table exists; C-flaw scan run and triaged;
threat model written.
**Artifacts:** `progress` table, `c-flaw-scan` report, `THREAT-MODEL.md`.
**lsof failure modes this prevents:** going straight to code and discovering the
scary module (the `NtQueryObject` hang) mid-implementation. Inventory surfaces
the hazards first.

---

## Phase 1 — Dependency graph & port order

**Goal:** an order that lets each module be tested against the oracle the moment
it lands.

**Do:**
- Build the module dependency graph (includes + call graph; `cflow`/`clangd` or a
  grep pass). Choose order by these criteria, in priority:
  1. **Roots before dependents** — port what others need first (in lsof: the
     process model before the files that hang off it).
  2. **Cheapest-and-safest-first among independents** — bank easy wins, harden
     the loop and harnesses on low-risk modules before the deep end.
  3. **Spike the known-scary module before you schedule it** (see Phase 4's
     "spike" note) — do not let a hazard ambush you inside its port.
- Prefer *capability-phased* slices (a user-visible feature end-to-end) over
  strict leaf-first when the codebase is a tool — it keeps every phase shippable
  and testable.

**Entry criteria:** Phase 0 inventory.
**Exit criteria:** ordered module list with a one-line rationale each; hazards
flagged for a pre-port spike.
**Artifacts:** ordered list in the `progress` table.
**lsof failure modes this prevents:** ad-hoc order that defers integration risk.
winlsof's phase order was sound; its one miss was not spiking the hang first.

---

## Phase 2 — Establish the oracle (before any Rust)

**Goal:** a reference you can diff against — while remembering it may be wrong.

**Do:**
- Lock the C binary at a known commit. Capture golden outputs across a
  **documented input matrix** (`harnesses/differential/input-matrix.example.toml`)
  with `harnesses/golden/golden.py capture`.
- **Detect oracle nondeterminism up front** — `golden.py` runs each input N times
  and flags fields that vary (PIDs, timestamps, addresses, ordering). Those feed
  the normalization rules (`harnesses/differential/normalize.py`), so a real
  regression isn't masked by noise and noise isn't mistaken for a regression.
- If the reference binary **cannot run on your dev/target environment** (winlsof:
  C lsof doesn't run on Windows), substitute:
  - **structural golden tests** for output *format* (columns, field codes, JSON
    shape), and
  - **independent oracles** for the *data* (native tools that report the same
    facts a different way).
- **Harden the harness for its host** (LESSONS #1). The test harness is software,
  and it runs in a shell with its own encoding/quoting model that *will* bite —
  winlsof spent six commits on PowerShell-5.1 / Windows-1252 breakage in the
  harness itself. Two defenses: write kit-level harnesses in a portable language
  (these are Python + POSIX sh on purpose, not the target's shell), and pin the
  tool's default output to the lowest-common-denominator encoding of the target's
  default shell (winlsof: ASCII default, UTF-8 opt-in).
- Stand up an **intentional-divergence ledger** (`DIVERGENCES.md`, template in
  the skeleton): every place the Rust will *deliberately* differ from C —
  starting with the Phase-0 flaw scan's findings.

**Entry criteria:** ordered module list.
**Exit criteria:** golden corpus captured + versioned; nondeterminism map;
normalization rules; divergence ledger seeded from the flaw scan.
**Artifacts:** `golden/corpus/`, `normalize.py` rules, `DIVERGENCES.md`.
**lsof failure modes this prevents:** the empty-result "bare header" and the
bare-`n` `-F` field shipped because there was no format oracle pinning them.

---

## Phase 3 — Architecture skeleton (unsafe quarantine)

**Goal:** a workspace shape that makes safety structural, not a review burden.

**Do:** copy `skeleton/` (see [`ARCHITECTURE-TEMPLATE.md`](ARCHITECTURE-TEMPLATE.md)).
The invariant it encodes:
- **`core` crate: `#![forbid(unsafe_code)]`.** Pure logic, data model, the
  algorithm. Testable everywhere, no FFI. This is where most of the port lives.
- **`sys` crate: the only place `unsafe` is allowed.** Every raw FFI call is
  wrapped in a small, audited safe function; every OS resource is an RAII type
  (close/free/drop-privilege on `Drop`). This kills use-after-free, leak, and
  privilege-held-too-long by construction.
- **`cli` crate:** thin; parse → build request → call core → render.
- **Scaffold observability on day one:** a `TRACE` env-gated phase logger. Do not
  wait for the first hang to add it.

**Environment preflight** (LESSONS #1): before the loop, confirm the toolchain
target actually links here (winlsof lost time to an MSVC-vs-GNU linker mismatch)
and that the build directory is not a synced/locked folder (OneDrive locked
`target\` → `os error 5`). Cheap checks that prevent days of "is it my code or my
machine?". **Pin the toolchain** so local `cargo fmt`/`clippy` run the exact
versions CI does: `skeleton/` ships a `rust-toolchain.toml` (exact `channel` +
`components`), and the CI stable jobs read it (`@master` + pinned `toolchain:`)
rather than floating `@stable`. A floating stable silently upgrades under you and
fails the PR on a rustfmt reflow or new clippy lint you never ran — it bit two M4
slices (LESSONS #16). Bump the pin deliberately, in its own PR.

**Entry criteria:** oracle in place.
**Exit criteria:** workspace builds; `core` is `forbid(unsafe_code)`; unsafe-audit
gate wired into CI (`harnesses/unsafe-audit`); trace logger present; environment
preflight clean.
**Artifacts:** the workspace; CI config from `harnesses/ci/porting-ci.template.yml`.
**lsof failure modes this prevents:** scattered `unsafe` (winlsof kept 0 in core /
144 in the sys layer — but only 91 documented; the gate makes the gap a build
failure). Tracing added reactively at hang-fix step 4 of 5.

---

## Phase 4 — The module port loop (per module)

**Goal:** each module ends safer than its C original, proven, before merge.

For a hazardous module (flagged in Phase 1), **spike first**: a timeboxed
experiment on the one scary syscall/idiom to learn its behavior (does it block?
need privilege? vary by version?) *before* committing to a design. Record the
result. This is the single highest-ROI habit in the retrospective.

**For a *research-grade* capability — one that might be impossible, not merely
hard** (winlsof: socket-FD correlation, byte-range locks, AF_UNIX/raw) — run the
**spike-and-gate ritual** instead of an open-ended attempt (LESSONS #1). It was
winlsof's biggest win: the hard gaps became the cheap ones. Steps: (a) rate
**effort** (S/M/L) and **confidence** a safe/public solution exists (Low/Med/
High); (b) write a **decision gate** *before* coding — the concrete signal that
says "stop, document as a platform limit"; (c) on hitting the gate, do a **pivot
check** — is there an adjacent, reachable goal? (winlsof's ETW spike couldn't get
the "real FD" but pivoted to extending `-i` to raw/ICMP/AF_UNIX, which shipped).
A closed sub-goal must not kill the shippable one beside it.

**A spike's decision gate must include *teardown*, not just steady-state — and the
stand-in must match the real API's *blocking/cancellation* semantics, not just its
data-flow** (LESSONS #17). A liveness spike naturally measures the hot path (does a
frame arrive? how fast? does it busy-spin?) and can pass every such criterion while
the design still deadlocks *on shutdown* — the state the throughput test never
enters. M4's pcap-in-async spike (`SPIKES.md` M4-1) gated on latency, no-busy-spin,
and no-readiness-fd, all met by a **BlockingThread → channel** design with an RAII
`Drop`-join; it shipped a hang because a blocking-capture thread against an *idle*
link cannot be woken for its join, and the spike's `std`-socket stand-in silently
had cancellation the real API (libpcap's blocking read ignores its timeout on an
idle link) lacks. So: (1) every spike of a resource-holding or blocking-in-a-thread
design must add a gate criterion **"prove it can be *stopped while idle*, cleanly,
within a bounded time"** — exercise `Drop`/cancel with no traffic in flight, not
just under load; and (2) when a spike uses a stand-in for the real API, the stand-in
must reproduce the property under test — for a *liveness* spike that means matching
**how the call blocks and how it unblocks** (a `std` `recv` is not a model of
`pcap_next_ex` blocking mode). If you can't model teardown faithfully, the spike is
not discharged until the real resource's teardown is tested (see gate 4 below).

Then the loop — each step is a CI-enforced gate:

1. **Port** into `core` (or a safe wrapper in `sys`). Translate C idioms to Rust:
   the "call-twice-for-size" buffer dance → a growing `Vec` with length checks;
   pointer arithmetic over structs → slices + `repr(C)` with bounds; unions/FAMs →
   audited casts with a `// SAFETY:` proof; integer math → checked/`saturating`.
   **A C byte-at-a-time parser stays byte-oriented — port it over `&[u8]`, not
   `&str`/`chars()`** (LESSONS #12). C reads its input a `char` (one byte) at a
   time and never asserts UTF-8; the input — a data file loaded via `--versiondb`,
   a network banner, a raw packet — is *binary*. Decoding it to `&str` first is
   both wrong (non-UTF-8 bytes are legal input the C accepts) and a **new panic
   class the C never had**: indexing/slicing on a `char` boundary panics
   mid-codepoint on a multibyte byte (nmap's `next_template` read a probe
   delimiter as `c as char`, mis-sized `len_utf8`, and sliced mid-codepoint — a
   fuzz-found panic). Reach for `&str` only where the field is *proven* text, and
   even then via `from_utf8` returning an error, never a slice-and-hope. This is
   why M3's regex engine is `regex::bytes` (Unicode off), not the `&str` API.
2. **Differential-test** against the oracle (`harnesses/differential/diff_run.py`).
   A divergence is a *triage*, not an auto-fail: {Rust bug → fix} vs {C bug →
   log in `DIVERGENCES.md`, keep the safe behavior}. The verdict is **stdout AND
   exit code** (LESSONS #4): a rewrite that prints the right thing but returns
   the wrong status is not a match — lsof exits 1 on no-match and scripts branch
   on it; `--ignore-exit` opts out for tools without stable codes. This gate is
   also the **liveness backstop** (LESSONS #1): a hang is not UB, so sanitizers
   won't see it — the harness's per-case timeout marks a wedged run as
   `<<TIMEOUT>>` and fails it. Treat a timeout as a design smell (an unbounded
   blocking call on the hot path) — the winlsof fix was to *avoid* the blocking
   call, not wrap it.
   When the port **intentionally renders a subset** of the C output (an MVP that
   abbreviates, e.g. nmap-rs collapsing closed ports into one summary line while C
   nmap lists each), do **not** diff raw output: `diff_run.py` is case-granular, so
   you either drown in intentional divergences or ledger the whole case — which
   blinds it to real regressions inside that case. Instead point `--oracle`/`--rust`
   at thin wrappers that emit a **canonical semantic projection** (the load-bearing
   result only — for a scanner: host state + open-port state/reason + per-state
   counts), canonicalizing *both* representations to the same shape. Then a genuine
   regression still breaks the match while the ledgered abbreviation stays invisible
   (LESSONS #7). Full output-format parity becomes its own later differential.
   The same projection discipline resolves a **second** blind spot: when *both*
   tools derive an output field from a **versioned data file** they ship
   independently (nmap's `nmap-service-probes`, `nmap-os-db`, `nmap-mac-prefixes`),
   that field's *value* is a property of the file version, not of your port.
   Projecting it turns the differential into a data-file-version check that fails
   whenever the two trees ship different DBs — a false divergence that trains you
   to ignore the gate (LESSONS #13). Project only the **version-independent
   semantic finding** (for `-sV`: the detected service *name* on a `method="probed"`
   port, not the product/version string; for `-O`: that a match occurred, not the
   OS label). Pin the data-derived detail with **unit/golden tests against a fixed
   DB snapshot** instead, where the input is controlled. Rule of thumb: the
   differential compares *what the port computes*; anything the port merely *looks
   up* belongs in a golden test, not the oracle.
3. **Fuzz** the module's parse/input surface (`harnesses/fuzz/gen_fuzz_target.sh`
   scaffolds a `cargo-fuzz` target). Any crash/panic on untrusted input is a
   release blocker. Scope this gate to the **threat-model boundary**: it applies to
   modules that consume untrusted input (parsers of CLI specs, data files, network
   responses), not to a renderer or a pure data model with no external input edge —
   for those the fuzz gate is *N/A*, not a missing tick, and forcing a token target
   just to fill the column is theater (LESSONS #9). Keep the hand-authored seed
   corpus **read-only and separate from the writable corpus dir**: `cargo fuzz run
   <t> <seeds>` writes discovered inputs back into whatever dir you pass, so run
   `cargo fuzz run <t> corpus/<t> seeds/<t>` (first dir writable, rest read-only) or
   the seeds silently balloon into thousands of committed files.
   **A time-bounded smoke (60s) is a floor, not a proof** (LESSONS #15): a panic on
   a low-probability branch can pass a module's own smoke and merge, then surface on
   a *later, unrelated* module's fuzz run — nmap's multibyte-delimiter panic lived
   in `probedb` (merged clean) and only fired two modules later. This is not a hole
   to close (exhaustive fuzzing is not on the table) but a discipline: when a
   crash *does* surface, **commit the exact crashing input as a named seed** so it
   is deterministically re-checked on every future run, and give the parser modules
   sitting on the untrusted boundary a longer budget than the 60s CI smoke at least
   once per milestone. The seed corpus is the port's accumulating regression memory.
4. **Sanitize** (`harnesses/sanitizers/run_sanitizers.sh`): Miri over the pure
   logic and, for the `sys` layer, ASan/UBSan (and TSan if threaded). winlsof's
   worker-thread hang fix is exactly the class TSan/Miri reasoning catches.
   **Miri cannot execute real I/O** (sockets, files, real syscalls) — a tokio
   `TcpStream::connect` test aborts under Miri. So structure the `sys` layer to
   **split the pure decision from the I/O**: extract the branch logic into a pure
   fn (`verdict(outcome, elapsed) -> …`) that Miri *does* cover, and gate the thin
   I/O tests behind `#[cfg_attr(miri, ignore = "…")]`. Don't let "Miri can't run
   this" become "this module has no Miri coverage" (LESSONS #8).
   **TSan is unsound as a gate over an async runtime** (tokio/async-std): it flags
   the runtime's own lock-free scheduler, not your code, and app code runs *inside*
   the runtime so suppressions can't separate the two (LESSONS #10). For
   async-driven concurrency, prove race-freedom **structurally** — no shared
   mutable state + the compiler's `Send`/`Sync` bounds on `spawn` reject it at
   compile time — and keep a multi-thread *liveness* test (must complete, no hang).
   Reserve TSan for code that spawns OS threads over genuinely shared state.
   That liveness test earns its keep on a class sanitizers *cannot* see: a
   **defensive catch-all `break`/`_ =>` in a work-scheduling loop is a liveness
   bug** (LESSONS #14). "When the state looks unexpected, break" silently *drops
   outstanding work* — nmap's rate-limited group loop hit a `_ => break` on a
   timing skew between two rate checks and abandoned 2 of 8 ports as neither
   open nor closed. It is not UB and not a hang, so only a liveness assertion
   ("every unit of work reaches a terminal state") catches it. In a scheduler
   loop the safe default with work still outstanding is **retry/continue (re-poll,
   sleep-then-continue), never `break`** — reserve `break` for a proven-terminal
   condition (queue empty), not for "confused."
   **A `sys` module whose real path is *privileged* is invisible to the differential
   backstop — give it a real-resource *teardown* test in its own slice** (LESSONS
   #17). The differential harness's per-case timeout is the kit's liveness backstop
   (gate 2), but it runs *unprivileged* so it never exercises a raw-socket/capture
   path — that code executes only under `CAP_NET_RAW`/root, outside every automated
   gate. M4's capture module passed all six gates against a **mock** `PacketSource`
   and merged (#47); the shutdown deadlock lived in the *real* pcap source's
   `Drop`-join and only surfaced two slices later when a root-only end-to-end test
   first wired the real source in (#48) — the same "green gate is a floor" trap as
   LESSONS #15, but for teardown liveness instead of a fuzz branch. So for any `sys`
   module that owns a blocking OS resource, add a **`#[ignore]` root-only test that
   opens the *real* resource and asserts clean shutdown while idle** (construct →
   no traffic → `Drop`/`stop()` returns within a bounded time), and run it in that
   module's own slice — a mock backend proves the channel plumbing, never the
   teardown of the thing the mock stands in for.
5. **Unsafe-audit** (`harnesses/unsafe-audit/audit_unsafe.py`): every `unsafe`
   block has a `// SAFETY:` justifying its invariants — **hard fail** otherwise.
6. **Review & merge.** Update the `progress` table (the module advances
   ported → differential-passing → fuzzed → sanitized → unsafe-audited).

**Entry criteria:** skeleton + oracle.
**Exit criteria (per module):** all six gates green; `progress` row fully ticked.
**Artifacts:** the module, its fuzz target, its golden cases, divergence entries.
**lsof failure modes this prevents:** the 7-commit hang (spike-first + sanitizer
reasoning), fidelity misses shipping before a test pinned them (gate 2 + golden),
undocumented unsafe (gate 5).

---

## Phase 5 — Cutover & retirement of the C

**Goal:** ship the Rust; retire the C without losing its guarantees.

**Do:**
- Gate cutover on: 100% of the port's target modules through all six gates; the
  differential corpus green (modulo logged divergences); fuzz corpus seeded and
  clean; supply-chain gate clean (`harnesses/supply-chain/run_supply_chain.sh` —
  `cargo audit` + `cargo deny`).
- Keep the C runnable as the oracle through one release overlap; only then retire.
- Ship the `DIVERGENCES.md` as user-facing release notes ("behaviors we
  deliberately changed, and why") — the security fixes are a *feature*.

**Entry criteria:** all target modules merged & gated.
**Exit criteria:** Rust is the shipped artifact; supply-chain clean; divergences
published; C archived (not deleted until an overlap release proves parity).
**Artifacts:** release, `DIVERGENCES.md`, final `progress` table.
**lsof failure modes this prevents:** big-bang deletion before parity; winlsof
kept both trees side by side — preserve that discipline.

---

## Cross-cutting safety controls (apply continuously)

| Control | Harness / mechanism | Gate |
|---|---|---|
| No `unsafe` in pure logic | `#![forbid(unsafe_code)]` on `core` | compile |
| Every `unsafe` justified | `unsafe-audit/audit_unsafe.py` | **hard-fail CI** |
| No UB at the FFI boundary | `sanitizers/run_sanitizers.sh` (Miri, ASan/UBSan/TSan) | CI |
| No panics on untrusted input | `fuzz/` (`cargo-fuzz`) | CI smoke + nightly deep |
| No vulnerable/untrusted deps | `supply-chain/run_supply_chain.sh` (`cargo audit`,`cargo deny`) | CI |
| No silent behavior drift | `differential/diff_run.py` + `DIVERGENCES.md` | CI |
| Lints as errors | `clippy -D warnings` (+ overflow/cast lints) | CI |
| Don't re-port a C vuln | `c-flaw-scan/scan_c_flaws.py` at Phase 0 | review |

See `harnesses/ci/porting-ci.template.yml` for the wiring and
`make -C porting-kit check-kit` to smoke-test every harness.

---

## The compounding loop

Every port **ends with a retrospective** (`PROMPTS/90-retrospective.md`) that
diffs lived experience against this playbook and patches it. New lessons append
to `LESSONS.md` with the section they amended. The kit is never "done" — it is
the running sum of every port it has survived.
