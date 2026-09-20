# Milestone 6 — NSE (Nmap Scripting Engine): Phase-0 analysis

Fresh kit cycle (PLAYBOOK Phases 0–1). Inventory + C-flaw scan + threat model +
dependency-ordered port plan. **No Rust is written until the port order is
approved** (kit requirement). This document is the durable record of the Phase-0
findings; the oracle harness (Phase 2) and the per-module six-gate loop (Phase 4)
follow on approval.

Every count below was measured against the C tree in this repository, not
recalled; the commands are reproducible from the paths cited.

## What is actually being ported

NSE looks like the largest milestone in the project and is not, because most of
its bulk is not C:

| part | files | lines | ported? |
|---|---|---|---|
| C++ binding glue (`nse_*.cc`, `nse_*.h`) | 27 | **8,303** | **yes — this is M6** |
| bundled Lua 5.4 interpreter (`liblua/`) | — | 30,120 | no — replaced, see *Decision 1* |
| `nselib/` script libraries (Lua) | 133 | 95,049 | no — must *run* unmodified |
| `scripts/` (Lua) | 611 | 116,260 | no — must *run* unmodified |

The deliverable is therefore **API compatibility with the Lua surface**, not a
rewrite of 211,309 lines of Lua. The measure of success is that the shipped
`nselib` and `scripts` trees execute against the port with no edits — which also
gives M6 something no other milestone has had: 611 real programs as a test corpus.

## The seven C-provided Lua modules, weighted by what needs them

Measured across all 744 shipped Lua files (`scripts/*.nse` + `nselib/*.lua`):

| module | source | hard `require` | via `pcall(require,…)` | any reference |
|---|---|---|---|---|
| `nmap` | `nse_nmaplib.cc` + `nse_nsock.cc` | **455** | 0 | 732 |
| `openssl` | `nse_openssl.cc` | 41 | 19 | 67 |
| `lpeg` | `nse_lpeg.cc` | 6 | 0 | 13 |
| `libssh2` | `nse_libssh2.cc` | 1 | 0 | 6 |
| `lfs` | `nse_fs.cc` | 1 | 0 | 2 |
| `zlib` | `nse_zlib.cc` | 0 | 2 | 5 |

Two things fall out of this.

**`nmap` is the whole game.** 455 of 744 files hard-require it, and nothing else
comes close. It is 31 registered functions plus the socket and dnet object types,
backed by `nse_nsock.cc`.

**Everything else is already optional, in the corpus's own idiom.** `zlib` is
*never* hard-required — both uses are `local have_zlib, zlib = pcall(require, "zlib")`
(`nselib/http.lua:158`, `scripts/deluge-rpc-brute.nse:6`). `openssl` is defensively loaded in 19 places, and 7 files gate
on `nmap.have_ssl()`. So a port that ships `nmap` alone does not fail 744 files; it
degrades exactly where the corpus already expects to degrade. That is what makes a
leaf-first build order possible here instead of a big-bang.

## The concurrency model, and why it is the hard part

NSE is cooperatively scheduled Lua coroutines. A script that does I/O calls into
`nse_nsock.cc`, which registers an nsock callback and yields the coroutine through
`lua_yieldk` (`nse_main.cc:703`, "All NSE initiated yields must use this
function"); the nsock event loop later fires the callback, which resumes the
coroutine with the result.

That is a continuation-passing event loop bolted onto Lua coroutines — and it maps
onto this port's existing async runtime almost exactly. A Lua coroutine yielding
for I/O *is* an `await`. The port's `sys` layer already runs tokio, so the natural
shape is a Lua async function that awaits a tokio future and resumes the coroutine
with its output, with no hand-written event loop and no callback plumbing at all.

The risk is not the mapping, it is scheduling fidelity: NSE's concurrency limits,
timeouts and per-host script parallelism are observable behaviour that scripts and
`--script-trace` output depend on.

## Threat model

This is the first milestone where the port **executes attacker-adjacent code by
design**, so the threat model is the deliverable that matters most.

1. **NSE scripts are not sandboxed at all.** `nse_main.cc:593` calls
   `luaL_openlibs(L)`, which opens the complete Lua standard library — including
   `io` and `os` (`liblua/linit.c:47-48`). A script can call `os.execute` and
   `io.open`. Since nmap is frequently run as root for raw sockets, `--script
   /path/to/untrusted.nse` is arbitrary code execution as root, and *that is the
   documented design*, not a bug. Any hardening here is a divergence to argue for
   explicitly, not to sneak in.
2. **Script arguments cross the boundary from the command line** (`--script-args`,
   `--script-args-file`, `nmap.cc:616-617`) into script logic.
3. **Scripts parse hostile network responses in Lua.** Memory safety is Lua's
   problem there, not ours, but the *C glue* that hands them those bytes is ours,
   and it is manual `lua_State` stack manipulation — the classic site for stack
   imbalance and type confusion.
4. **Script selection reads a generated index.** `script.db` and the category
   expressions decide what runs; a poisoned or stale index changes which code
   executes.

## Proposed build order

Leaf-first, and ordered by the dependency weight measured above:

1. **M6.0 — the Lua runtime.** Decided (Decision 1 below): extend `piccolo`, a
   pure-Rust stackless Lua VM, with the stdlib surface the corpus actually
   uses. This is the long pole and is sized separately below.
2. **M6.1 — `core::nse::script`**: the `.nse` file format, the mandatory fields,
   categories, and `script.db`. Pure parsing over `&[u8]`, no Lua. Fuzzable on
   day one, and it is the input that decides what executes.
3. **M6.2 — `core::nse::selection`**: `--script` expression grammar (categories,
   wildcards, `and`/`or`/`not`, paths). Pure, total, fuzzable.
4. **M6.3 — the `nmap` module, non-I/O half**: the 31 registered functions that
   only read port/host state, registry, timing and verbosity. Pure against
   already-ported `core` types.
5. **M6.4 — the `nmap` module, I/O half**: sockets over the existing tokio layer,
   as Lua async functions. The scheduling-fidelity work lives here.
6. **M6.5 — `openssl`**, the only other module with real weight (41 hard requires).
7. **M6.6 — `lpeg`, `lfs`, `zlib`, `libssh2`**: 8 hard requires between them, all
   already `pcall`-guarded or trivially few. Individually optional.

Gates: 6.1 and 6.2 are pure parsers and get the full ladder (differential against
the C's own selection, fuzz, mutation). 6.3-6.7 are gated by running the real
`scripts/` corpus, which is the strongest oracle available in this project.

## Decision 1 — the Lua runtime: extend `piccolo`, ship no C

The project's premise is the removal of C, so binding a C interpreter is not a
trade to weigh — it is disqualifying. `mlua`, `rlua` and `hlua` all vendor and
compile PUC-Lua, and are out on that ground alone.

That leaves the pure-Rust field, which was surveyed rather than assumed:

| crate | verdict |
|---|---|
| **`piccolo`** (kyren, MIT/CC0) | stackless Lua VM, real GC, coroutines, compiler — **the only viable base** |
| `hematita` | abandoned at 0.1.0 |
| `full_moon` | parser only, no VM |
| `luar` | toy |

`piccolo`'s dependency tree is `ahash`, `allocator-api2`, `anyhow`,
`gc-arena`, `hashbrown`, `rand`, `thiserror` — measured: **no `build.rs`
anywhere in the tree and no `cc`/`bindgen` dependency**. It compiles no C.

### What `piccolo` gives us for free

The expensive parts of a Lua implementation are already done: 18,621 lines
across 44 files implementing a stackless VM, a compiler, metatables,
coroutines, and a tracing GC (`gc-arena`, a further 7,908 lines).

**Stacklessness is not incidental here — it is the reason this is the right
base.** NSE's entire concurrency model is coroutines that suspend for I/O
(`lua_yieldk`, `nse_main.cc:703`). PUC-Lua cannot yield across a C call
boundary without the `k`-continuation dance that `nse_nsock.cc` exists to
perform. A stackless VM suspends anywhere, so the callback plumbing that makes
up much of the 8,303 lines of C++ glue has no analogue to port — it simply
stops being necessary.

The safety arithmetic is also favourable, and is the argument for the whole
milestone:

| | lines | unsafe |
|---|---|---|
| `liblua/` (C, today) | 30,120 | all of it, by construction |
| `piccolo` | 18,621 | 31 sites across 7 files |
| `gc-arena` | 7,908 | 234 sites |

265 auditable `unsafe` sites concentrated in a GC, versus 30,120 lines where
every pointer is unchecked. That is the trade this milestone is for.

### What is missing, measured against the corpus

`piccolo`'s own `COMPATIBILITY.md` was parsed rather than read impressionistically:
79 unimplemented entries, 61 implemented, 6 will-not-implement, 3 differing.
All of `table` is implemented; `math` is complete; `string.byte/char/len/lower/
reverse/sub/upper`, `pcall`, `tonumber`, `rawlen`, `_VERSION`, `next`, `pairs`,
`setmetatable` and `coroutine.create/resume/running/status/yield` are done.

The gap that matters, weighted by what the 744 shipped Lua files actually call:

| missing surface | call sites | files |
|---|---|---|
| Lua patterns — `find` / `match` / `gmatch` / `gsub` | **1,890** | 421 |
| `string.pack` / `unpack` / `packsize` | **1,747** | 169 |
| `string.format` | **1,568** | 397 |
| `string.rep` | 174 | 60 |
| `_G`, `coroutine.wrap`, `loadfile`, `load`, `xpcall`, `rawequal` | 64 | ~30 |
| `require` / `package` | — | 742 |

**609 of 744 files (81.9%) use at least one missing stdlib function**, and 742
use `require`. But the shape of that number is the point: it is dominated by
**three** subsystems — the Lua pattern matcher, `string.format`, and
`string.pack`/`unpack` — which between them account for 5,205 of the 5,379
measured call sites. Each is a self-contained mini-language over `&[u8]` with a
precise specification in the Lua 5.4 manual, no I/O, and total behaviour on
malformed input. In other words: exactly the kind of thing this project's
existing gate ladder (differential → fuzz → mutation → Miri) is built to prove
correct, and exactly the kind of thing C gets wrong.

`require` is not really a gap. NSE does not use stock `package` loading — it
installs its own searcher in `nse_main.cc`, which is ours to write anyway.

### Correction (M6.0): the table above counts functions, and the corpus needs dispatch

**The gap table is incomplete in a way that changes the plan.** It measures
missing *functions*. It does not measure the *mechanisms those calls travel
through*, and the corpus depends on one that piccolo does not have.

`s:sub(1, 2)` is not a call to `string.sub` that a runtime satisfies by defining
`string.sub`. It is an `__index` lookup on a string **value**, which needs a
string metatable the VM itself supports. PUC-Lua installs one in
`luaopen_string` — `createmetatable` (`liblua/lstrlib.c:1852-1863`) sets a
metatable on a dummy string and points its `__index` at the `string` library —
and `OP_SELF` (`liblua/lvm.c:1383`) reaches it via `luaV_finishget`, which calls
`luaT_gettmbyobj(L, t, TM_INDEX)` for any non-table receiver (`lvm.c:296`).

piccolo has no such thing, in **either** the published 0.3.3 or master:

* `meta_ops::index` (`src/meta_ops.rs:182` on master, `:66` at v0.3.3) matches
  `Value::Table` and `Value::UserData`; every other value falls to `_ =>` and
  errors.
* The VM's method opcode routes straight there — `Operation::Method`,
  `src/thread/vm.rs:336` — so there is no separate path to special-case.
* `setmetatable`/`getmetatable` reject non-tables outright
  (`src/stdlib/base.rs:200`: *"'getmetatable' can only be used on table types"*),
  and `debug.setmetatable` — PUC-Lua's only route to installing one from Lua —
  is marked unimplemented in `COMPATIBILITY.md`.

So a runtime built by working down the gap table could implement every entry in
it and still fail on most of the corpus. Measured by
[`nse_corpus_census.py`](nse_corpus_census.py) over the 758 shipped
`.nse`/`.lua` files, counting code only (Lua comments and string literals are
blanked first, offsets preserved — without that, a grep for `//` reports 2,271
integer-division sites where there are 38, the rest being URLs in comments):

| | sites | files |
|---|---|---|
| method form, `s:NAME(...)` | **3,340** | **454 of 758 (59.9%)** |
| …of which the receiver is a string **literal** | **992** | **284** |
| `:format` method form | 885 | 269 |
| `string.format(…)` direct form | 692 | 183 |

The last two rows are the shape of the problem: the method form is not a
minority spelling, it is the **dominant** one. And the 992 literal-receiver
sites — `(" "):rep(n)`, `("%d"):format(x)` — are unambiguous: there is no
reading under which those are anything but a string metatable lookup.

**Consequence for Decision 3's prerequisite.** Adding string-method dispatch
means a per-type metatable and a new arm in `meta_ops::index` — piccolo
*internals*, not reachable from a downstream crate through its public API. So
**a fork is required regardless of how the `gc-arena` pin resolves**, which
removes "depend on the published crate and extend it only from outside" from the
options. The prerequisite is still the right thing to do first; it just has one
fewer way to end.

Two things that *do* check out, recorded so they are not re-litigated:

* **`_ENV` works.** piccolo compiles the top-level chunk with an `_ENV` upvalue
  and exposes `Closure::new_with_env` (`src/closure.rs:219-269`,
  `src/compiler/compiler.rs:1424-1462`). NSE's per-script environment
  (`nse_main.lua:472-479` — `setmetatable(env, {__index = _G})` then
  `local _ENV = env`) maps onto it directly. 337 sites in 134 corpus files.
* **Lua 5.3/5.4 operators work.** Bitwise `& | ~ << >>` have opcodes
  (`src/opcode.rs:257-277`) and `goto`/labels parse
  (`src/compiler/parser.rs:446-682`). The corpus uses them in 80, 41, 26, 23 and
  8 files respectively.

### The honest cost, and the risks

This is a subproject, not a slice — comparable in size to M3 and M4 combined.
Two risks are worth stating plainly rather than discovering later:

1. **`piccolo` is dormant.** Last release 0.3.3 (2024-06-16); last commit
   `ce709eb`, 2025-07-10. Master carries unreleased work (the whole of `table`,
   `string.byte/char`) that 0.3.3 lacks, so we would be building on a git rev,
   not a published crate. `gc-arena`, by contrast, is actively maintained (last
   commit 2026-08-17). Plan on a **fork**, not on upstream contributions
   landing.
2. **Master pins `gc-arena` by git rev**, which the supply-chain CI job will
   not accept as-is. Vendoring or a published-version pin is a prerequisite.

The correctness strategy is the one this project already runs: **PUC-Lua as a
differential oracle, never as a shipped dependency** — the same relation the
port has to C nmap today, where the C is the reference and never the product.
The Lua 5.4 official test suite plus the 744-file corpus is a strong oracle,
and the oracle harness (`tests/differential/`) already exists.

## Decision 2 — the sandbox: it costs nothing, because we are writing the stdlib

The C exposes the complete standard library to every script
(`luaL_openlibs(L)`, `nse_main.cc:593`; `io`/`os` at `liblua/linit.c:47-48`),
so `--script /path/to/untrusted.nse` is arbitrary code execution — usually as
root. Decision 1 changes the economics of fixing that completely: because the
stdlib is ours to write, **restricting it is not a restriction bolted onto an
interpreter, it is declining to write four functions.**

Measured across all 744 files (aliased forms included — `base32.lua` and
`base64.lua` both do `local remove = require "os".remove`, which a naive grep
for `os.remove` misses):

| primitive | operational uses |
|---|---|
| `os.execute` | **0** |
| `io.popen` | **0** — the 2 sites are inside `if not unittest.testing()` self-test blocks (`base32.lua:239`, `base64.lua:197`) |
| `os.remove`, `os.tmpname` | **0** — same two self-test blocks |
| `os.exit` | **0** — the single occurrence is commented out (`msrpctypes.lua:1830`) |

128 files (17%) touch `os.*` or `io.*` at all. What they genuinely need:

| | files | uses |
|---|---|---|
| `io.open` | 61 | 73 — 32 write/append, 34 read, 7 unspecified (read) |
| `io.lines` | 11 | 13 |
| `io.write` | 5 | 20 |
| `os.time` | 53 | 109 |
| `os.date` | 8 | 16 |
| `os.difftime` | 4 | 6 |
| `os.getenv` | 1 | 3 — all `HOME`, for `.ssh/config` and `known_hosts` (`ssh1.lua:244,248,255`) |

**The plan.** Ship no process-execution surface at all — no `os.execute`, no
`io.popen`, no `os.remove`/`os.rename`/`os.tmpname`. Measured cost: **zero
shipped scripts**, and the two self-test blocks that would notice are exactly
the place where a divergence is acceptable and visible.

In their place:

- **Capability-scoped filesystem** rather than raw `io.open`: reads from the
  data directories and from paths passed explicitly via `--script-args`; writes
  only beneath an operator-designated output directory. That covers all 73
  `io.open` sites, including the ~28 scripts that legitimately write loot.
- **A clock** — `os.time`/`os.date`/`os.difftime`, unrestricted. Harmless.
- **No `os.getenv`.** Resolve `HOME`, `.ssh/config` and `known_hosts` in Rust
  and hand the paths in. Three call sites, one library.

Every item above is a divergence and goes in `DIVERGENCES.md` with this
measurement as its justification. The result is a port that is safer than the C
by construction, at a measured cost of nothing.

## Decision 3 — scope: the engine is the port; the scripts are data

**"All 611 scripts run" is the wrong exit criterion**, and gating M6 on it is
the single biggest schedule risk in the milestone. A script that does not yet
run is a coverage number, not a safety regression, and 611 programs is a bar
that never quite closes.

The proposed exit criterion instead, in increasing order of strength:

1. **All 133 `nselib` libraries load, and the tests NSE already ships pass.**
   NSE carries its own test framework — `nselib/unittest.lua` driven by
   `scripts/unittest.nse` — and **26 of the 133 libraries define a
   `test_suite`**. That is a ready-made conformance oracle sitting in the tree,
   and it exercises the stdlib far harder than the scripts do.
2. **The 125 `default`-category scripts run.** That is precisely what a bare
   `nmap -sC` executes, so it is the user-visible baseline.
3. The remaining 486 become a **tracked coverage number that must not
   regress**, not a merge gate.

For reference, the category distribution over all 611 scripts: `safe` 350,
`discovery` 312, `intrusive` 213, `default` 125, `vuln` 105, `brute` 73,
`version` 48, `broadcast` 47, `exploit` 45, `auth` 38, `external` 33, `dos` 11,
`malware` 10, `fuzzer` 3, `info` 1.

## Sequencing recommendation

Given the size of Decision 1, **M6 should run after M7**, not before it.
Cutover plus `ncat`/`nping` yields a complete, C-free, shippable nmap sooner,
and the Lua runtime work then proceeds without the rest of the port parked
behind an interpreter project. Sequencing M6 first couples every remaining
milestone to the hardest one.

## Still open

Nothing blocks M6.1 and M6.2 (the `.nse` parser and the `--script` selection
grammar) — both are pure, fuzzable, and independent of the runtime decision.
The runtime work (M6.0) needs port-order approval before any Rust is written,
per the kit.

## Decision 3 — the M6.0 port order (approved M7.5)

M6.1 and M6.2 are merged. M6.3 is the first piece that needs a running VM, so
this is what unblocks the rest of M6.

**Prerequisite, done first and alone:** resolve `piccolo` master's `gc-arena`
**git-rev pin**. The supply-chain gate (`cargo deny check`, `sources`) rejects a
git dependency outright, so this is not a detail to discover during the first
stdlib PR — it decides whether the fork vendors `gc-arena` or waits on a
published version. It is also the cheapest possible test of the whole plan: if
the pin cannot be resolved acceptably, that is worth knowing before any Lua code
is written, not after three subsystems of it.

**Then, descending by files touched**, so each piece unblocks the largest slice
of the 744-file corpus and is independently gateable before the next begins:

| order | subsystem | call sites | files | why here |
|---|---|---|---|---|
| 1 | Lua patterns (`find`/`match`/`gmatch`/`gsub`) | 1,890 | **421** | most files, and the hardest — a mini-language with its own semantics. Doing it first means the risk is known early rather than discovered last. |
| 2 | `string.format` | 1,568 | **397** | nearly as broad, far simpler; a fast confirmation that the pattern set up in (1) generalises. |
| 3 | `string.pack`/`unpack`/`packsize` | 1,747 | 169 | most call sites but fewest files — concentrated in binary protocol libraries, so it unblocks the least breadth per unit of work. |
| 4 | the tail | 238 | ~90 | `_G`, `coroutine.wrap`, `load`, `xpcall`, `rawequal`, `string.rep` |

Ordering by **files** rather than call sites is deliberate: the goal of each
step is to make more of the corpus *runnable*, and a file blocked on one missing
function is as blocked as a file blocked on fifty.

`require` is not in the table because it is not a gap (see above) — NSE installs
its own searcher, which is ours to write.

**On whether M6 resumes at all:** M7's cutover profile explicitly excludes
scripting, so M7 can finish without M6, and none of the 21 remaining MUST-tier
options need Lua. M6 is therefore sequenced *after* the MUST tier rather than
competing with it. That is a scheduling decision and reversible; the port order
above is not affected by when it starts.

---

## Decision 4 — the `gc-arena` pin is resolved: fork master **backwards** onto published 0.5.3, vendor the fork, keep the GC on crates.io

Decision 3's prerequisite, settled by building every candidate rather than
reasoning about them. Six configurations were compiled and run; the numbers
below are measured, and the commands are reproducible.

### What was actually wrong

The pin is worse than "upstream is on a git rev". `gc-arena` rev `5a7534b`
(2024-07-22) sits **after tag `v0.5.3` and before `v0.6.0`** — v0.5.3 plus 31
unreleased commits, several deliberately API-breaking. Its manifest still reads
`version = "0.5.3"`, so the version number is actively misleading. And upstream
is dead: piccolo master is `ce709eb`, 2025-07-10, unchanged since.

Going forward does not help. `gc-arena 0.6.0` **deleted the `allocator-api2`
feature** that piccolo master's dependency line requests — upstream's own commit
(`c591dd3`) calls it "a bit of an aggressive pruning" and says the replacement
should be "custom user logic for external allocation and manual tuning of
collection pacing."

### The options, measured

| option | builds | `cargo deny` | MSRV 1.88 | GC pacing | divergences / panics |
|---|---|---|---|---|---|
| **A** published 0.3.3 | yes, 0 errors | **all ok** | yes | intact | **32 / 68, 5 panics** |
| **B** fork → gc-arena 0.7.0 | yes, after ~100 lines | all ok | **NO** | **lost** | 16 / 68, 2 panics |
| **B′** fork → gc-arena 0.6.1 | yes | all ok | yes | **lost** | 16 / 68, 2 panics |
| **C** fork → gc-arena `=0.5.3` | yes, after **~40 lines** | **all ok** | **yes** | **intact** | **16 / 68, 2 panics** |

Divergence counts are against [`m60_semantics_golden.txt`](../tests/differential/m6/m60_semantics_golden.txt),
68 cases evaluated by nmap's own Lua. `math.mininteger % -1` **aborts the
process** in every version and `pcall` does not contain it. 0.3.3 additionally
gets `-7 // 2` wrong, panics on three bit-shift cases, and — found by the
adversarial pass, not by any probe — **inverts every NaN `>` and `>=`
comparison**: `v0.3.3 src/compiler/operators.rs:146-155` lowers `a > b` to
`LessEq { skip_if: !skip_if }`, a *negation*, where master lowers it to
`Less { left: right, right: left }`, an operand *swap*. NaN is unordered, so
`a <= b` is false and the negation yields `true`. All six NaN ordering cases are
wrong in 0.3.3 and right in master. That is a silent wrong answer in float
comparison on parsed protocol data, and it is invisible unless `>`/`>=` are
tested separately from `<`/`<=` — which the corpus now does.

Two measurements decided it, and neither was in the original framing:

* **`gc-arena 0.7.0` does not build at the declared MSRV 1.88** — it uses the
  unstable `ptr_as_ref_unchecked`. It needs >1.94. The `msrv` CI job builds at
  exactly `rust-version`, so Option B would have broken it. `0.6.1` and `0.5.3`
  both build at 1.88.
* **`MetricsAlloc` exists in 0.5.3 and is gone from 0.6.0 onward.** It is what
  ties GC pacing to Lua data growth. Without it, a hostile NSE script can
  allocate without the collector noticing — a memory-exhaustion vector in a tool
  that runs untrusted scripts against hostile hosts. Going *backwards* keeps the
  defence; going forwards discards it.

Option C's back-port is **~40 functional lines across 7 files**; `util/freeze.rs`,
predicted to be the hard case, needed none. All 31 commits in the gap were read:
there is **no soundness fix** among them, so back-porting does not strand the
port on a GC bug. Scored on the semantics corpus, the 0.5.3 fork behaves
**identically** to the 0.6.1 fork — 16 divergences, same set.

### How it enters the tree

The fork is **vendored as a workspace member under `crates/`**, with
`publish = false`. `gc-arena` stays an ordinary crates.io dependency pinned
`=0.5.3` — it is *not* vendored, because it is actively maintained (last commit
2026-08-17) and we want its security updates.

Verified with the project's own `deny.toml`, byte-identical:

```
advisories ok, bans ok, licenses ok, sources ok
```

`sources ok` is the milestone blocker, gone. `Cargo.lock` contains **zero** git
sources and resolves `gc-arena 0.5.3` from `registry+…crates.io-index`.

Three details that are load-bearing and non-obvious:

1. **`publish = false` is required.** Without it `bans` FAILS with
   `allow-wildcard-paths is enabled, but does not apply to public crates`. The
   repo's own crates already carry it (`crates/core/Cargo.toml:4`); upstream
   crates do not.
2. **The vendored crate goes under `crates/`, where the unsafe-audit gate can
   see it.** `audit_unsafe.py` has no `--exclude`: the path argument *is* the
   exclusion, and CI hardcodes `nmap-rs/crates/` (`nmap-rs-ci.yml:132`). Putting
   vendored code anywhere else is therefore not configuration, it is
   gate-dodging. Cost of doing it honestly: **30 unsafe blocks, 14 already
   documented, 16 to write.**
3. **Clippy keys off workspace *membership*, not directory**, while the audit
   harness keys off directory only. The two gates can disagree about what is
   covered, so both must be checked when the vendoring lands.

### What the fork is *for* — and what it is not

The assumption that we fork piccolo "to extend it with the stdlib NSE needs" is
**wrong**, and testing it was the most useful thing the campaign did.

`stdlib/string.rs` on master is 126 lines registering `len, byte, char, sub,
lower, reverse, upper`. `git grep -E 'gmatch|gsub|lua_pattern' src/` returns
**zero hits at both `v0.3.3` and master**. Forking master buys none of the three
subsystems the port needs.

Everything else works from the **published public API, unpatched** — each
verified by running it: injecting Rust functions into the existing `string`
table, overwriting entries already there, creating a whole new `nmap` global
library, round-tripping non-UTF-8 bytes both ways, **yielding out of a Rust
callback and being resumed**, and calling back into Lua from Rust
(`gsub(s, pat, func)` and `gmatch` iterators).

So the fork exists for a **short, enumerable list**:

| # | change | size |
|---|---|---|
| 1 | the `gc-arena` back-port | ~40 lines, 7 files |
| 2 | **string metatable** — a `Registry` singleton plus a `Value::String` arm in `meta_ops::index`, with a `pub fn string_metatable(ctx)` so the *external* crate installs its own `__index` | ~30 lines |
| 3 | the 2 modulo panics, and the remaining semantics divergences the corpus names | small, each with a golden |

Lua patterns, `string.format` and `string.pack`/`unpack` are then written **in
our own crate**, against piccolo's public API — which means they pass through
this project's differential, fuzz, Miri and sanitizer gates, none of which reach
into a vendored dependency. That is a better outcome than a fat fork, and it is
the opposite of what Decision 3's table implied.

### Free, and worth recording: Decision 2's sandbox costs nothing

`grep -rnE 'std::process|Command|std::fs|File::open|std::env' src/` over
piccolo master returns **zero hits**, and `grep -rn load_os src/` returns zero
too — there is no `os` library in either version to withhold. `Lua::core()`
calls exactly `load_base, load_coroutine, load_math, load_string, load_table`
(`src/lua.rs:172-180`) and never `load_io`, so `os` and `io` are both nil.
Withholding
process execution is not a restriction to bolt on — it is already absent, and
`Lua::empty()` plus the public `stdlib::load_*` functions makes the surface
opt-in by construction rather than something to tear down.

### Sequencing, revised

Decision 3's order stands, with one change: the string metatable is **not** part
of "the tail", it is a **prerequisite of step 1**. Lua patterns are reached
through `s:find(...)` in most of the corpus, so shipping the pattern matcher
without method dispatch would leave it unreachable from 454 of 758 files.

### The adversarial pass, and the one objection that landed

Three attacks were run against the decision above. Two failed; both corrected
something on the way.

**"It blocks M6.4"** — *failed, and fixed a probe error.* The claim was that
piccolo cannot suspend a Rust callback and resume it from an external async
runtime, which is NSE's whole concurrency model. It traced to a probe reporting
`Executor::resume()` returning `Err(bad executor mode: Result, expected
Suspended)` and escalating that into an API-shape constraint. It is not one:
`do_yield` with `to_thread: None` pushes **two** frames, `Yielded` then
`Result`, and the documented protocol is take_result-**then**-resume
(`src/thread/thread.rs:129-131`). The probe called `resume()` with the `Result`
frame still on the stack and reported its own missing call as a property of the
VM. Host-driven suspension works, on both versions.

**"It ships known defects"** — *failed against the decision, fatal to the
dissent.* One judge preferred vendoring published **v0.3.3** on maintenance
grounds. The attack found that 0.3.3 inverts every NaN `>` and `>=` comparison
(see the table above). That option is dead.

**"It is gate evasion"** — **partly upheld, and acted on.** Its three claims
were checked against the workflow file and by running the gates:

| claim | verdict |
|---|---|
| clippy's safety lints are vacuous on dependency code | **true — and it is an argument *for* this decision**, not against it |
| ASan never executes the VM | **true, and unaddressed. Fixed below.** |
| hand-writing SAFETY comments for upstream code is itself a risk | **true as a caution**, not as a refutation |

On the first: `cargo clippy --all-targets --all-features -D
clippy::undocumented_unsafe_blocks` — the repo's exact escalation — reports
**14 missing-safety-comment errors** when piccolo is a vendored *workspace
member*, and **0** when it is a registry dependency. The project already
recorded this failure mode for `ffi.rs` (`nmap-rs-ci.yml:186-190`: *"cargo
clippy mentioned ffi.rs 0 times, so the `-D clippy::undocumented_unsafe_blocks`
escalation above was a hard error aimed at code it never saw"*). Vendoring as a
member is what converts that gate from vacuous to firing. Depending on the
published crate would have left it silent — which is the strongest argument yet
against Option A, and it is an argument the campaign only reached by attacking
its own answer.

On the second, the attack is right and the decision was incomplete. The
sanitizer job is `cargo +nightly test -p nmap-sys --all-features`
(`nmap-rs-ci.yml:235`), scoped to the one crate that holds first-party `unsafe`.
The VM will not live in `nmap-sys`, so **ASan would execute none of it** — in a
job whose own header comment exists because a sanitizer gate that does not
execute the unsafe is vacuous. That is precisely the failure this project keeps
writing lessons about. **The ASan job must be extended to the crate hosting the
VM as part of M6.0, not after it**; a vendored GC-backed interpreter is the
single most sanitizer-worthy thing in the tree.

On the third: a `SAFETY:` comment written by someone who did not write the code
is an assertion, and writing one to turn a gate green is exactly the fabrication
this project should fear. The discipline is therefore: **document only the
invariants actually verified, and where an invariant cannot be verified from the
code, say so in the comment and ledger it** — a `SAFETY:` that reads "upstream
asserts X; not independently verified" is honest and still passes the harness,
while a confident invention does not become true by compiling. The scale is
tractable precisely because `gc-arena` is **not** vendored: the figure of 108
undocumented sites came from a probe that vendored both crates. For piccolo
alone it is **16** by the audit harness and **14** by clippy.

One practical consequence, recorded so it is not rediscovered: clippy on the
vendored member reports **124 errors in total**, of which only 14 are safety
lints — the rest are style lints on code we did not write and have no business
policing. The vendored crate therefore needs a narrow `allow` list at its root
for the stylistic lints, and that list must **never** include
`undocumented_unsafe_blocks` or `missing_safety_doc`. Silencing those two is the
only way this decision could become the gate evasion it was accused of being.
