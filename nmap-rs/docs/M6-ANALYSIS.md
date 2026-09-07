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
