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
| bundled Lua 5.4 interpreter (`liblua/`) | — | 30,120 | no — use a maintained binding |
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

1. **M6.0 — the Lua runtime decision.** Bind a maintained Lua 5.4 rather than
   porting `liblua`'s 30k lines. Needs a decision (below) before anything else.
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

## Open questions — need answers before M6.1

1. **Which Lua?** `mlua` (vendored Lua 5.4, builds from source, needs a C
   compiler — present) is the obvious choice, but it puts a C interpreter back
   into a port whose premise is memory safety. The alternatives are a pure-Rust
   Lua (none is remotely complete enough for 611 real scripts) or accepting the C.
   This is the same class of trade as `ed25519-dalek` in S2, and larger.
2. **Do we sandbox?** The C exposes `io` and `os` to every script. Shipping the
   same thing is faithful; restricting it by default is safer and would be the
   port's most user-visible divergence yet. It also risks breaking scripts in the
   shipped corpus — which is measurable before deciding, and should be measured.
3. **Scope of the corpus.** Do all 611 scripts have to run, or is a defined subset
   the M6 exit criterion with the rest deferred to M7?
