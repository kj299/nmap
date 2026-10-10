# Provenance — `piccolo` (vendored)

Everything in `src/` is third-party code. This file records exactly whose, at
which revision, what we changed, and how to re-derive it. The rule is the same
one the rest of this port lives by: **no silent drift.**

| | |
|---|---|
| upstream | <https://github.com/kyren/piccolo> |
| commit | `ce709eb1dae5c543cbc78e7e12bb80249d88c55f` (2025-07-10) |
| upstream version | `0.3.3` (the tag; master carries 139 unreleased commits on top) |
| license | MIT **or** CC0-1.0, at your option (`LICENSE-MIT`, `LICENSE-CC0`) |
| local changes | twelve patches in `patches/`, listed below |
| omitted | the `util/` workspace member (`piccolo-util`); unused here, and it carries 4 further `unsafe` blocks |

`Cargo.toml` is **ours**, not upstream's: upstream's is a workspace root and
cannot be vendored as-is.

## The patch series

One file per intent, applied in name order. The split is the point: a reader can
see which change is the supply-chain back-port and which is a semantics fix,
without reverse-engineering it from one combined diff.

| patch | what it does |
|---|---|
| `0001-backport-gc-arena-0.5.3.patch` | moves off the `gc-arena` git-rev pin onto the published `=0.5.3`, so `cargo deny check sources` passes |
| `0002-document-unsafe-for-the-audit-gate.patch` | `SAFETY:` comments on all 30 of piccolo's `unsafe` blocks, for `audit_unsafe.py` |
| `0003-skip-filesystem-tests-under-miri.patch` | upstream's suite walks `tests/scripts/` with `read_dir`, which Miri's isolation refuses |
| `0004-string-metatable-dispatch.patch` | gives strings a metatable so `s:sub(1, 2)` dispatches; also corrects `getmetatable`, which errored for five of Lua's eight types |
| `0005-port-modulo-and-shifts-from-puc-lua.patch` | `%` and the shifts, ported from `lvm.c` — the previous formula aborted the process on `i64::MIN % -1` |
| `0006-port-float-formatting-from-puc-lua.patch` | `tostring` and `..` for floats, ported from `tostringbuff` in `lobject.c`; also fixes an `i64::MIN.abs()` abort in the concat length estimate |
| `0007-port-string-to-number-coercion-from-puc-lua.patch` | `luaO_str2num` and which operators reach for it: the integer-before-float subtype, `tointegerns` for the bitwise operators, the float-to-integer range, and the `inf`/`nan` refusal. The first patch to touch `tests/` — see below |
| `0008-port-runtime-errors-and-numeric-for-from-puc-lua.patch` | runtime errors as PUC-Lua raises them: Lua strings, in its words (`ldebug.c`'s `typeerror`, `concaterror`, `opinterror`, `ordererror`; `lstrlib.c`'s `trymt`; `__name`), prefixed `chunk:LINE:` from the failing instruction (`luaO_chunkid`, now `src/chunk_id.rs`); `error` levels and `assert` positions (`luaL_where`), counting a tail-called Rust function's caller as C does; and the numeric `for` rewritten to Lua 5.4's `forprep`/`forloop`, which closes a hang on a zero step. Also corrects `tests/scripts/pcall.lua` and `coroutine.lua` — see below |
| `0009-port-call-depth-stack-and-memory-limits-from-puc-lua.patch` | PUC-Lua's limits on a running state (`src/limits.rs`). `LUAI_MAXCCALLS`, counted per frame as `ccall` counts it: a call from a Rust function, a metamethod, a `for` iterator and a coroutine resume each take a level, and a message handler runs one level above its error (`SequencePoll::CallAt`, `Execution::error_ccalls`). `LUAI_MAXSTACK`, and `lua_checkstack` for `table.unpack` and `string.byte`. `__index`/`__newindex` followed as `luaV_finishget`/`luaV_finishset` follow them, up to `MAXTAGLOOP`. And a memory budget (`src/budget.rs`, `Lua::set_memory_limit`) that fails with a catchable "not enough memory" where the process used to abort: requests are granted, refused or followed by a full collection as `luaM_malloc_` does, and handlers never see the error |
| `0010-expose-frame-introspection-for-the-debug-library.patch` | Read-only frame introspection for NSE's `debug.getinfo` and `debug.traceback`: `Execution::frame_info(level)` and `Thread::frame_infos()` report, level by level as `lua_getstack` counts them, the function each frame runs and, for a Lua frame, its closure and current line (`FrameInfo`). The line lookup `lua_where` already did is shared as `line_at`. Nothing is writable through it: no locals, upvalues or hooks |
| `0011-print-references-as-puc-lua-does.patch` | `tostring` of a table, function, thread or userdata is `luaL_tolstring`'s `type: 0x...` rather than `<type 0x...>`. `nse_main.lua` labels each script thread by matching `^thread: 0?[xX]?(.*)` against `tostring(co)`, and scripts that print or match a reference see what they see under nmap. The address differs run to run in both |
| `0012-honour-name-in-tostring.patch` | `tostring` (and so `print` and `%s`) of a table or userdata whose metatable holds a string `__name` is `NAME: 0x...`, as `luaL_tolstring` writes it: patterns print as `lpeg-pattern: 0x...` (M6.6 step b, E7). `__tostring` still comes first, and a `__name` that is not a string is ignored, as in PUC-Lua. The name is read by `meta_ops::name_metafield`, which is `luaL_getmetafield(L, idx, "__name")` as the auxiliary library prints it with `%s`: raw, from the metatable of any value that has one (the string metatable too, which `luaL_typeerror` consults — the binding's type errors use it), and up to its first NUL, as bytes. The VM's own errors keep `luaT_objtypename`'s rule (tables and userdata only) |

### The one patch that edits upstream's tests

`0007` rewrites `tests/scripts/bit.lua`, and the reason is worth stating rather
than burying in a diff. Upstream asserted `"2" & 3.0 == 2`; PUC-Lua **raises**,
because `luaO_rawarith` converts bitwise operands with `tointegerns` — the
no-string-coercion one — and `lstrlib.c` installs no bitwise metamethod on the
string metatable. Eleven assertions in that file encoded semantics Lua 5.4 does
not have, so the vendored suite was pinning the VM to the wrong answer.

The cases were kept and inverted rather than deleted: as `is_err` they now pin
the real behaviour, which is more coverage than before. The rewritten file is
checked both ways — it passes under this VM **and** under `liblua/` built from
this repository.

Two further upstream scripts, `pcall.lua` and `coroutine.lua`, asserted that
`error('msg')` comes back undecorated, where PUC-Lua prepends `chunk:LINE:`.
That was a VM defect, ledgered as `error_string_gets_position` until `0008`
fixed it; `0008` also corrects the two assertions, which now check the
position's line and the message. `pcall.lua` passes under `liblua/` too.
`coroutine.lua` gets further than before under `liblua/`, then stops at line 74,
which calls piccolo's non-standard `coroutine.continue`; that is upstream's
test of an upstream extension, left as it is. Two other tests that inspected
the error's Rust type now inspect its message: `tests/error.rs` and
`tests/tail_call_stack_panic.rs`.

## Why the fork exists

Two independent reasons, both measured in `docs/M6-ANALYSIS.md` (Decision 4):

1. **Supply chain.** Upstream master pins `gc-arena` by git rev
   (`5a7534b`, which is v0.5.3 + 31 unreleased commits, despite still declaring
   `version = "0.5.3"`). `cargo deny check sources` sets `unknown-git = "deny"`
   and `allow-git = []`, so that is an outright fail. The patch moves the
   dependency onto the published `=0.5.3`.
2. **The VM needs patching regardless.** It has no string metatable, so
   `s:sub(1, 2)` raises rather than dispatching — and 454 of the 758 shipped NSE
   files use that form (3,340 call sites; 992 of them on a string *literal*).
   The fix is a new arm in `meta_ops::index`, which is internals.

Going *forwards* instead was measured and rejected: `gc-arena 0.6.0` deleted
`MetricsAlloc`, which ties GC pacing to Lua data growth — losing it is a
memory-exhaustion vector in a tool that runs untrusted scripts — and `0.7.0`
additionally fails this workspace's declared MSRV of 1.88.

## Re-deriving this tree

```sh
git clone https://github.com/kyren/piccolo /tmp/piccolo
cd /tmp/piccolo && git checkout ce709eb1dae5c543cbc78e7e12bb80249d88c55f
V=/path/to/nmap-rs/crates/vendor/piccolo
for p in "$V"/patches/*.patch; do git apply --include='src/*' --include='tests/*' "$p"; done
diff -ru src "$V/src" && diff -ru tests "$V/tests"          # expect no output
```

`check_vendor.sh` does exactly that and is wired into CI, so the vendored tree
cannot drift from `upstream commit + patches` without the build going red.

## Upstream is dormant — plan accordingly

Last commit `ce709eb`, 2025-07-10. There will be no upstream release to rebase
onto and no upstream security patches. This tree is ours to maintain, which is
why the patch is kept as a **named series** rather than smeared into `src/`: a
future reader can always tell our changes from theirs.

## What the gates see, and why it is here rather than elsewhere

Placed under `crates/` and listed as a workspace member, **both deliberately**:

| gate | sees this crate? | because |
|---|---|---|
| `cargo deny` | yes | it resolves the whole graph |
| `audit_unsafe.py` | **yes** | CI walks `nmap-rs/crates/`; the harness has no `--exclude`, so the path IS the exclusion |
| clippy safety lints | **yes** | measured: 14 findings as a member, **0** as a registry dependency |
| `cargo fmt --check` | yes | member or not |
| miri | partly | workspace-wide, but only reaches code our own tests execute |
| ASan | **yes** | the job runs `-p nmap-sys -p piccolo`, which drives upstream's 43 Lua programs through the VM under the sanitizer |

30 `unsafe` blocks live here. That number is not an argument against piccolo —
depending on it from crates.io would carry the identical risk and **no gate
would print the number**. Vendoring is what makes it visible.

## Writing `SAFETY:` comments on code you did not write

A `SAFETY:` comment is an assertion. Writing one merely to turn a red gate green
is fabrication, and this project would rather fail a gate than fake one.

So: **document only the invariant you actually verified.** Where an invariant
cannot be established from the code in front of you, say so —

```rust
// SAFETY: upstream asserts <X> here; the invariant depends on <Y> which is not
// checkable from this module. Not independently verified.
```

— which is honest, still satisfies the harness, and leaves an accurate trail. A
confident invention does not become true by compiling.
