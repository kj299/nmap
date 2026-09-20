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
| local changes | `patches/0001-backport-gc-arena-0.5.3.patch` — 7 files, 382 lines |
| omitted | the `util/` workspace member (`piccolo-util`); unused here, and it carries 4 further `unsafe` blocks |

`Cargo.toml` is **ours**, not upstream's: upstream's is a workspace root and
cannot be vendored as-is.

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
git apply /path/to/nmap-rs/crates/vendor/piccolo/patches/0001-backport-gc-arena-0.5.3.patch
diff -ru src /path/to/nmap-rs/crates/vendor/piccolo/src     # expect no output
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
| ASan | see below | the job is scoped `-p nmap-sys`; extending it is tracked as M6.0 work |

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
