# M6.6 step 0b: adversarial slowness search over the network-facing LPeg patterns

**Local only.** CI never runs this. It never edits the tree's `lpeg.c`,
`liblua/` or anything else in the repository. It builds from a patched copy
of `lpeg.c` and writes only to a work directory outside the repository.

## What it does

`patch_lpeg.py` writes an instrumented copy of `lpeg.c` with two counters:
one per VM instruction and per byte a span instruction examines, and one per
capture-evaluation step (each `pushcapture` call). `lpeg.__steps()` returns
both and resets them. (Until M6.6 step e a span counted once however many
bytes it scanned; see "What the counters cannot see".)
`build_patched_lua.sh` builds the M6 oracle interpreter around that copy.
It runs the committed `oracle/build_lua_oracle.sh` itself, in a throw-away
tree under the work directory, so the build recipe is the oracle's own.

`search.lua` takes one pattern and runs an evolutionary hill-climb over
subjects of up to 64 KiB. It starts from realistic fixtures and the pattern's
`grow(n)` family, and maximises LPeg work per subject byte. Selection uses
the step 0b critic's fitness, `(vm + cap) / max(#s, SELMIN)` with SELMIN
1024. Without the floor, tiny subjects, whose per-byte cost is inflated by a
match's fixed start-up cost, crowd large ones out. The reported ratios are
plain `(vm + cap) / #s`. After the search it fits steps against size four
ways:
- `grow_exp`: over the hand-written `grow(n)` family;
- `env_exp`: over the search's envelope from 64 B;
- `pre_exp`: over prefixes of the subject with the most steps;
- `tail_exp`: over the envelope from 8 KiB.

The 11 patterns (`matchers.lua`) are built from this tree's real sources:
- **`require`d through `package.path`, with `stubs.lua`:** `json`
  (`json.parse`) and lpeg-utility's `get_response`, `parse_fp` and
  `escaped_quote`.
- **Sliced out of the real files by exact-line anchors and loaded:** `coap`
  (link format), `ntp` (ntp-info's `kvmatch`), `fpstrings`
  (fingerprint-strings' `strings()` at the script's default n=4) and the four
  http-affiliate-id `re` grammars (`aff_ga`, `aff_ad`, `aff_amz`,
  `aff_short`). An edit that moves an anchor stops the search with an error;
  it does not measure a stale copy. The `site` column of each result gives
  the file and the line numbers it read.

## How to run

```sh
./run_search.sh                              # all 11, 600 s CPU each, 4 at once (~30 min)
./run_search.sh --budget 5                   # smoke test (~20 s)
./run_search.sh -j 2 --work /scratch/ls json ntp
```

| option | default |
|---|---|
| `--work DIR` | `$LPEG_SEARCH_WORK`, else `${TMPDIR:-/tmp}/nmap-lpeg-search`. A directory inside the repository is refused |
| `--budget SECONDS` | `$LPEG_SEARCH_BUDGET`, else 600 CPU seconds per pattern |
| `-j JOBS` | `$LPEG_SEARCH_JOBS`, else 4 |
| `--selmin N` | 1024 |
| `--rebuild` | rebuild `lua-instr` even if it is newer than every input |

The work directory receives:
- `lua-instr`, the instrumented interpreter (about 4 s to build);
- `out/res_ID.txt`, the full result for each pattern: every `GROW_ROW`,
  `ENV_ROW` and `PREFIX_ROW`;
- `out/sustained_ID.bin`, `best_ID.bin` and `beststeps_ID.bin`, the subjects
  behind the maxima;
- `out/table.txt`, the printed table;
- `out/wellformed.txt` (`verify_wellformed.lua`), which fits closed families
  for get_response, parse_fp and ntp, where every size runs both LPeg passes;
- `out/scriptside.txt` (`scriptside.lua`), which gives the CPU time of the
  Lua around two patterns that the counters do not see: ntp-info's
  `accumulate_output`, quadratic in the pair count, and json's table build.

To clean up, delete the work directory.

The table has one row per pattern:
- **`max_spb`:** the highest steps per byte over every subject of at least
  SELMIN bytes, the "max sustained steps/byte". `at_size` is that subject's
  size.
- **`best_64`:** the same over subjects of at least 64 bytes.
- **The four exponents:** about 1.0 means linear.
- **`K_1.25`:** 1.25 × `max_spb`.

A warning is printed if `grow_exp` or `tail_exp` exceeds 1.10. Two exponents
read high for known reasons, so the warning ignores them:
- `env_exp` needs a long budget to settle;
- `pre_exp` can read up to about 1.2 for get_response and parse_fp. A
  prefix that cuts the closing quote skips the unescape pass, so only the
  full subject pays for both.

## What it last measured

M6.6 step e, 2026-10-12: `./run_search.sh` at its defaults (600 s CPU per
pattern, SELMIN 1024, 4 at once), with span bytes counted:

| pattern | evals | max steps/byte (≥ 1 KiB) | at size | best, ≥ 64 B | grow_exp | env_exp | pre_exp | tail_exp | K = 1.25 × max |
|---|---|---|---|---|---|---|---|---|---|
| json | 1,393,156 | 22.51 | 1,025 | 22.60 | 0.999 | 0.999 | 1.009 | 0.999 | 28.13 |
| get_response | 140,392 | 21.48 | 65,348 | 21.48 | 1.010 | 1.049 | 1.190 | 1.000 | 26.85 |
| parse_fp | 141,634 | 21.46 | 65,129 | 21.46 | 0.996 | 1.111 | 1.188 | 1.001 | 26.83 |
| ntp | 294,998 | 21.00 | 65,531 | 21.00 | 0.998 | 1.048 | 1.000 | 1.001 | 26.25 |
| escaped_quote | 13,231,795 | 14.01 | 1,024 | 14.09 | 0.999 | 0.999 | 1.000 | 0.997 | 17.51 |
| fpstrings | 14,527,764 | 8.03 | 1,025 | 8.51 | 0.981 | 0.984 | 1.000 | 0.924 | 10.04 |
| aff_amz | 22,245,828 | 8.01 | 1,024 | 8.16 | 1.009 | 0.996 | 1.000 | 0.997 | 10.01 |
| aff_ga | 24,615,102 | 7.01 | 1,024 | 7.12 | 0.997 | 0.998 | 1.000 | 1.000 | 8.76 |
| aff_ad | 24,566,020 | 7.01 | 1,024 | 7.12 | 0.997 | 0.998 | 1.000 | 0.997 | 8.76 |
| coap | 90,160 | 6.90 | 48,546 | 6.90 | 0.998 | 1.033 | 1.002 | 1.001 | 8.63 |
| aff_short | 29,806,387 | 6.01 | 1,024 | 6.12 | 0.994 | 0.998 | 1.000 | 1.000 | 7.51 |

Every pattern is linear: no `grow_exp` or `tail_exp` passes 1.01, so the
run printed no warning (`env_exp` and `pre_exp` read high for the known
reasons above). Counting span bytes moved four maxima, each by under 7%
(step 0b's critic, 300 s and spans counted once: json 22.15, ntp 19.64,
fpstrings 7.69, coap 6.67); none of the 11 has the span-rescanning shape,
as step 0b judged by inspection. The closed families (`wellformed.txt`)
fit 0.997 to 1.003.

## The regression gate

`adversarial/` holds, for each pattern, the subject behind its maximum
(`sustained_ID.bin` as `ID.bin`), and `K.txt` the instrumented C's counts on
it and K = 1.25 × its steps per byte (D3 condition 4). The port's
`crates/core/tests/lpeg_slowness_regression.rs` builds the same 11 patterns
through this directory's own `matchers.lua`, unmodified, runs each on its
subject, and counts steps with the port's counters in the same units
(`lpeg::take_steps`: instructions and span bytes, and `pushcapture` calls).
Each pattern must stay at or under its K, and its counts must be the C's: they
are equal on all 11 but escaped_quote, where the C's machine takes one more
step, its `IGiveup` on a failed match. It also checks that the counter sees a
span's bytes, and (since the M6.6 retrospective) that a span cut by slice
boundaries counts as one slice does: until then each boundary inside a span
counted two steps more, so the counts were the C's only while no span crossed
a slice (`a_span_cut_by_slices_counts_as_one_slice_does`). Deterministic,
under a second; it runs in `cargo test`.

To move the gate after a new search: copy `OUT/sustained_ID.bin` to
`adversarial/ID.bin`, and write each row of `K.txt` from `OUT/res_ID.txt`'s
`SUSTAINED` line and the instrumented interpreter's `lpeg.__steps()` over the
new subject (`matchers.lua`'s `M[id].match`, through `pcall`).

## What the counters cannot see

Until M6.6 step e the VM counter added one step per instruction, and `ISpan`
(`S(...)^0`, `(P(1) - x)^0` and the like) consumes a whole run of bytes in
one instruction, so a pattern that rescans a span from many start positions
was quadratic in time and linear in steps: `anywhere(P"a"^0 * "b")` on a run
of `a`s gave a flat 6.00 steps/byte from 1,000 to 8,000 bytes while its CPU
time grew about 30-fold. `patch_lpeg.py` now counts every byte a span
examines, and that pattern takes 506,505 steps at 1,000 bytes and 8,026,005
at 4,000 (`build_instrumented.sh` checks a 1,000-byte span counts at least
1,000). The port counts span bytes the same way (`lpeg::take_steps`, and its
work counter).

What still goes uncounted:
- **Inside a capture's evaluation.** One step per `pushcapture` call: a
  substitution's walk of its nested captures, a string capture's copy of its
  bytes, a back-reference's re-evaluation of its group are each one step,
  whatever their length. The port's fuel and work counter charge them (a unit
  per frame and per `BYTES_PER_FUEL` bytes); this gate does not compare them.
- **The Lua around a pattern**: `scriptside.txt` times two.
- **The compile**, once per pattern.
- **Subjects above 64 KiB.**

## Files

| file | what |
|---|---|
| `run_search.sh` | the entry point: builds if needed, runs the patterns in parallel, prints the table |
| `build_instrumented.sh` | patches a copy of `lpeg.c`, builds `lua-instr`, checks that `lpeg.__steps` counts and resets |
| `build_patched_lua.sh` | builds the oracle interpreter around any patched copy of `lpeg.c` through `oracle/build_lua_oracle.sh`; `../lpeg_sabotage` uses it too |
| `patch_lpeg.py` | the instrumentation: five edits (1, 2, 2b, 3, 4) over six anchors, each of which must match once |
| `search.lua` | the search and the exponent fits for one pattern |
| `matchers.lua`, `stubs.lua` | the 11 patterns, and the stubs that let nselib load standalone |
| `verify_wellformed.lua`, `scriptside.lua` | the closed-family fits and the script-side CPU times |
| `adversarial/` | each pattern's adversarial subject and `K.txt`, the regression gate's ceilings |
