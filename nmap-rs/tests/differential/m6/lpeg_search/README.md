# M6.6 step 0b: adversarial slowness search over the network-facing LPeg patterns

**Local only.** CI never runs this. It never edits the tree's `lpeg.c`,
`liblua/` or anything else in the repository. It builds from a patched copy
of `lpeg.c` and writes only to a work directory outside the repository.

## What it does

`patch_lpeg.py` writes an instrumented copy of `lpeg.c` with two counters:
one per VM instruction, and one per capture-evaluation step (each
`pushcapture` call). `lpeg.__steps()` returns both and resets them.
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

The last full measurement is the step 0b critic's re-run of this search,
with this fitness, at 300 s CPU per pattern. get_response and parse_fp were
not re-run; their figures come from the first 120 s run (`*`), whose fitness
had no floor but whose maxima came from 64 KiB subjects anyway. The values
below are recomputed from those runs' saved outputs, using this harness's
definitions:

| pattern | max steps/byte (≥ 1 KiB) | at size | best, ≥ 64 B | grow_exp | env_exp | tail_exp | 1.25 × max |
|---|---|---|---|---|---|---|---|
| json | 22.15 | 6,887 | 22.17 | 0.999 | 1.008 | 1.001 | 27.69 |
| get_response* | 21.46 | 65,536 | 21.46 | 1.010 | 1.035 | 1.001 | 26.82 |
| parse_fp* | 21.02 | 65,536 | 21.04 | 0.995 | 1.057 | 1.007 | 26.28 |
| ntp | 19.64 | 6,888 | 19.64 | 0.998 | 1.046 | 1.002 | 24.55 |
| escaped_quote | 14.00 | 1,217 | 14.09 | 0.999 | 0.999 | 0.997 | 17.51 |
| aff_amz | 8.01 | 1,217 | 8.16 | 1.009 | 0.998 | 1.000 | 10.01 |
| fpstrings | 7.69 | 1,217 | 8.14 | 0.976 | 0.982 | 0.933 | 9.61 |
| aff_ga | 7.01 | 1,217 | 7.12 | 0.997 | 0.998 | 1.000 | 8.76 |
| aff_ad | 7.01 | 1,217 | 7.12 | 0.997 | 0.998 | 0.997 | 8.76 |
| coap | 6.67 | 1,216 | 6.76 | 0.998 | 0.990 | 0.969 | 8.34 |
| aff_short | 6.01 | 1,217 | 6.12 | 0.994 | 0.998 | 1.000 | 7.51 |

Every pattern is linear: no exponent reaches 1.06. The step 0b report's
figures differ from these in two places:
- coap: the report quoted 6.76, which is the best over subjects of at least
  64 bytes;
- fpstrings: the report quoted 7.66, the plateau above 4 KiB.

Step e sets K per pattern at 1.25 × the maximum from a 600 s run of
`./run_search.sh`, which has not been done yet.

The budget matters. A 5 s smoke run of this harness reached lower maxima,
for example ntp 14.6 steps/byte and parse_fp 15.7.

## What the counters cannot see

The VM counter adds one step per instruction, but `ISpan` (`S(...)^0`,
`(P(1) - x)^0` and the like) consumes a whole run of bytes in one
instruction. Work inside a span is therefore invisible to steps per byte.
A pattern that rescans a span from many start positions is quadratic in
time and linear in steps. For example, `anywhere(P"a"^0 * "b")` on a run of
`a`s gives a flat 6.00 steps/byte from 1,000 to 8,000 bytes, while its CPU
time grows about 30-fold. This search cannot find that shape.

By inspection, none of the 11 patterns has it. Their retry loops start with
a literal or bounded head: `anywhere("%r(")`, `'UA-'`, `'pub-'`,
`'http://'`, and fingerprint-strings' `^-(n-1)`. A pattern added later
should be checked for it by hand, or the counter extended.

## Files

| file | what |
|---|---|
| `run_search.sh` | the entry point: builds if needed, runs the patterns in parallel, prints the table |
| `build_instrumented.sh` | patches a copy of `lpeg.c`, builds `lua-instr`, checks that `lpeg.__steps` counts and resets |
| `build_patched_lua.sh` | builds the oracle interpreter around any patched copy of `lpeg.c` through `oracle/build_lua_oracle.sh`; `../lpeg_sabotage` uses it too |
| `patch_lpeg.py` | the instrumentation: four anchored edits, each of which must match once |
| `search.lua` | the search and the exponent fits for one pattern |
| `matchers.lua`, `stubs.lua` | the 11 patterns, and the stubs that let nselib load standalone |
| `verify_wellformed.lua`, `scriptside.lua` | the closed-family fits and the script-side CPU times |
