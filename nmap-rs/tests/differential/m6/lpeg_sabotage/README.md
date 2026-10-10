# M6.6 step 0b: does the LPeg corpus catch a sabotaged `lpeg.c`?

**Local only.** CI never runs this. It never edits the tree's `lpeg.c`,
`liblua/` or the committed corpus files. Each variant is a patched copy of
`lpeg.c` built in a work directory outside the repository.

## What it does

`variants.py` holds the 16 sabotages of the M6.6 sequencing review (S01 to
S16) and the unpatched baseline S00. Each sabotage is an anchored edit, and
an anchor must match exactly once, so a variant can never silently build
unpatched.

`build_variants.py` writes each patched copy and builds it with
`../lpeg_search/build_patched_lua.sh`. That script runs the committed
`oracle/build_lua_oracle.sh` in a throw-away tree, so every variant is built
by the oracle's own recipe.

`sabcmp.py` then works as follows:
1. It snapshots `m66_lpeg_cases.txt`, `m66_lpeg_golden.txt` and
   `m66_lpeg_steps.txt` into the work directory, so a regeneration running
   at the same time cannot change them mid-run. It refuses to go on if the
   cases and the golden name different rows.
2. It runs the cases through each build with `oracle/m66_lpeg_driver.lua`.
   The runner is `screen_m66_lpeg.resume`, which resumes after any row that
   kills or hangs the build, and such a row counts as caught.
3. It compares each row with the golden, hash-order masked. The readers and
   the canonicalisation are `oracle/classify_m66_lpeg.py`'s.

Rows the cases file tags `cdepth` or `drift794` are left out. Their answer
belongs to the embedding (a C-stack or Lua-stack depth), not to the engine.

The run fails if the baseline differs on any row. On a full run, it also
fails if a sabotage differs on no row, or if any of S05, S07, S08, S09, S10
and S14 is not caught by a fixed row of family X.

## How to run

```sh
./run_sabotage.sh                         # build all 17 and run the whole corpus (a few minutes)
./run_sabotage.sh --limit 2000 S00 S13    # smoke test: two builds, the first 2,000 rows (~5 s)
python3 -I -B sabcmp.py --work DIR S06    # re-run the comparison on builds already in DIR
```

| option | default |
|---|---|
| `--work DIR` | `$LPEG_SABOTAGE_WORK`, else `${TMPDIR:-/tmp}/nmap-lpeg-sabotage`. A directory inside the repository is refused |
| `-j JOBS` | 4 builds at once; each takes about 4 s |
| `--limit N` | the whole corpus. With N, only the first N rows run, and only the baseline check applies |
| `--timeout SECONDS` | 120: how long one driver process may run before the row it is on counts as hung |
| `VARIANT ...` | all 17. Full names or S-numbers (`S00 S13`) |

The run prints, for each variant:
- the rows that differ;
- how many of them are fixed rows, that is, not from the random families R
  and Q;
- the rows that crashed or hung;
- the first fixed rows that catch it, family X first;
- how the differing rows map to the plan's steps (b/c/d).

The full lists go to `WORK/out/sab.json`, and the builds' logs to
`WORK/log/`. To clean up, delete the work directory.

## What it last measured

The last full run was the step 0b critic's, over the committed corpus of
62,599 rows, leaving out the 22 `cdepth` rows. The result is the table under
"What the corpus catches" in `../README.md`:
- every sabotage differs on at least one row;
- the baseline differs on none;
- S05, S07, S08, S09, S10 and S14 are each caught by a fixed row of family X.

S06 hangs on `R.6687`, which is why the per-process timeout exists. S11
crashes on about ten rows, and which rows those are moves with the memory
layout.

The same run mapped each differing row to the step whose gate first runs it:
- S01, S02, S04, S05 and S10 to S16 are caught by rows at steps b or c;
- S03, S06, S07, S08 and S09 are caught only by rows at step d.

That run predates the `drift794` tag and the regeneration under way when
this harness was packaged, so the counts will move with the corpus.
