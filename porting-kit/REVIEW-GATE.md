# REVIEW-GATE: gate 6, an independent review before the next step

PLAYBOOK Phase 4 gate 6 links here. The rule: **every step is reviewed for
fidelity and for security before the next step starts.** Each finding is fixed
or ledgered in the same PR, and its class becomes a standing gate for every
later step (LESSONS #041). This page also holds the sabotage protocol the review
uses (LESSONS #038, #044) and the merge preconditions (LESSONS #042, #045).

## Why

In nmap's M6.6, every step's automated gates were green at its commit, and every
step that was reviewed still had defects:

- Review fix rounds were 57%, 57%, 28% and 34% of their step's Rust churn, plus
  a 2,473-line base-library port that step d's review triggered.
- Two PRs (#130, #134) merged before their reviews ran. The step c defects sat
  on master for more than three hours.
- Step e was never reviewed. Its later review found only a nit, but nothing had
  required that review.
- Step b's review said "fuel is charged per call, not per unit of work". The
  class recurred at steps c and d, because each fix gated only its own step.
- Step b's fidelity review found that `next({})` returns 2 values. It filed the
  finding as "Incidental, not LPeg, not ledgered". The base library stayed wrong
  until step d's review.

Reviews were the only mechanism that found M6.6's defects. A gate that is
optional is skipped exactly when it matters.

## The gate

1. **Independent.** The reviewer is not the author: a fresh session or agent, or
   a human, with the step's diff, the ledger and the oracle.
2. **Two lenses, both required.**
   - *Fidelity:* adversarial rows beyond the corpus, run against the C oracle.
     Cover defaults and omitted options (LESSONS #047), error paths, argument
     numbering, and the sibling functions of anything touched. When a
     dependency is involved, check every function its exposed API reaches, not
     only the ones the corpus calls (LESSONS #043).
   - *Security and resources:* time, memory and totality. That means the
     per-slice and total work, n-versus-4n scaling against C
     (`RESOURCE-BOUNDS.md`), peak and retained memory, panics, and inputs that
     block (FIFOs, `/dev/zero`).
3. **An independent sabotage set** (below), with its catch rate reported.
4. **A severity table**: one row per finding, with severity, class, how it was
   found, and the gate that would have caught it at its step.
5. **A fix round in the same PR.** The merge is blocked until each finding is
   either fixed with a pinning test or ledgered with an ID.
6. **The finding's class becomes a standing gate.** Add it to the entry gates of
   every later step, for example "unmetered work: work counted apart from fuel,
   plus a scale check". The plan carries the list, and each later review checks
   it first.
7. **Out-of-scope findings are recorded the same day.** Each one gets a ledger
   entry or a BACKLOG row with an ID. "Incidental, not ledgered" is not a
   disposition.

### Reviewer brief (paste into the reviewing session)

> Review step `[STEP]` (commit `[SHA]`) of the `[PROJECT]` port. Read-only.
> Lens 1, fidelity: find inputs where the port and the C oracle disagree, beyond
> the committed corpus. Try defaults, error messages and argument numbers, the
> boundaries, and the sibling functions of everything touched. Lens 2, security
> and resources: measure per-slice and total time and peak and retained memory
> at n and 4n, port against C, in a release build. Try blocking inputs and
> panics. Then write your own sabotage set of at least 10 mutations, run the
> gates against it, and report which mutations survive. Restore each file from
> a byte copy and bump its mtime. Only a named assertion counts as a catch.
> Output: a severity table (severity, class, repro, the gate that would have
> caught it) and a list of out-of-scope findings with proposed ledger IDs.

## Merge preconditions

- **CI ran on the head SHA** (LESSONS #042). The commit has check runs, and they
  are green: `gh api repos/OWNER/REPO/commits/SHA/check-runs --jq .total_count`
  is not 0. If CI cannot run, run every workflow job locally, unscoped, with
  `make -C porting-kit ci-local`, and paste its summary into the PR. A PR that
  says "CI did not run" and has no `ci-local` summary is blocked, not annotated.
  The whole of M6.6 merged with zero check runs while its local stand-ins were
  scoped. That is LESSONS #030's trap, and the gate the kit trusted most never
  ran.
- **The tracker is updated and stamped** (LESSONS #045):
  `progress.py --file progress.json set MODULE GATE --src crates`, so that
  `audit --src crates` notices when the module's code later outgrows the tick.

## The sabotage protocol

A sabotage run measures the gates. Like any measurement, it can fail without
anyone noticing.

1. **Restore from a byte copy and bump the mtime.** Save the file's bytes, mutate
   the file, run the gate, then write the saved bytes back and `touch` the file.
   - Do not restore with `git checkout -- file`. It restores the last commit and
     discards uncommitted work (LESSONS #038).
   - Do not restore with `cp -p` or `shutil.copy2`. They put back the old mtime,
     so cargo's fingerprint sees no change and the next run tests the stale,
     still-sabotaged build. M6.6's step a review hit exactly this (LESSONS #044).
2. **Only a named assertion counts as a catch.** The test you expect must fail,
   with its message. A kill, a timeout or a harness crash is *inconclusive*:
   either bound the run or fix the gate, then re-run. Step b's S2 had been
   counted as caught by a 117 s kill. After its fix it failed by assertion in
   29 s.
3. **Each step gets an independent set.** The author's own sabotages share the
   author's blind spots. At step a, all 11 of the author's mutations were
   caught, and 8 of the reviewers' 34 survived every gate. Report the catch rate
   and treat each survivor as a missing case (see the positive validation in
   LESSONS): add the fixture that kills it, checked against C first.
4. **Sabotage inside every tolerance.** Mutate the port within the spans a
   normalisation or tolerance class absorbs. An unscoped tolerance passed an
   argument-number regression on 5,906 rows (LESSONS #048).
5. **Sabotage the C to measure the corpus** (Phase 2, `ORACLE-CHECKS.md`). Port
   sabotage measures the gates. C sabotage measures whether the corpus can
   discriminate at all.
