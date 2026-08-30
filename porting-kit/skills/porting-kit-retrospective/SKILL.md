---
name: porting-kit-retrospective
description: Close a C-to-Rust port (or a major phase) and patch the Porting Kit with what was learned. Use when a port/phase is complete, or when the user asks to "wrap up", "retro", "capture lessons", or "improve the kit". This is the compounding loop — every port leaves the kit sharper than it found it.
---

# Porting Kit — closing retrospective (patch the kit)

Wraps `porting-kit/PROMPTS/90-retrospective.md`. This is the rule from
`porting-kit/CLAUDE.md`: **every port ends with a retrospective that patches the kit.**
A port that ships without this wastes its most valuable output.

## Procedure
0. **Run every harness against the real target first — not last.** The kit's own
   post-ship passes (LESSONS #2–#4) each found a defect *in a harness* (a noisy
   scanner, an unwired gate, an under-checking differential); none surfaced from
   reading the prose. A dry-run that doesn't execute the tools against the actual code
   is theater. Run `scan_c_flaws.py`, `audit_unsafe.py`, the differential, etc. and
   eyeball the signal-to-noise.
   **Run the kit's own self-check as the very first command**, and treat its failure as
   a finding rather than an obstacle to route around: `make -C porting-kit check-kit`
   returned *"No rule to make target"* at the start of the M5 retrospective — sixteen
   documented references to a target that had never existed, past an integrity checker
   that validated paths but not commands (LESSONS #022).
   **Point the flaw scanner at the files where this port actually found bugs** and
   check whether it reports them. If it does not, that gap is the headline finding, not
   a footnote — in M5 it missed both defects in the file it was run on (LESSONS #020).
1. **Reconstruct from artifacts** the way `RETROSPECTIVE-lsof.md` was built: lean on git
   history — especially commit *sequences* where a message says "the real fix"
   (higher signal than reverts), churn per file (time-sink proxy), the final
   `progress.json`, and the `DIVERGENCES.md` entries.
   **Sweep the port's own notes first** (`BACKLOG.md`, `LESSONS`-ish files, TODOs in
   the repo being ported). Lessons are often already written down *locally* and never
   promoted — nmap's "an oracle must copy the C, not restate it" sat in the port's
   backlog for nine PRs while the kit stayed ignorant (LESSONS #019). A lesson
   recorded outside the kit does not compound. Promote every one you find.
   Treat `progress.json` as **suspect until verified**: run
   `progress.py --file <f> drift --src crates` before trusting it, because a stale
   table misleads this review specifically (LESSONS #021).
2. **Diff lived experience against `PLAYBOOK.md`.** Per phase: did entry/exit criteria
   match reality? Was a gate missing that would have caught a bug earlier? Did any
   harness misfire, over-report, or get skipped (a skipped control is a broken
   control)? **Did a failure occur the playbook would NOT have prevented?** — the most
   important finding.
3. **Patch the kit — make the edits, don't just describe them:** amend `PLAYBOOK.md`;
   fix/extend a harness and re-run `make -C porting-kit check-kit`; update
   `ARCHITECTURE-TEMPLATE.md`, the `PROMPTS/`, or these skills if the shape/loop changed.
   **Keep the skills in integrity with the kit** — if you renamed a harness or changed a
   flag, update every skill that references it (the skills-integrity check enforces this).
4. **Append to `porting-kit/LESSONS.md`** — one entry per lesson in the required format
   (date, codebase, lesson, section amended). If the kit had the lesson but it didn't
   fire, say why (friction? unclear? not wired to CI?).
5. **Commit the kit changes separately** from the port, each message explaining which
   failure it prevents next time.

Report: the top 3 kit improvements and the single failure the kit still would not have
prevented (the next port's target).

## Integrity
This skill and the rest of the suite are part of "all elements of the kit" — keep them
consistent with `PLAYBOOK.md`, the harnesses, and `LESSONS.md`. Run
`make -C porting-kit check-kit` (which includes the skills-integrity check) after edits.
