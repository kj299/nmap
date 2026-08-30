#!/usr/bin/env python3
"""Skills-integrity check — keeps the skills suite in lockstep with the kit.

Each skill in porting-kit/skills/<name>/SKILL.md is a thin invokable wrapper over
the kit's authoritative docs and real harness commands. The risk is *drift*: a
harness gets renamed or a flag changes, and a skill quietly points at something
that no longer exists. This check makes that a hard failure — it verifies:

  1. every SKILL.md has YAML frontmatter with `name:` and `description:`,
  2. the frontmatter `name` matches its directory name,
  3. every `porting-kit/<path>` a skill references actually exists in the kit,
  4. every `make <target>` a skill tells the reader to run actually exists in the
     kit's Makefile.

Check 4 exists because check 3 alone was not enough: the M5 retrospective (nmap)
found `make -C porting-kit check-kit` cited in sixteen places across the docs and
all six skills while no Makefile existed at all. Only *paths* were validated, so a
phantom command sailed through — the kit's own LESSONS #003 ("a delegated control
that nothing enforces is not a control") reproduced inside the integrity checker
meant to prevent it.

Wired into `make check-kit`, so renaming a harness without updating the skills
(or the docs) breaks the build — the compounding-loop rule that the retrospective
must "keep the skills in integrity with the kit," enforced mechanically.

Usage:  check_skills.py [SKILLS_DIR]   (defaults to this file's directory)
        check_skills.py --self-test
"""
from __future__ import annotations

import os
import re
import sys

# A referenced kit path: porting-kit/<something with an extension or a dir>.
# Skip placeholders (<...>, *) and trailing punctuation/backticks.
PATH_RE = re.compile(r"porting-kit/[A-Za-z0-9_./-]+")
PLACEHOLDER = re.compile(r"[<>*`]")
# `make check-kit`, `make -C porting-kit check-kit`, `make  -C  <dir>  target`.
# Only ever applied to CODE SPANS, never to prose: "make the edits" is English, not
# an invocation, and matching it produced a false positive the first time this check
# ran. Inline `code` and fenced blocks are the only places a command can live.
MAKE_RE = re.compile(r"\bmake\s+(?:-C\s+\S+\s+)?([a-zA-Z][a-zA-Z0-9_.-]*)")
CODE_SPAN_RE = re.compile(r"`{1,3}([^`]+)`{1,3}", re.S)
# Targets Make itself defines or that are conventional no-ops in prose.
MAKE_IGNORE = {"all", "clean", "install", "test", "help"}


def cited_make_targets(text):
    """Make targets named inside code spans, in order, deduped."""
    found = []
    for span in CODE_SPAN_RE.findall(text):
        found.extend(MAKE_RE.findall(span))
    return [t for t in dict.fromkeys(found) if t not in MAKE_IGNORE]


def makefile_targets(kit_root):
    """Every explicit target in the kit's Makefile, or None if there is no Makefile."""
    path = os.path.join(kit_root, "Makefile")
    if not os.path.isfile(path):
        return None
    targets = set()
    for line in open(path, encoding="utf-8"):
        if line.startswith("\t") or line.lstrip().startswith("#"):
            continue
        m = re.match(r"([A-Za-z0-9_.-]+(?:\s+[A-Za-z0-9_.-]+)*)\s*:(?!=)", line)
        if m:
            targets.update(m.group(1).split())
    targets.discard(".PHONY")
    return targets


def parse_frontmatter(text):
    if not text.startswith("---"):
        return None
    end = text.find("\n---", 3)
    if end < 0:
        return None
    fm = {}
    for line in text[3:end].splitlines():
        if ":" in line:
            k, v = line.split(":", 1)
            fm[k.strip()] = v.strip()
    return fm


def check_skill(skill_dir, kit_root, make_targets=None):
    problems = []
    name = os.path.basename(skill_dir.rstrip("/"))
    path = os.path.join(skill_dir, "SKILL.md")
    if not os.path.isfile(path):
        return [f"{name}: missing SKILL.md"]
    text = open(path, encoding="utf-8").read()

    fm = parse_frontmatter(text)
    if fm is None:
        problems.append(f"{name}: no YAML frontmatter (--- ... ---)")
    else:
        if not fm.get("name"):
            problems.append(f"{name}: frontmatter missing `name`")
        elif fm["name"] != name:
            problems.append(f"{name}: frontmatter name '{fm['name']}' != directory '{name}'")
        if not fm.get("description"):
            problems.append(f"{name}: frontmatter missing `description`")

    # Every referenced kit path must exist.
    for m in dict.fromkeys(PATH_RE.findall(text)):  # dedupe, keep order
        rel = m[len("porting-kit/"):].rstrip(".,);:")
        if not rel or PLACEHOLDER.search(m):
            continue
        if not os.path.exists(os.path.join(kit_root, rel)):
            problems.append(f"{name}: references missing kit path '{m}'")

    # Every `make <target>` the skill tells the reader to run must exist.
    cited = cited_make_targets(text)
    if cited and make_targets is None:
        problems.append(f"{name}: cites `make {cited[0]}` but the kit has no Makefile")
    elif make_targets is not None:
        for target in cited:
            if target in make_targets:
                continue
            problems.append(f"{name}: references missing make target '{target}'")
    return problems


def run(skills_dir):
    kit_root = os.path.dirname(os.path.abspath(skills_dir.rstrip("/")))
    skill_dirs = sorted(
        os.path.join(skills_dir, d) for d in os.listdir(skills_dir)
        if os.path.isdir(os.path.join(skills_dir, d))
    )
    if not skill_dirs:
        print(f"no skills found under {skills_dir}")
        return 1
    make_targets = makefile_targets(kit_root)
    all_problems = []
    for sd in skill_dirs:
        all_problems.extend(check_skill(sd, kit_root, make_targets))
    for p in all_problems:
        print("PROBLEM: " + p)
    print(f"\n{len(skill_dirs)} skill(s) checked, {len(all_problems)} problem(s)")
    return 1 if all_problems else 0


def _self_test():
    import tempfile
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "porting-kit")
        skills = os.path.join(kit, "skills")
        os.makedirs(os.path.join(kit, "harnesses"))
        open(os.path.join(kit, "PLAYBOOK.md"), "w").write("x")
        # good skill: valid frontmatter + only-existing refs
        good = os.path.join(skills, "good-skill"); os.makedirs(good)
        open(os.path.join(good, "SKILL.md"), "w").write(
            "---\nname: good-skill\ndescription: ok\n---\nsee porting-kit/PLAYBOOK.md\n")
        check("clean suite passes", run(skills) == 0)
        # bad skill: name mismatch + missing referenced path
        bad = os.path.join(skills, "bad-skill"); os.makedirs(bad)
        open(os.path.join(bad, "SKILL.md"), "w").write(
            "---\nname: WRONG\ndescription: d\n---\nrun porting-kit/harnesses/gone.py\n")
        check("name mismatch + missing path is caught", run(skills) == 1)

    # The make-target check: a cited target must exist, prose must not be mistaken
    # for a command, and a kit with no Makefile at all must be caught.
    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "porting-kit")
        skills = os.path.join(kit, "skills")
        sk = os.path.join(skills, "s"); os.makedirs(sk)
        head = "---\nname: s\ndescription: d\n---\n"

        def write(body):
            open(os.path.join(sk, "SKILL.md"), "w").write(head + body)

        open(os.path.join(kit, "Makefile"), "w").write(
            ".PHONY: check-kit\ncheck-kit: check-skills\n\t@echo hi\ncheck-skills:\n\t@echo hi\n")
        write("run `make check-kit` now\n")
        check("existing make target passes", run(skills) == 0)
        write("run `make -C porting-kit check-skills` now\n")
        check("`make -C <dir> target` form is understood", run(skills) == 0)
        write("run `make check-nothing` now\n")
        check("missing make target is caught", run(skills) == 1)
        write("make the edits, don't just describe them\n")
        check("prose 'make the edits' is not a command", run(skills) == 0)
        os.remove(os.path.join(kit, "Makefile"))
        write("run `make check-kit` now\n")
        check("cited target with no Makefile at all is caught", run(skills) == 1)
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv and argv[0] == "--self-test":
        return _self_test()
    skills_dir = argv[0] if argv else os.path.dirname(os.path.abspath(__file__))
    return run(skills_dir)


if __name__ == "__main__":
    sys.exit(main())
