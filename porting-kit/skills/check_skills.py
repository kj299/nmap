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
     kit's Makefile,
  5. every LESSONS entry whose "Section amended" names a PLAYBOOK phase is cited
     by number in the skills (and prompt) that run that phase: Phase 4 in
     porting-kit-module and PROMPTS/10-module-port.md, Phase 2 in
     porting-kit-oracle, Phase 0 in porting-kit-kickoff and porting-kit-cflaw-scan.

Check 4 exists because check 3 alone was not enough: the M5 retrospective (nmap)
found `make -C porting-kit check-kit` cited in sixteen places across the docs and
all six skills while no Makefile existed at all. Only *paths* were validated, so a
phantom command sailed through — the kit's own LESSONS #003 ("a delegated control
that nothing enforces is not a control") reproduced inside the integrity checker
meant to prevent it.

Check 5 exists because checks 1-4 validate that a skill's references resolve, not
that it says what the PLAYBOOK says. By M6.6 no skill cited LESSONS #030, #036,
#038 or #039, all Phase-4 rules, and #039's in-flight patch touched only LESSONS
and PLAYBOOK: an agent driven by the module skill ran a loop four lessons behind
the book (LESSONS #046). An entry with no "Section amended" field is read by its
"Kit change" field instead (LESSONS is append-only, so old entries are not
rewritten to add one). Any `#N` counts as a citation, and `#2-#4` covers 2 to 4.

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


# Check 5: which skills/prompts must cite the lessons that amended each phase.
PHASE_CITERS = {
    "0": ["skills/porting-kit-kickoff/SKILL.md", "skills/porting-kit-cflaw-scan/SKILL.md"],
    "2": ["skills/porting-kit-oracle/SKILL.md"],
    "4": ["skills/porting-kit-module/SKILL.md", "PROMPTS/10-module-port.md"],
}
_ENTRY_RE = re.compile(r"^## (\d{3})\. ", re.M)
_FIELD_END = r"(?=\n[ \t]*\n|\n- \*\*|\n[ \t]*→|\n#|\Z)"
_AMENDED_RE = re.compile(r"Section amended:?\*{0,2}:?\*{0,2}(.*?)" + _FIELD_END, re.S)
_KITCHANGE_RE = re.compile(r"Kit change:?\*{0,2}:?\*{0,2}(.*?)" + _FIELD_END, re.S)
_PHASE_RE = re.compile(r"Phase[\s-]*(\d)")
_CITE_RANGE_RE = re.compile(r"#0*(\d{1,3})\s*[–—-]\s*#?0*(\d{1,3})")
_CITE_RE = re.compile(r"#0*(\d{1,3})\b")


def lessons_by_phase(text):
    """{phase digit: {lesson numbers}} for every entry whose Section amended (or,
    lacking one, Kit change) field names `PLAYBOOK ... Phase N` in one clause."""
    out = {}
    heads = list(_ENTRY_RE.finditer(text))
    for k, h in enumerate(heads):
        body = text[h.end():heads[k + 1].start() if k + 1 < len(heads) else len(text)]
        fields = _AMENDED_RE.findall(body) or _KITCHANGE_RE.findall(body)
        for field in fields:
            for clause in re.split(r"[;\n]", " ".join(field.split("\n"))):
                if "PLAYBOOK" in clause:
                    for ph in _PHASE_RE.findall(clause):
                        out.setdefault(ph, set()).add(int(h.group(1)))
    return out


def cited_lessons(text):
    """Every lesson number a document cites: `#30`, `#030`, and `#2–#4` ranges."""
    nums = {int(n) for n in _CITE_RE.findall(text)}
    for a, b in _CITE_RANGE_RE.findall(text):
        if int(a) <= int(b) <= int(a) + 20:
            nums.update(range(int(a), int(b) + 1))
    return nums


def check_lesson_citations(kit_root):
    path = os.path.join(kit_root, "LESSONS.md")
    if not os.path.isfile(path):
        return []
    need = lessons_by_phase(open(path, encoding="utf-8").read())
    problems = []
    for phase, docs in sorted(PHASE_CITERS.items()):
        for rel in docs:
            doc = os.path.join(kit_root, rel)
            if not os.path.isfile(doc):
                if rel.startswith("skills/"):
                    problems.append(f"{rel}: missing, but Phase {phase} lessons must be cited there")
                continue
            have = cited_lessons(open(doc, encoding="utf-8").read())
            missing = sorted(need.get(phase, set()) - have)
            if missing:
                problems.append(f"{rel}: does not cite Phase-{phase} lesson(s) "
                                + ", ".join(f"#{n:03d}" for n in missing))
    return problems


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
    all_problems.extend(check_lesson_citations(kit_root))
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

    # Check 5: a lesson that amended a phase must be cited where that phase runs.
    lessons = (
        "## 002. scanner\n- **Kit change:** x\n- **Section amended:** harnesses/x.py; the "
        "principle belongs to PLAYBOOK · Phase 0.\n\n"
        "## 026. cfg\n- **Section amended:** `SECURITY-CHECKLIST.md` (Phase-4 step)\n\n"
        "## 030. scoped gate\n- **What happened:** y\n- **Kit change:** `PLAYBOOK.md` Phase 4 — "
        "run each gate as CI runs it.\n\n"
        "## 040. bounds\n- **Section amended:** PLAYBOOK · Phase 4 (step 4b),\n"
        "  Phase 2; `harnesses/scaling/scale_check.py`.\n")
    need = lessons_by_phase(lessons)
    check("Section amended is read, wrapped lines included",
          need.get("4") == {30, 40} and need.get("2") == {40} and need.get("0") == {2})
    check("a Phase named outside a PLAYBOOK clause does not count", 26 not in need.get("4", set()))
    check("an entry with no Section amended is read by its Kit change", 30 in need.get("4", set()))
    check("citations: plain, zero-padded and ranges",
          cited_lessons("see LESSONS #2–#4 and (#030), #40") == {2, 3, 4, 30, 40})
    with tempfile.TemporaryDirectory() as root:
        kit = os.path.join(root, "porting-kit")
        os.makedirs(os.path.join(kit, "PROMPTS"))
        open(os.path.join(kit, "LESSONS.md"), "w").write(lessons)
        docs = {"skills/porting-kit-module/SKILL.md": "gates (LESSONS #030, #040)",
                "PROMPTS/10-module-port.md": "gates #30 #40",
                "skills/porting-kit-oracle/SKILL.md": "oracle #040",
                "skills/porting-kit-kickoff/SKILL.md": "scan (LESSONS #2)",
                "skills/porting-kit-cflaw-scan/SKILL.md": "noise (#002)"}
        for rel, body in docs.items():
            os.makedirs(os.path.dirname(os.path.join(kit, rel)), exist_ok=True)
            open(os.path.join(kit, rel), "w").write(
                (f"---\nname: {rel.split('/')[1]}\ndescription: d\n---\n" if rel.startswith("skills/")
                 else "") + body + "\n")
        check("a suite that cites every phase lesson passes", run(os.path.join(kit, "skills")) == 0)
        open(os.path.join(kit, "PROMPTS/10-module-port.md"), "w").write("gates #40\n")
        probs = check_lesson_citations(kit)
        check("a prompt missing a Phase-4 lesson is caught, by number",
              probs == ["PROMPTS/10-module-port.md: does not cite Phase-4 lesson(s) #030"])
        os.remove(os.path.join(kit, "PROMPTS/10-module-port.md"))
        check("an absent prompt is not required (skills are)", check_lesson_citations(kit) == [])
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
