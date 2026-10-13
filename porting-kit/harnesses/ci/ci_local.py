#!/usr/bin/env python3
"""ci-local: run every job of a GitHub Actions workflow on this machine,
unscoped, and print a summary to paste into the pull request.

No check run on the head SHA means no gate ran (LESSONS #042). nmap's CI did not
run from 5 October to the end of M6.6: every SHA of that milestone has zero
check runs, and four edits to the workflow (88 lines) never executed. The local
runs that stood in for it were scoped, which is LESSONS #030's trap: Miri on
`lpeg::` only ("43 passed ... 930 filtered out"), fuzzing only the changed
targets, and nothing that mentions `cargo deny` or the ASan job. A gate wired
into CI is a gate only on the commits CI ran on. When CI is down, this runs what
CI would have run: every job, every matrix leg, every `run:` step, with the
workflow's own working directories, environment and step outputs.

What it does not do, and says so in the summary:
  * `uses:` steps are not executed. Set-up actions (checkout, toolchains, caches)
    are assumed to be satisfied by this machine; any other action is listed as
    NOT RUN, because skipping it silently would be a scoped run again.
  * `if:` conditions are not evaluated; such steps are listed and not run.
  * GitHub-context expressions (`${{ github.* }}`, secrets) resolve to empty and
    are listed. `${{ matrix.* }}`, `${{ strategy.job-total }}`,
    `${{ strategy.job-index }}` and `${{ steps.<id>.outputs.<key> }}` are resolved.

It needs python3 only: it reads the workflow with a small YAML-subset parser
that handles what workflows use (block maps and lists, flow lists and maps, `|`
and `>` block scalars, comments). `--list` prints the plan without running it.

Usage:
  ci_local.py WORKFLOW.yml [WORKFLOW.yml ...] [--repo DIR] [--job ID ...]
              [--list] [--timeout SECONDS] [--json]
  ci_local.py --self-test

  --repo DIR   where commands run (default: the directory holding .github/)
  --job ID     run only these jobs. The summary then says SCOPED: a scoped run
               is an inner loop, not a substitute for CI (LESSONS #030)
Exit: 0 every job passed; 1 a job failed; 2 usage or parse error.
"""
from __future__ import annotations

import argparse
import itertools
import json
import os
import re
import subprocess
import sys
import tempfile
import time

# ----------------------------------------------------------------------------
# A YAML subset, enough for GitHub workflows
# ----------------------------------------------------------------------------


def _strip_comment(s):
    """Drop a ` #` comment outside quotes and brackets' strings."""
    q = None
    for i, c in enumerate(s):
        if q:
            if c == q:
                q = None
        elif c in "'\"":
            q = c
        elif c == "#" and (i == 0 or s[i - 1] in " \t"):
            return s[:i].rstrip()
    return s.rstrip()


def _split_top(s, sep=","):
    out, depth, q, cur = [], 0, None, []
    for c in s:
        if q:
            cur.append(c)
            if c == q:
                q = None
            continue
        if c in "'\"":
            q = c
        elif c in "[{":
            depth += 1
        elif c in "]}":
            depth -= 1
        if c == sep and depth == 0:
            out.append("".join(cur)); cur = []
        else:
            cur.append(c)
    if "".join(cur).strip():
        out.append("".join(cur))
    return out


def _scalar(s):
    s = s.strip()
    if not s:
        return None
    if s[0] == "[" and s[-1] == "]":
        return [_scalar(x) for x in _split_top(s[1:-1])]
    if s[0] == "{" and s[-1] == "}":
        out = {}
        for item in _split_top(s[1:-1]):
            k, _, v = item.partition(":")
            out[_scalar(k)] = _scalar(v)
        return out
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "'\"":
        body = s[1:-1]
        return body.replace("''", "'") if s[0] == "'" else body.replace('\\"', '"')
    if re.fullmatch(r"-?\d+", s):
        return int(s)
    if s in ("true", "false"):
        return s == "true"
    return s


def _indent(line):
    return len(line) - len(line.lstrip(" "))


def _key_split(text):
    """'key: rest' -> (key, rest); None when the line is not a mapping entry."""
    m = re.match(r"""\s*("[^"]*"|'[^']*'|[^\s'"#][^:#]*?)\s*:(?:\s+(.*)|$)""", text)
    if not m:
        return None
    return _scalar(m.group(1)), (m.group(2) or "")


class _Parser:
    def __init__(self, text):
        self.lines = text.expandtabs(8).splitlines()
        self.i = 0

    def _next(self):
        """Index of the next significant line (not blank, not a comment)."""
        j = self.i
        while j < len(self.lines):
            s = self.lines[j].strip()
            if s and not s.startswith("#"):
                return j
            j += 1
        return None

    def block(self, min_indent):
        j = self._next()
        if j is None or _indent(self.lines[j]) < min_indent:
            return None
        ind = _indent(self.lines[j])
        if self.lines[j].lstrip().startswith("- ") or self.lines[j].strip() == "-":
            return self.sequence(ind)
        return self.mapping(ind)

    def _block_scalar(self, header, parent_indent):
        style, chomp = header[0], header[1:2]
        raw = []
        while self.i < len(self.lines):
            line = self.lines[self.i]
            if line.strip() and _indent(line) <= parent_indent:
                break
            raw.append(line)
            self.i += 1
        while raw and not raw[-1].strip():
            raw.pop()
        if not raw:
            return ""
        ind = min(_indent(l) for l in raw if l.strip())
        body = [l[ind:] if l.strip() else "" for l in raw]
        if style == "|":
            text = "\n".join(body)
        else:  # folded: a single newline becomes a space, a blank line a newline
            text, para = "", []
            for l in body:
                if l == "":
                    text += " ".join(para) + "\n"; para = []
                else:
                    para.append(l.strip())
            text += " ".join(para)
        return text if chomp == "-" else text + "\n"

    def _value(self, rest, indent):
        """The value after `key:` or `- `, consuming continuation lines."""
        rest = _strip_comment(rest)
        if rest[:1] in ("|", ">"):
            return self._block_scalar(rest, indent)
        if rest == "":
            return self.block(indent + 1)
        # A flow collection may continue over several lines.
        if rest[0] in "[{":
            while rest.count("[") + rest.count("{") > rest.count("]") + rest.count("}") \
                    and self.i < len(self.lines):
                rest += " " + _strip_comment(self.lines[self.i].strip())
                self.i += 1
            return _scalar(rest)
        # A plain scalar may fold onto more-indented lines.
        while True:
            j = self._next()
            if j is None or _indent(self.lines[j]) <= indent:
                break
            nxt = self.lines[j].strip()
            if nxt.startswith("- ") or _key_split(nxt):
                break
            rest += " " + _strip_comment(nxt)
            self.i = j + 1
        return _scalar(rest)

    def mapping(self, ind):
        out = {}
        while True:
            j = self._next()
            if j is None or _indent(self.lines[j]) != ind or self.lines[j].lstrip().startswith("- "):
                return out
            kv = _key_split(self.lines[j])
            if kv is None:
                raise ValueError(f"line {j + 1}: expected 'key: value': {self.lines[j].strip()!r}")
            self.i = j + 1
            out[kv[0]] = self._value(kv[1], ind)

    def sequence(self, ind):
        out = []
        while True:
            j = self._next()
            if j is None or _indent(self.lines[j]) != ind:
                return out
            line = self.lines[j]
            if not (line.lstrip().startswith("- ") or line.strip() == "-"):
                return out
            content = line.lstrip()[1:].lstrip()
            col = len(line) - len(line.lstrip()[1:].lstrip())
            self.i = j + 1
            if content and _key_split(content) and not content.startswith(("'", '"', "[", "{")):
                # `- key: value` starts a mapping whose keys sit at column `col`.
                self.lines[j] = " " * col + content
                self.i = j
                out.append(self.mapping(col))
            else:
                out.append(self._value(content, ind))


def parse_workflow(text):
    data = _Parser(text).block(0)
    if not isinstance(data, dict) or not isinstance(data.get("jobs"), dict):
        raise ValueError("not a workflow: no top-level `jobs:` mapping")
    return data


# ----------------------------------------------------------------------------
# Running it
# ----------------------------------------------------------------------------

SETUP_ACTIONS = re.compile(r"^(actions/(checkout|setup-[\w-]+|cache)|dtolnay/rust-toolchain"
                           r"|Swatinem/rust-cache|taiki-e/install-action)(@|$)")
_EXPR = re.compile(r"\$\{\{\s*(.*?)\s*\}\}")


def matrix_legs(job):
    m = (job.get("strategy") or {}).get("matrix") or {}
    if not isinstance(m, dict):
        return [{}], ["matrix is an expression; ran once with no values"]
    notes = [f"matrix `{k}` not expanded" for k in m if k in ("include", "exclude")]
    axes = {k: (v if isinstance(v, list) else [v]) for k, v in m.items()
            if k not in ("include", "exclude")}
    if not axes:
        return [{}], notes
    keys = list(axes)
    return [dict(zip(keys, combo)) for combo in itertools.product(*(axes[k] for k in keys))], notes


def substitute(text, ctx, unresolved):
    def repl(m):
        expr = m.group(1)
        mm = re.fullmatch(r"matrix\.([\w-]+)", expr)
        if mm and mm.group(1) in ctx["matrix"]:
            return str(ctx["matrix"][mm.group(1)])
        mm = re.fullmatch(r"strategy\.(job-total|job-index)", expr)
        if mm:
            return str(ctx["strategy"][mm.group(1)])
        mm = re.fullmatch(r"steps\.([\w-]+)\.outputs\.([\w-]+)", expr)
        if mm and mm.group(2) in ctx["steps"].get(mm.group(1), {}):
            return ctx["steps"][mm.group(1)][mm.group(2)]
        if mm and ctx.get("listing"):
            return m.group(0)   # known only once the step has run
        unresolved.add(expr)
        return ""
    return _EXPR.sub(repl, str(text))


def _git(repo, *args):
    try:
        return subprocess.run(["git", "-C", repo] + list(args), capture_output=True,
                              text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return ""


def plan(workflow, only=None):
    """[(job_id, leg_index, legs, matrix, job)] in workflow order."""
    out = []
    for job_id, job in workflow["jobs"].items():
        if only and job_id not in only:
            continue
        legs, _notes = matrix_legs(job)
        for idx, combo in enumerate(legs):
            out.append((job_id, idx, len(legs), combo, job))
    return out


def run_workflow(path, repo, only=None, timeout=None, listing=False, log=sys.stdout):
    wf = parse_workflow(open(path, encoding="utf-8").read())
    wd_default = ((wf.get("defaults") or {}).get("run") or {}).get("working-directory") or "."
    results = []
    for job_id, idx, total, combo, job in plan(wf, only):
        label = job_id + (" [" + ", ".join(f"{k}={v}" for k, v in combo.items()) + "]" if combo else "")
        jwd = ((job.get("defaults") or {}).get("run") or {}).get("working-directory") or wd_default
        ctx = {"matrix": combo, "strategy": {"job-total": total, "job-index": idx}, "steps": {},
               "listing": listing}
        res = {"job": label, "status": "PASS", "ran": 0, "setup_skipped": 0, "not_run": [],
               "unresolved": set(), "seconds": 0.0, "notes": matrix_legs(job)[1]}
        env_base = dict(os.environ)
        for scope in (wf.get("env") or {}, job.get("env") or {}):
            env_base.update({k: substitute(v, ctx, res["unresolved"]) for k, v in scope.items()})
        print(f"\n=== {label}", file=log)
        for n, step in enumerate(job.get("steps") or [], 1):
            name = step.get("name") or step.get("id") or (step.get("uses") or str(step.get("run", "")))
            name = " ".join(str(name).split())[:70]
            if "uses" in step:
                if SETUP_ACTIONS.match(str(step["uses"])):
                    res["setup_skipped"] += 1
                else:
                    res["not_run"].append(f"action {step['uses']}")
                    print(f"  NOT RUN (action): {step['uses']}", file=log)
                continue
            if "if" in step:
                res["not_run"].append(f"conditional step '{name}' (if: {step['if']})")
                print(f"  NOT RUN (if: {step['if']}): {name}", file=log)
                continue
            if "run" not in step:
                continue
            cmd = substitute(step["run"], ctx, res["unresolved"])
            wd = os.path.join(repo, step.get("working-directory") or jwd)
            if listing:
                print(f"  [{wd}] $ " + cmd.rstrip().replace("\n", "\n      "), file=log)
                continue
            env = dict(env_base)
            env.update({k: substitute(v, ctx, res["unresolved"])
                        for k, v in (step.get("env") or {}).items()})
            with tempfile.NamedTemporaryFile("w+", suffix=".out", delete=False) as out:
                env["GITHUB_OUTPUT"] = out.name
            env.setdefault("CI", "true")
            print(f"  -> {name}", file=log)
            t0 = time.monotonic()
            try:
                rc = subprocess.run(["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", cmd],
                                    cwd=wd, env=env, timeout=timeout).returncode
            except subprocess.TimeoutExpired:
                rc = 124
            except FileNotFoundError as e:
                print(f"     cannot run: {e}", file=log)
                rc = 127
            res["seconds"] += time.monotonic() - t0
            res["ran"] += 1
            if step.get("id"):
                outputs = {}
                for line in open(env["GITHUB_OUTPUT"], encoding="utf-8", errors="replace"):
                    k, sep, v = line.rstrip("\n").partition("=")
                    if sep:
                        outputs[k] = v
                ctx["steps"][step["id"]] = outputs
            os.unlink(env["GITHUB_OUTPUT"])
            if rc != 0 and not step.get("continue-on-error"):
                res["status"] = f"FAIL (step {n} '{name}' exited {rc})"
                break
        if listing:
            res["status"] = "LISTED"
        res["unresolved"] = sorted(res["unresolved"])
        results.append(res)
    return results


def summary(paths, results, repo, only, listing):
    head = _git(repo, "rev-parse", "HEAD") or "unknown (not a git checkout)"
    dirty = bool(_git(repo, "status", "--porcelain", "--untracked-files=no"))
    lines = [f"ci-local {'plan' if listing else 'run'}: {', '.join(paths)}",
             f"  at {head}{' + UNCOMMITTED CHANGES' if dirty else ''}"
             f", {time.strftime('%Y-%m-%d %H:%M:%SZ', time.gmtime())}"]
    if only:
        lines.append(f"  SCOPED to job(s) {', '.join(only)}: an inner loop, NOT a substitute for CI")
    w = max((len(r["job"]) for r in results), default=10)
    for r in results:
        lines.append(f"  {r['job'].ljust(w)}  {r['status']}  ({r['ran']} step(s) run, "
                     f"{r['setup_skipped']} set-up action(s) assumed, {r['seconds']:.0f}s)")
        for x in r["not_run"]:
            lines.append(f"  {''.ljust(w)}    not run: {x}")
        if r["unresolved"]:
            lines.append(f"  {''.ljust(w)}    resolved to empty: {', '.join(r['unresolved'])}")
        for x in r["notes"]:
            lines.append(f"  {''.ljust(w)}    note: {x}")
    passed = sum(1 for r in results if r["status"] == "PASS")
    gaps = sum(len(r["not_run"]) for r in results)
    if not listing:
        lines.append(f"  {passed}/{len(results)} job leg(s) passed"
                     + (f"; {gaps} step(s) not run locally, listed above" if gaps else ""))
    return "\n".join(lines)


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("workflows", nargs="*")
    ap.add_argument("--repo")
    ap.add_argument("--job", action="append", default=[])
    ap.add_argument("--list", action="store_true", help="print the plan; run nothing")
    ap.add_argument("--timeout", type=float, help="per-step timeout in seconds")
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    if not args.workflows:
        ap.print_usage(sys.stderr)
        print("error: give at least one workflow file, or --self-test", file=sys.stderr)
        return 2
    results = []
    for wf in args.workflows:
        repo = args.repo or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(wf))))
        try:
            results += run_workflow(wf, repo, args.job or None, args.timeout, args.list,
                                    log=sys.stderr if args.json else sys.stdout)
        except (OSError, ValueError) as e:
            print(f"error: {wf}: {e}", file=sys.stderr)
            return 2
    repo = args.repo or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(args.workflows[0]))))
    if args.json:
        print(json.dumps(results, indent=2))
    else:
        print("\n" + summary(args.workflows, results, repo, args.job, args.list))
    return 0 if args.list or all(r["status"] == "PASS" for r in results) else 1


SELF_TEST_WF = """\
name: t   # a comment
on:
  push:
    paths: ['a/**', 'b.c',
            'liblua/**']
env:
  TOP: top
defaults:
  run:
    working-directory: sub
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: dtolnay/rust-toolchain@master
        with: { toolchain: "1.97.0", components: clippy }
      - id: declared
        run: |
          echo "version=1.88" >> "$GITHUB_OUTPUT"
          pwd > ../where.txt   # a shell comment stays in a block scalar
      - run: echo "+${{ steps.declared.outputs.version }} $TOP $STEPV" > ../out-build.txt
        env: { STEPV: stepv }
      - name: folded
        run: >
          echo folded
          one-line > ../folded.txt
      - uses: EmbarkStudios/cargo-deny-action@v2
  shard:
    strategy:
      fail-fast: false
      matrix:
        shard: [1, 2]
    steps:
      - run: echo "${{ matrix.shard }}/${{ strategy.job-total }} ${{ github.ref }}" > ../shard-${{ matrix.shard }}.txt
        working-directory: sub
  broken:
    steps:
      - run: "false"
      - run: echo unreachable > ../unreachable.txt
  after:
    steps:
      - if: failure()
        run: echo never
      - run: echo still-ran > ../after.txt
"""


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    # 1. The kit's own CI template parses into the jobs and commands it holds.
    here = os.path.dirname(os.path.abspath(__file__))
    tpl = parse_workflow(open(os.path.join(here, "porting-ci.template.yml"), encoding="utf-8").read())
    check("the kit's CI template parses to its seven jobs",
          list(tpl["jobs"]) == ["build-test", "unsafe-audit", "miri", "sanitizers",
                                "fuzz-smoke", "supply-chain", "differential"])
    runs = [s["run"] for s in tpl["jobs"]["build-test"]["steps"] if "run" in s]
    check("a folded `run: >` keeps every flag of the clippy gate",
          any("--all-features" in r and "-D clippy::missing_safety_doc" in r for r in runs))
    check("the fuzz job's matrix expands to one leg per shard",
          len(matrix_legs(tpl["jobs"]["fuzz-smoke"])[0]) == 4)
    diff_runs = [s["run"] for s in tpl["jobs"]["differential"]["steps"] if "run" in s]
    check("a `|` block keeps its lines",
          any("diff_run.py" in r and "\n" in r for r in diff_runs))
    check("the template wires the resource-bounds check (LESSONS #040)",
          any("scale_check.py" in r for r in diff_runs))

    # 2. A synthetic workflow, executed.
    wf = parse_workflow(SELF_TEST_WF)
    check("a flow list continued over lines parses",
          wf["on"]["push"]["paths"] == ["a/**", "b.c", "liblua/**"])
    with tempfile.TemporaryDirectory() as root:
        os.makedirs(os.path.join(root, ".github", "workflows"))
        os.makedirs(os.path.join(root, "sub"))
        path = os.path.join(root, ".github", "workflows", "t.yml")
        open(path, "w").write(SELF_TEST_WF)
        import io
        log = io.StringIO()
        res = {r["job"]: r for r in run_workflow(path, root, log=log)}
        read = lambda f: open(os.path.join(root, f)).read().strip() if os.path.exists(
            os.path.join(root, f)) else None
        check("defaults.run.working-directory is honoured",
              read("where.txt") == os.path.realpath(os.path.join(root, "sub")))
        check("step outputs, workflow env and step env reach later steps",
              read("out-build.txt") == "+1.88 top stepv")
        check("a folded block runs as one line", read("folded.txt") == "folded one-line")
        check("every matrix leg runs, with job-total resolved",
              read("shard-1.txt") == "1/2" and read("shard-2.txt") == "2/2")
        check("a GitHub-context expression is reported, not invented",
              "github.ref" in res["shard [shard=1]"]["unresolved"])
        check("set-up actions are assumed; any other action is listed as not run",
              res["build"]["setup_skipped"] == 2
              and res["build"]["not_run"] == ["action EmbarkStudios/cargo-deny-action@v2"])
        check("a failing step fails its job and stops it",
              res["broken"]["status"].startswith("FAIL") and read("unreachable.txt") is None)
        check("a failing job does not stop the jobs after it",
              res["after"]["status"] == "PASS" and read("after.txt") == "still-ran")
        check("a conditional step is listed, not run", len(res["after"]["not_run"]) == 1)
        s = summary([path], list(res.values()), root, [], False)
        check("the summary counts passing legs and names the gaps",
              "4/5 job leg(s) passed" in s and "not run: action EmbarkStudios" in s)
        check("a scoped run says it is not a substitute for CI",
              "NOT a substitute for CI" in summary([path], [], root, ["build"], False))
        import contextlib
        with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
            rc = main([path, "--repo", root, "--json"])
        check("main exits 1 when a job fails", rc == 1)

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
