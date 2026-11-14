#!/usr/bin/env python3
"""sabotage: measure the gates by breaking the port on purpose.

Each mutation replaces one unique span of one source file, runs the gate that
should notice, and restores the file. The run reports, per mutation:

  CAUGHT        the gate failed, and a test the mutation names failed by name
  WRONG-TEST    the gate failed, but not through a test the mutation names:
                the pin the ledger cites does not reach the fix (LESSONS #055)
  MISSED        the gate passed: a missing case, not a missing assertion
  INCONCLUSIVE  timeout, kill, or a mutation that does not compile. Never a
                catch (LESSONS #044): bound the test or fix the mutation, re-run

It exists because the protocol in REVIEW-GATE.md was re-typed as a throwaway
script at every step of nmap's IPv6-scans milestone, and each copy had to get
the same four things right (LESSONS #038, #044, #054):

  * restore from the saved bytes, never `git checkout` (which discards the work
    being checked), and bump the mtime (or cargo tests the stale, still-broken
    build);
  * bound every run: a mutation that makes a test hang is not a catch;
  * refuse to start over a leftover backup, so a killed run cannot leave a
    mutated file to be committed;
  * the replaced span must occur exactly once, so the mutation is the one meant.

Spec (JSON): a list of
  {"name": "...", "file": "path/relative/to/root", "old": "...", "new": "...",
   "cmd": ["cargo", "test", ...], "expect": ["substring of a test name", ...]}
`expect` is optional; without it any named failing test is a catch. Give it for
every mutation that reverts a ledgered fix: it is how a "Pinned by" line is
checked rather than trusted.

Usage:
  sabotage.py --root nmap-rs --spec sab.json [--timeout 900] [--only 3 7]
  sabotage.py --self-test
Exit status: 0 when every mutation run was CAUGHT, 1 otherwise, 2 on a refusal.
"""
import argparse
import json
import os
import re
import signal
import subprocess
import sys
import tempfile
import time

BACKUP = ".sabotage-orig"
FAIL = r"^test (\S+) \.\.\. FAILED"
NOCOMPILE = ("error[E", "could not compile", "SyntaxError")


def leftovers(root):
    found = []
    for d, dirs, files in os.walk(root):
        dirs[:] = [x for x in dirs if x not in (".git", "target", "node_modules")]
        found += [os.path.join(d, f) for f in files if f.endswith(BACKUP)]
    return found


def run_gate(cmd, cwd, timeout, env):
    """(returncode or None on timeout, output). Kills the whole process group."""
    p = subprocess.Popen(cmd, cwd=cwd, env=env, stdout=subprocess.PIPE,
                         stderr=subprocess.STDOUT, text=True, start_new_session=True)
    try:
        out, _ = p.communicate(timeout=timeout)
        return p.returncode, out
    except subprocess.TimeoutExpired:
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        out, _ = p.communicate()
        return None, out


def judge(rc, out, expect, fail_pattern):
    failed = re.findall(fail_pattern, out, flags=re.M)
    if rc is None:
        return "INCONCLUSIVE", failed, "timed out and was killed"
    if any(m in out for m in NOCOMPILE) and not failed:
        return "INCONCLUSIVE", failed, "the mutation does not compile"
    if rc == 0:
        return "MISSED", failed, "the gate passed"
    if not failed:
        return "INCONCLUSIVE", failed, "the gate failed with no named test"
    if expect and not any(e in f for e in expect for f in failed):
        return "WRONG-TEST", failed, "expected " + " or ".join(expect)
    return "CAUGHT", failed, ""


def mutate_and_run(root, m, timeout, fail_pattern, env):
    path = os.path.join(root, m["file"])
    with open(path, "rb") as f:
        saved = f.read()
    old, new = m["old"].encode(), m["new"].encode()
    n = saved.count(old)
    if n != 1:
        return "INCONCLUSIVE", [], f"`old` occurs {n} times in {m['file']}, not once"
    with open(path + BACKUP, "wb") as f:
        f.write(saved)
    try:
        with open(path, "wb") as f:
            f.write(saved.replace(old, new))
        rc, out = run_gate(m["cmd"], root, timeout, env)
        return judge(rc, out, m.get("expect"), fail_pattern)
    finally:
        with open(path, "wb") as f:
            f.write(saved)
        now = time.time()
        os.utime(path, (now, now))   # cargo must see the restore as a change
        os.remove(path + BACKUP)


def run(root, spec, timeout, only, fail_pattern, log=sys.stdout, env=None):
    stale = leftovers(root)
    if stale:
        print("refusing to start: a backup from a killed run exists. Each is the "
              "ORIGINAL of the file beside it; move it back, then re-run:", file=sys.stderr)
        for s in stale:
            print(f"  mv {s} {s[:-len(BACKUP)]}", file=sys.stderr)
        return 2
    tally = {}
    for i, m in enumerate(spec):
        if only and i not in only:
            continue
        verdict, failed, why = mutate_and_run(root, m, timeout, fail_pattern, env)
        tally[verdict] = tally.get(verdict, 0) + 1
        tail = f" [{', '.join(failed[:3])}]" if failed else ""
        print(f"{verdict:<12} {i} {m['name']}{tail}{' — ' + why if why else ''}",
              file=log, flush=True)
    total = sum(tally.values())
    rest = ", ".join(f"{v} {k}" for k, v in sorted(tally.items()) if k != "CAUGHT")
    print(f"caught {tally.get('CAUGHT', 0)} of {total}" + (f" ({rest})" if rest else ""),
          file=log, flush=True)
    return 0 if total and tally.get("CAUGHT", 0) == total else 1


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        if not cond:
            ok = False
            print(f"FAIL: {name}", file=sys.stderr)

    with tempfile.TemporaryDirectory() as root:
        src = os.path.join(root, "lib.txt")
        with open(src, "w") as f:
            f.write("answer = 42\nmode = fast\nmode2 = slow\n")
        old_time = time.time() - 3600
        os.utime(src, (old_time, old_time))
        # A gate that reads the file and reports as cargo's test runner does.
        gate = os.path.join(root, "gate.py")
        with open(gate, "w") as f:
            f.write(
                "import sys, time\n"
                "t = open('lib.txt').read()\n"
                "if 'hang' in t: time.sleep(60)\n"
                "if 'broken' in t: print('error[E0308]: mismatched'); sys.exit(101)\n"
                "if 'crash' in t: sys.exit(3)\n"
                "bad = False\n"
                "if 'answer = 42' not in t: print('test the_answer ... FAILED'); bad = True\n"
                "if 'mode = fast' not in t: print('test the_mode ... FAILED'); bad = True\n"
                "sys.exit(1 if bad else 0)\n")
        cmd = [sys.executable, "gate.py"]
        spec = [
            {"name": "caught", "file": "lib.txt", "old": "42", "new": "41", "cmd": cmd,
             "expect": ["the_answer"]},
            {"name": "wrong pin", "file": "lib.txt", "old": "42", "new": "41", "cmd": cmd,
             "expect": ["the_mode"]},
            {"name": "missed", "file": "lib.txt", "old": "slow", "new": "slower", "cmd": cmd},
            {"name": "hang", "file": "lib.txt", "old": "slow", "new": "hang", "cmd": cmd},
            {"name": "no compile", "file": "lib.txt", "old": "slow", "new": "broken", "cmd": cmd},
            {"name": "crash", "file": "lib.txt", "old": "slow", "new": "crash", "cmd": cmd},
            {"name": "ambiguous", "file": "lib.txt", "old": "mode", "new": "x", "cmd": cmd},
            {"name": "any test", "file": "lib.txt", "old": "fast", "new": "f", "cmd": cmd},
        ]
        import io
        log = io.StringIO()
        rc = run(root, spec, 2, None, FAIL, log)
        lines = log.getvalue().splitlines()
        want = ["CAUGHT", "WRONG-TEST", "MISSED", "INCONCLUSIVE", "INCONCLUSIVE",
                "INCONCLUSIVE", "INCONCLUSIVE", "CAUGHT"]
        check("verdicts " + repr(lines), [l.split()[0] for l in lines[:8]] == want)
        check("a hang is not a catch", "timed out" in lines[3])
        check("summary counts", lines[-1].startswith("caught 2 of 8"))
        check("exit 1 unless all caught", rc == 1)
        check("bytes restored",
              open(src).read() == "answer = 42\nmode = fast\nmode2 = slow\n")
        check("mtime bumped", os.path.getmtime(src) > old_time + 1800)
        check("no backup left", not leftovers(root))
        check("all caught exits 0", run(root, spec[:1], 5, None, FAIL, io.StringIO()) == 0)
        check("--only", run(root, spec, 5, [0, 7], FAIL, io.StringIO()) == 0)
        open(src + BACKUP, "w").close()
        err, sys.stderr = sys.stderr, io.StringIO()
        try:
            check("refuses over a leftover", run(root, spec[:1], 5, None, FAIL, io.StringIO()) == 2)
        finally:
            sys.stderr = err
    print("self-test OK" if ok else "self-test FAILED")
    return 0 if ok else 1


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--root", default=".")
    ap.add_argument("--spec")
    ap.add_argument("--timeout", type=float, default=900,
                    help="seconds per mutation; past it the run is INCONCLUSIVE")
    ap.add_argument("--only", type=int, nargs="*")
    ap.add_argument("--fail-pattern", default=FAIL,
                    help="regex with one group naming a failed test (default: cargo's)")
    ap.add_argument("--self-test", action="store_true")
    a = ap.parse_args(argv)
    if a.self_test:
        return _self_test()
    if not a.spec:
        ap.error("--spec is required")
    with open(a.spec) as f:
        spec = json.load(f)
    return run(a.root, spec, a.timeout, a.only, a.fail_pattern)


if __name__ == "__main__":
    sys.exit(main())
