#!/usr/bin/env python3
"""Scaling check — does the port's cost grow the way it was declared to grow?

Run a command at sizes n, 2n, 4n, ... and measure wall-clock time and peak
resident memory (per run, children included). Fit the growth exponent of each
(the slope of log cost against log n), and fail when it exceeds the bound the
port declared, or the C oracle's own exponent, by more than a tolerance.

Why this exists (LESSONS #040, nmap M6.6). Every gate was green at every step
of M6.6, and the step reviews still found nine resource defects, among them the
milestone's only High: `json.parse` of a 1.8 MB network body took 270 s in the
port against 0.17 s in C (1,600x), and a `/string` capture re-copied its format
on every step (a 2 MB format: 140 s against 0.033 s). The port was pre-emptible
-- it returned `Pending` on schedule -- and the plan had gated exactly that.
"Can yield" is not "bounded". The per-slice step counter could not see the cost
either, because a meter counts only what it is instrumented to count: one VM
step scanned a whole run of bytes, so a quadratic pattern read as a flat 6
steps per byte while CPU time grew 30x. Wall clock and RSS are the meters
nothing can forget to instrument. See RESOURCE-BOUNDS.md for the procedure.

Placeholders in a command template:
  {n}       the size of this run
  {input}   a temp file written by --gen for this size (generation is untimed)

Usage:
  scale_check.py --cmd 'TEMPLATE' (--sizes A,B,C | --n N [--steps K])
                 [--gen 'TEMPLATE'] [--repeat R] [--floor-size F]
                 [--time-exp E] [--mem-exp E] [--tolerance T]
                 [--oracle-cmd 'TEMPLATE'] [--max-time-ratio X] [--max-mem-ratio X]
                 [--max-rss-mb M] [--timeout S] [--json]
  scale_check.py --self-test

  --n N --steps K     sizes N, 2N, ... 2^(K-1)N (default K=3: n, 2n, 4n)
  --repeat R          run each size R times; keep the fastest time and the
                      smallest peak (the least-noise estimate of each)
  --floor-size F      measure size F once and subtract its time and RSS. Rarely
                      needed: for three or more geometric sizes the exponent is
                      fitted on successive differences, which cancels start-up
                      time and the start-up RSS high-water mark by itself
  --time-exp/--mem-exp  the declared bound (1 = linear); fail above E + T
  --oracle-cmd        run the C oracle at the same sizes; fail when the port's
                      exponent exceeds the oracle's by more than T
  --max-time-ratio/--max-mem-ratio  fail when port/oracle at the largest size
                      exceeds X (e.g. 10 for "within an order of magnitude")

Use a RELEASE build of the port, sizes large enough that the work dominates
start-up (the largest run should take well over 100 ms, and the smallest should
allocate well past the start-up peak RSS, which is a high-water mark), and
inputs shaped by the threat model's worst case, not its typical one. When the
per-step exponents disagree by more than 0.5 the output says so: add a size.

Exit: 0 within every bound; 1 a bound exceeded or a run failed; 2 usage error.
"""
from __future__ import annotations

import argparse
import json
import math
import os
import signal
import subprocess
import sys
import tempfile
import threading
import time

RSS_UNIT = 1 if sys.platform == "darwin" else 1024   # ru_maxrss: bytes on macOS, KiB on Linux


def measure(cmd, timeout=None):
    """Run one shell command. Return (wall_seconds, peak_rss_bytes, exit_code).
    The peak is this run's own (os.wait4), including any children it waited for;
    RUSAGE_CHILDREN would instead return the maximum over every earlier run."""
    start = time.perf_counter()
    p = subprocess.Popen(["/bin/sh", "-c", cmd], stdin=subprocess.DEVNULL,
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         start_new_session=True)
    killed = []

    def kill():
        killed.append(True)
        try:
            os.killpg(p.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass

    timer = threading.Timer(timeout, kill) if timeout else None
    if timer:
        timer.start()
    try:
        _pid, status, ru = os.wait4(p.pid, 0)
    finally:
        if timer:
            timer.cancel()
    wall = time.perf_counter() - start
    p.returncode = os.waitstatus_to_exitcode(status)
    rc = 124 if killed else p.returncode
    return wall, ru.ru_maxrss * RSS_UNIT, rc


def fit_exponent(sizes, values):
    """Least-squares slope of log(value) against log(size)."""
    pts = [(math.log(n), math.log(max(v, 1e-9))) for n, v in zip(sizes, values) if n > 0]
    if len(pts) < 2:
        return float("nan")
    mx = sum(x for x, _ in pts) / len(pts)
    my = sum(y for _, y in pts) / len(pts)
    den = sum((x - mx) ** 2 for x, _ in pts)
    return sum((x - mx) * (y - my) for x, y in pts) / den if den else float("nan")


def growth_exponent(sizes, values):
    """The exponent k of cost = a + b*n^k, with the constant a cancelled.

    For geometric sizes (n, rn, r^2 n, ...) the successive differences are
    b*n_i^k*(r^k - 1), proportional to n_i^k, so fitting them removes start-up
    time and the start-up RSS high-water mark without a floor run. A peak RSS
    is a high-water mark: an interpreter that peaks at 12 MiB while starting
    hides a 4 MiB allocation completely, which a floor subtraction cannot undo.
    Falls back to fitting the values themselves for two sizes, non-geometric
    sizes, or differences too noisy to be positive. Returns (k, method)."""
    if len(sizes) >= 3 and all(n > 0 for n in sizes):
        ratios = [b / a for a, b in zip(sizes, sizes[1:])]
        diffs = [b - a for a, b in zip(values, values[1:])]
        if max(ratios) - min(ratios) < 0.01 * ratios[0] and all(d > 0 for d in diffs):
            return fit_exponent(sizes[:-1], diffs), "differences"
    return fit_exponent(sizes, values), "values"


def step_exponents(sizes, values):
    """The exponent between each consecutive pair: where does growth bend?"""
    out = []
    for (n0, v0), (n1, v1) in zip(zip(sizes, values), zip(sizes[1:], values[1:])):
        if n0 > 0 and n1 > n0:
            out.append(math.log(max(v1, 1e-9) / max(v0, 1e-9)) / math.log(n1 / n0))
    return out


def run_series(template, sizes, gen=None, repeat=1, floor_size=None, timeout=None):
    """Measure TEMPLATE at each size. Returns a dict of per-size results."""
    with tempfile.TemporaryDirectory(prefix="scale_check-") as tmp:
        def fill(t, n):
            return t.replace("{n}", str(n)).replace("{input}", os.path.join(tmp, f"in-{n}"))

        def one(n):
            if gen:
                g = subprocess.run(["/bin/sh", "-c", fill(gen, n)], capture_output=True)
                if g.returncode != 0:
                    return {"n": n, "error": f"--gen exited {g.returncode}: "
                            + g.stderr.decode("utf-8", "replace")[-200:]}
            best_t, best_m, rc = None, None, 0
            for _ in range(max(1, repeat)):
                t, m, rc = measure(fill(template, n), timeout)
                if rc != 0:
                    return {"n": n, "error": "timed out" if rc == 124 else f"exited {rc}"}
                best_t = t if best_t is None else min(best_t, t)
                best_m = m if best_m is None else min(best_m, m)
            return {"n": n, "time": best_t, "rss": best_m}

        floor = one(floor_size) if floor_size is not None else None
        rows = []
        for n in sizes:
            rows.append(one(n))
            if "error" in rows[-1]:
                break   # a larger size will not do better, and a timeout costs the most
    errors = [r for r in rows + ([floor] if floor else []) if "error" in r]
    res = {"sizes": sizes, "rows": rows, "floor": floor, "errors": errors}
    if errors:
        return res
    ft = floor["time"] if floor else 0.0
    fm = floor["rss"] if floor else 0
    times = [max(r["time"] - ft, 1e-6) for r in rows]
    mems = [max(r["rss"] - fm, 1) for r in rows]
    (te, tm), (me, mm) = growth_exponent(sizes, times), growth_exponent(sizes, mems)
    res.update({
        "time_net": times, "rss_net": mems,
        "time_exp": te, "rss_exp": me, "fit": {"time": tm, "rss": mm},
        "time_steps": step_exponents(sizes, times), "rss_steps": step_exponents(sizes, mems),
    })
    return res


def judge(port, oracle=None, time_exp=None, mem_exp=None, tol=0.25,
          max_time_ratio=None, max_mem_ratio=None, max_rss_mb=None):
    """Return a list of failure strings (empty = within every bound)."""
    fails = []
    if port["errors"]:
        return [f"port n={e['n']}: {e['error']}" for e in port["errors"]]
    if time_exp is not None and port["time_exp"] > time_exp + tol:
        fails.append(f"time grows as n^{port['time_exp']:.2f}; declared n^{time_exp:g} (+{tol:g})")
    if mem_exp is not None and port["rss_exp"] > mem_exp + tol:
        fails.append(f"peak memory grows as n^{port['rss_exp']:.2f}; declared n^{mem_exp:g} (+{tol:g})")
    if max_rss_mb is not None:
        worst = max(r["rss"] for r in port["rows"])
        if worst > max_rss_mb * 2 ** 20:
            fails.append(f"peak RSS {worst / 2 ** 20:.1f} MiB exceeds the ceiling {max_rss_mb:g} MiB")
    if oracle is not None:
        if oracle["errors"]:
            return fails + [f"oracle n={e['n']}: {e['error']}" for e in oracle["errors"]]
        for key, label in (("time_exp", "time"), ("rss_exp", "peak memory")):
            if port[key] > oracle[key] + tol:
                fails.append(f"{label} grows as n^{port[key]:.2f}, the oracle as n^{oracle[key]:.2f} (+{tol:g})")
        tr = port["rows"][-1]["time"] / max(oracle["rows"][-1]["time"], 1e-9)
        mr = port["rows"][-1]["rss"] / max(oracle["rows"][-1]["rss"], 1)
        port["time_ratio_at_max"], port["rss_ratio_at_max"] = tr, mr
        if max_time_ratio is not None and tr > max_time_ratio:
            fails.append(f"port takes {tr:.1f}x the oracle's time at n={port['sizes'][-1]} (max {max_time_ratio:g}x)")
        if max_mem_ratio is not None and mr > max_mem_ratio:
            fails.append(f"port peaks at {mr:.1f}x the oracle's memory at n={port['sizes'][-1]} (max {max_mem_ratio:g}x)")
    return fails


def render(label, res):
    lines = [f"{label}:"]
    if res["errors"]:
        return "\n".join(lines + [f"  n={e['n']}: {e['error']}" for e in res["errors"]])
    lines.append(f"  {'n':>12}  {'wall s':>9}  {'peak MiB':>9}")
    for r in res["rows"]:
        lines.append(f"  {r['n']:>12}  {r['time']:>9.3f}  {r['rss'] / 2 ** 20:>9.1f}")
    if res["floor"]:
        f = res["floor"]
        lines.append(f"  floor n={f['n']}: {f['time']:.3f} s, {f['rss'] / 2 ** 20:.1f} MiB (subtracted)")
    steps = lambda xs: ", ".join(f"{x:.2f}" for x in xs)
    lines.append(f"  time   ~ n^{res['time_exp']:.2f}  (fit on {res['fit']['time']}; "
                 f"raw per step: {steps(res['time_steps'])})")
    lines.append(f"  memory ~ n^{res['rss_exp']:.2f}  (fit on {res['fit']['rss']}; "
                 f"raw per step: {steps(res['rss_steps'])})")
    for name, st in (("time", res["time_steps"]), ("memory", res["rss_steps"])):
        if len(st) >= 2 and max(st) - min(st) > 0.5:
            lines.append(f"  note: {name} growth bends between steps; the smallest size may "
                         "still be start-up dominated, or the cost changes regime. Add a size.")
    return "\n".join(lines)


def _sizes(args):
    if args.sizes:
        sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    elif args.n:
        sizes = [args.n * 2 ** k for k in range(args.steps)]
    else:
        return None
    return sizes if len(sizes) >= 2 and sizes == sorted(set(sizes)) else None


def main(argv=None):
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--cmd", help="command template for the port, with {n} and/or {input}")
    ap.add_argument("--oracle-cmd", help="the same for the C oracle")
    ap.add_argument("--gen", help="untimed template that writes {input} for size {n}")
    ap.add_argument("--sizes", help="comma-separated, increasing")
    ap.add_argument("--n", type=int, help="first size; then 2n, 4n, ...")
    ap.add_argument("--steps", type=int, default=3)
    ap.add_argument("--repeat", type=int, default=3)
    ap.add_argument("--floor-size", type=int)
    ap.add_argument("--time-exp", type=float)
    ap.add_argument("--mem-exp", type=float)
    ap.add_argument("--tolerance", type=float, default=0.25)
    ap.add_argument("--max-time-ratio", type=float)
    ap.add_argument("--max-mem-ratio", type=float)
    ap.add_argument("--max-rss-mb", type=float)
    ap.add_argument("--timeout", type=float, default=600)
    ap.add_argument("--json", action="store_true")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args(argv)
    if args.self_test:
        return _self_test()
    sizes = _sizes(args)
    if not args.cmd or not sizes:
        ap.print_usage(sys.stderr)
        print("error: --cmd and --sizes (two or more, increasing) or --n are required", file=sys.stderr)
        return 2
    kw = dict(gen=args.gen, repeat=args.repeat, floor_size=args.floor_size, timeout=args.timeout)
    port = run_series(args.cmd, sizes, **kw)
    oracle = run_series(args.oracle_cmd, sizes, **kw) if args.oracle_cmd else None
    fails = judge(port, oracle, args.time_exp, args.mem_exp, args.tolerance,
                  args.max_time_ratio, args.max_mem_ratio, args.max_rss_mb)
    unbounded = args.time_exp is None and args.mem_exp is None and oracle is None \
        and args.max_rss_mb is None
    if args.json:
        print(json.dumps({"port": port, "oracle": oracle, "failures": fails,
                          "measurement_only": unbounded}, indent=2, default=str))
    else:
        print(render("port", port))
        if oracle:
            print(render("oracle", oracle))
            if "time_ratio_at_max" in port:
                print(f"port/oracle at n={sizes[-1]}: time {port['time_ratio_at_max']:.1f}x, "
                      f"peak memory {port['rss_ratio_at_max']:.1f}x")
        for f in fails:
            print("FAIL: " + f)
        if unbounded:
            print("note: no bound declared (--time-exp/--mem-exp/--oracle-cmd/--max-rss-mb): "
                  "this was a measurement, not a gate")
        print("OK" if not fails else f"{len(fails)} bound(s) exceeded")
    return 1 if fails else 0


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    check("the fit recovers an exact exponent",
          abs(fit_exponent([1, 2, 4, 8], [3 * n ** 2 for n in (1, 2, 4, 8)]) - 2) < 1e-9)
    k, how = growth_exponent([1, 2, 4, 8], [50 + 3 * n ** 2 for n in (1, 2, 4, 8)])
    check("fitting differences cancels a constant start-up cost",
          how == "differences" and abs(k - 2) < 1e-9)
    check("the raw fit is biased by that constant (why differences are used)",
          fit_exponent([1, 2, 4, 8], [50 + 3 * n ** 2 for n in (1, 2, 4, 8)]) < 1.5)
    check("per-doubling exponents show where growth bends",
          [round(e, 6) for e in step_exponents([1, 2, 4], [1, 2, 8])] == [1.0, 2.0])

    py = sys.executable
    sizes = [1, 2, 4]
    # Wall time: sleeps are deterministic where CPU loops are not, so the fit is
    # tested rather than the machine. Floor at n=0 removes interpreter start-up.
    lin_t = run_series(py + ' -c "import time; time.sleep({n} * 0.05)"', sizes,
                       repeat=2, floor_size=0)
    quad_t = run_series(py + ' -c "import time; time.sleep({n} * {n} * 0.0125)"', sizes,
                        repeat=2, floor_size=0)
    check("linear wall time fits n^1", abs(lin_t["time_exp"] - 1) < 0.3)
    check("quadratic wall time fits n^2", abs(quad_t["time_exp"] - 2) < 0.3)
    check("a linear command passes a declared linear time bound",
          judge(lin_t, time_exp=1) == [])
    check("a quadratic command fails a declared linear time bound",
          len(judge(quad_t, time_exp=1)) == 1)
    check("a quadratic command passes a declared quadratic time bound",
          judge(quad_t, time_exp=2) == [])

    # Peak memory: `b'x' * N` writes every byte, so it is resident. No floor run:
    # the difference fit cancels the interpreter's own high-water mark.
    lin_m = run_series(py + ' -c "b = b\'x\' * ({n} * 32 * 2**20)"', sizes, repeat=1)
    quad_m = run_series(py + ' -c "b = b\'x\' * ({n} * {n} * 8 * 2**20)"', sizes, repeat=1)
    check("linear peak memory fits n^1", abs(lin_m["rss_exp"] - 1) < 0.3)
    check("quadratic peak memory fits n^2", abs(quad_m["rss_exp"] - 2) < 0.3)
    check("quadratic memory fails a declared linear memory bound",
          any("peak memory" in f for f in judge(quad_m, mem_exp=1)))
    check("an absolute RSS ceiling is enforced",
          any("ceiling" in f for f in judge(lin_m, max_rss_mb=64)))

    # Against an oracle: the port must not grow faster than C does.
    check("a quadratic port fails against a linear oracle",
          any("the oracle as" in f for f in judge(quad_t, oracle=lin_t)))
    check("a linear port passes against a linear oracle", judge(lin_t, oracle=lin_t) == [])
    check("the port/oracle ratio at the largest size is bounded",
          any("the oracle's time" in f for f in judge(quad_t, oracle=lin_t, max_time_ratio=0.5)))

    # {input} from an untimed generator, and a failing run is a failure.
    gen = run_series("wc -c < {input} >/dev/null", [100, 200],
                     gen=py + ' -c "open(\'{input}\', \'w\').write(\'a\' * {n})"', repeat=1)
    check("--gen writes {input} per size and the command reads it", not gen["errors"])
    bad = run_series(py + ' -c "import sys; sys.exit(3)"', [1, 2], repeat=1)
    check("a run that exits non-zero fails the check",
          bad["errors"] and judge(bad, time_exp=1) == ["port n=1: exited 3"])
    slow = run_series(py + ' -c "import time; time.sleep(5)"', [1, 2], repeat=1, timeout=0.3)
    check("a run past --timeout is killed and fails", judge(slow) == ["port n=1: timed out"])

    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
