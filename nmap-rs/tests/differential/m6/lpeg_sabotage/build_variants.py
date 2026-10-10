#!/usr/bin/env -S python3 -I -B
"""Build sabotaged lpeg.c variants (variants.py) into WORK/bin/lua_NAME.

    build_variants.py --work WORK [-j JOBS] [VARIANT ...]

VARIANT is a full name or its S-number (S00, S13, ...); the default is all 17.
Each variant is a patched copy of the tree's lpeg.c, written to WORK/src and
built by ../lpeg_search/build_patched_lua.sh, which runs the committed
oracle/build_lua_oracle.sh in a throw-away tree: the oracle's own recipe. The
tree's lpeg.c is only read. LOCAL ONLY.
"""
import sys

sys.dont_write_bytecode = True

import argparse  # noqa: E402
import concurrent.futures  # noqa: E402
import importlib.util  # noqa: E402
import os  # noqa: E402
import subprocess  # noqa: E402

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.realpath(os.path.join(HERE, "..", "..", "..", "..", ".."))
HELPER = os.path.join(HERE, "..", "lpeg_search", "build_patched_lua.sh")


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    mod = importlib.util.module_from_spec(spec)
    sys.modules[name] = mod
    spec.loader.exec_module(mod)
    return mod


V = load("lpeg_sabotage_variants", os.path.join(HERE, "variants.py"))


def inside_repo(path):
    p = os.path.realpath(path)
    return p == REPO or p.startswith(REPO + os.sep)


def main():
    ap = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    ap.add_argument("--work", required=True, help="work directory (never inside the repository)")
    ap.add_argument("-j", "--jobs", type=int, default=4)
    ap.add_argument("variants", nargs="*")
    a = ap.parse_args()
    work = os.path.realpath(a.work)
    if inside_repo(work):
        sys.exit("refusing a work directory inside the repository: %s" % work)
    names = V.select(a.variants)
    srcdir, bindir, logdir, tmpdir = (os.path.join(work, d) for d in ("src", "bin", "log", "tmp"))
    for d in (srcdir, bindir, logdir, tmpdir):
        os.makedirs(d, exist_ok=True)

    with open(os.path.join(REPO, "lpeg.c"), encoding="latin-1") as fh:
        src = fh.read()
    # every patch first, so a moved anchor fails before anything compiles
    paths = {}
    for name in names:
        p = os.path.join(srcdir, "lpeg_%s.c" % name)
        with open(p, "w", encoding="latin-1") as fh:
            fh.write(V.patched(src, name))
        paths[name] = p

    def build(name):
        out = os.path.join(bindir, "lua_" + name)
        log = os.path.join(logdir, "build_%s.log" % name)
        if os.path.exists(out):
            os.remove(out)
        with open(log, "w") as fh:
            rc = subprocess.run(["bash", HELPER, paths[name], out, tmpdir], stdout=fh, stderr=subprocess.STDOUT).returncode
        return name, rc, log

    failed = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=max(1, a.jobs)) as ex:
        for name, rc, log in ex.map(build, names):
            if rc == 0:
                print("built %s" % name, flush=True)
            else:
                failed.append(name)
                with open(log) as fh:
                    tail = fh.read()[-2000:]
                print("FAILED %s (rc %d), %s:\n%s" % (name, rc, log, tail), file=sys.stderr, flush=True)
    if failed:
        sys.exit("%d variant(s) failed to build: %s" % (len(failed), " ".join(failed)))


if __name__ == "__main__":
    main()
