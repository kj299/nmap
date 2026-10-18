#!/usr/bin/env python3
"""The M6.5 `openssl` oracle (docs/M6.5-ANALYSIS.md §11 row a): what
regen_m65.sh runs. The corpus is m65_cases.txt (oracle/gen_m65_cases.py, over
m65_algs.txt and m65_certs.txt); oracle/m65_core.lua runs it under

  - nmap 7.94, the installed binary: the ORACLE, through oracle/m65_probe.nse
    with --datadir set to this tree. Its output is the golden;
  - this tree's C, oracle/lua-openssl (build_openssl_oracle.sh): the SPEC
    (D1). Where the two differ, the difference must belong to a family §2
    names, and the membership of each family is pinned in m65_drift.txt.

    gen_m65.py golden            run 7.94 twice: m65_golden.txt (refuses if an
                                 untagged row differs between the runs)
    gen_m65.py drift             run the tree's C: m65_drift.txt (refuses a
                                 difference no family explains), and the tree's
                                 answer on each drift row, m65_drift_tree.txt,
                                 which the port is held to there (D1 (c))
    gen_m65.py screen            run the sanitizer build over every case:
                                 m65_screen.txt (refuses any report)
    gen_m65.py census            rows per exposed function: m65_census.txt
    gen_m65.py --check           CI, no nmap: the cases are current, the
                                 golden, drift and census files match them,
                                 the screen record matches every input
    gen_m65.py --check-794       CI, differential job: the header matches, then
                                 7.94 agrees with the golden on every row
    gen_m65.py --check-tree      local: the tree's C differs from the golden in
                                 exactly the pinned rows, each for its family,
                                 and gives the answers m65_drift_tree.txt holds

A row whose answer is random is tagged `nondet:` in the cases; it is compared
on its status and the shape of its values (lengths, types, a bignum's sign
and bit count), never its bytes (`shape`).

A row where the C is undefined is tagged `ub:` (ORACLE-CHECKS 5c). 7.94 never
runs it, and the golden records status `ub`. For `ub:iv-length-uaf` the
values are what this tree's C says with the one named repair
build_openssl_oracle.sh makes (the message the C means), and `golden` checks
that the repaired C raises "Length of iv" on exactly those rows, so the tag
can neither miss a row that reaches the flaw nor claim one that does not.
For any other `ub:` the values are `-`: no golden, the Rust side covers it.
"""

import hashlib
import os
import re
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
M6 = os.path.dirname(HERE)
TREE = os.path.abspath(os.path.join(HERE, "..", "..", "..", "..", ".."))
CASES = os.path.join(M6, "m65_cases.txt")
CERTS = os.path.join(M6, "m65_certs.txt")
ALGS = os.path.join(M6, "m65_algs.txt")
GOLDEN = os.path.join(M6, "m65_golden.txt")
DRIFT = os.path.join(M6, "m65_drift.txt")
DRIFT_TREE = os.path.join(M6, "m65_drift_tree.txt")
SCREEN = os.path.join(M6, "m65_screen.txt")
CENSUS = os.path.join(M6, "m65_census.txt")
CORE = os.path.join(HERE, "m65_core.lua")
PROBE = os.path.join(HERE, "m65_probe.nse")
DRIVER = os.path.join(HERE, "m65_driver.lua")
ORACLE = os.path.join(HERE, "lua-openssl")
ORACLE_ASAN = os.path.join(HERE, "lua-openssl-asan")
ORACLE_SABOTAGE = os.path.join(HERE, "lua-openssl-sabotage")
NMAP = os.environ.get("NMAP", "nmap")

# The inputs whose content decides the screen's verdict (ORACLE-CHECKS §3).
SCREEN_INPUTS = ([CASES, CERTS, CORE, DRIVER, os.path.join(HERE, "build_openssl_oracle.sh"),
                  os.path.join(HERE, "openssl_oracle_shim.h"), os.path.join(HERE, "gen_m65.py")]
                 + [os.path.join(TREE, f) for f in ("nse_openssl.cc", "nse_ssl_cert.cc",
                                                     "nse_openssl.h", "nse_lua.h")])
SCREEN_FLAGS = "-O1 -g -fsanitize=address,undefined -fno-sanitize-recover=all -DLUA_USE_APICHECK"
# allocator_may_return_null: an impossible malloc returns NULL, as glibc's does
# (rand_bytes(-1) is malloc(SIZE_MAX), which the C checks: "Couldn't allocate
# memory."), instead of ASan aborting on a request that is defined behaviour.
ASAN_OPTIONS = "detect_leaks=0:abort_on_error=0:allocator_may_return_null=1"
UBSAN_OPTIONS = "print_stacktrace=1:halt_on_error=1"


def sha256(path):
    return hashlib.sha256(open(path, "rb").read()).hexdigest()


def read_cases(path=CASES):
    cases = []
    for line in open(path):
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split("\t")
        cases.append((f[0], f[1].split(","), f[2], f[3], f[4:]))
    return cases


def is_ub(tags):
    return any(t.startswith("ub:") for t in tags)


def safe_cases(d):
    """m65_cases.txt without its `ub:` rows: what 7.94 runs."""
    path = os.path.join(d, "safe")
    with open(path, "w") as fh:
        for line in open(CASES):
            f = line.split("\t")
            if line.startswith("#") or len(f) < 2 or not is_ub(f[1].split(",")):
                fh.write(line)
    return path


IV_LENGTH = re.compile(r'^e"Length of iv is \d+; should be \d+"$')


def check_ub(tree):
    """The repaired C raises "Length of iv" on exactly the rows tagged
    `ub:iv-length-uaf`."""
    bad = []
    for cid, tags, *_ in read_cases():
        st, vals, _ = tree[cid]
        raised = st == "err" and IV_LENGTH.match(vals) is not None
        if raised != ("ub:iv-length-uaf" in tags):
            bad.append("%s (%s %s)" % (cid, st, vals[:60]))
    if bad:
        raise SystemExit("the `ub:iv-length-uaf` tag and the rows that reach the flaw differ "
                         "(gen_m65_cases.py ub_iv): %s" % "; ".join(bad[:10]))


def read_results(path):
    rows = {}
    for line in open(path):
        if line.startswith("#") or not line.strip():
            continue
        f = line.rstrip("\n").split("\t")
        rows[f[0]] = (f[1], f[2] if len(f) > 2 else "", f[3] if len(f) > 3 else "")
    return rows


# ---- running -------------------------------------------------------------------


def run(kind, out, cases=CASES):
    """Run every case of `cases` under 7.94 (`794`), the tree's C (`tree`),
    its sanitizer build (`asan`) or a sabotaged build (`sabotage`), resuming
    after a case that kills the process, which is recorded as `crash` (or,
    under `asan`, as the sanitizer's report)."""
    ids = [c[0] for c in read_cases(cases)]
    if os.path.exists(out):
        os.remove(out)
    start, crashes = 1, []
    while start <= len(ids):
        if kind == "794":
            cmd = [NMAP, "-n", "--datadir", TREE, "--script", PROBE, "--script-args",
                   "core=%s,cases=%s,certs=%s,out=%s,start=%d" % (CORE, cases, CERTS, out, start)]
        else:
            binary = {"tree": ORACLE, "asan": ORACLE_ASAN, "sabotage": ORACLE_SABOTAGE}[kind]
            cmd = [binary, DRIVER, CORE, cases, CERTS, out, str(start)]
        env = dict(os.environ, ASAN_OPTIONS=ASAN_OPTIONS, UBSAN_OPTIONS=UBSAN_OPTIONS)
        r = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE, env=env,
                           timeout=7200, cwd=tempfile.gettempdir())
        done = sum(1 for _ in open(out)) if os.path.exists(out) else 0
        if r.returncode == 0 and done == len(ids):
            break
        if done >= len(ids):
            raise SystemExit("%s: exited %d after every case: %s" % (kind, r.returncode, r.stderr[-400:]))
        report = r.stderr.decode("latin-1")
        sig = re.search(r"(ERROR: AddressSanitizer: [\w-]+|runtime error: [^\n]*)", report)
        why = sig.group(1) if sig else "signal=%d" % -r.returncode
        crashes.append((ids[done], why, report[-3000:]))
        with open(out, "a") as fh:
            fh.write("%s\tcrash\t%s\n" % (ids[done], why.replace("\t", " ")))
        start = done + 2
    return crashes


# ---- the header ------------------------------------------------------------------


def header():
    def out(cmd):
        try:
            return subprocess.run(cmd, capture_output=True, text=True).stdout.strip().splitlines()[0]
        except (OSError, IndexError):
            return "(unavailable)"
    legacy = subprocess.run(["openssl", "list", "-providers", "-provider", "legacy"],
                            capture_output=True).returncode == 0
    return [
        "nmap: " + out([NMAP, "--version"]),
        "openssl: " + out(["openssl", "version"]),
        "openssl-dir: " + out(["openssl", "version", "-d"]),
        "OPENSSL_CONF: " + os.environ.get("OPENSSL_CONF", "(unset)"),
        "legacy-provider: " + ("loads" if legacy else "absent"),
        "cases: " + sha256(CASES),
        "certs: " + sha256(CERTS),
    ]


def read_header(path):
    return [l[3:].rstrip("\n") for l in open(path) if l.startswith("#: ")]


# ---- nondeterminism ---------------------------------------------------------------


def shape(values):
    """What a random answer is compared on: each value's type and length; a
    bignum's sign (its size is random too: BN_rand's top bit may be 0, and
    the rlen rows check the bound)."""
    out = []
    # A bignum's MPI is a quoted string and may hold `>` or `|`: parse it.
    for v in re.findall(r'bn<-?[0-9A-F]+\|-?\d+\|(?:"(?:[^"\\]|\\x..)*"|#\d+:[0-9a-f]+)\|\d+\|\d+>'
                        r'|"(?:[^"\\]|\\x..)*"|#\d+:[0-9a-f]+|\S+', values):
        if v.startswith('"'):
            out.append("s%d" % len(re.sub(r"\\x..", ".", v[1:-1])))
        elif v.startswith("#"):
            out.append("s" + v[1:].split(":")[0])
        elif v.startswith("bn<"):
            f = v[3:-1].split("|")
            out.append("bn" + ("-" if f[0].startswith("-") else "+"))
        else:
            out.append(v)
    return " ".join(out)


def golden():
    cases = read_cases()
    subprocess.run([os.path.join(HERE, "build_openssl_oracle.sh")], check=True)
    with tempfile.TemporaryDirectory() as d:
        t, a, b = os.path.join(d, "t"), os.path.join(d, "a"), os.path.join(d, "b")
        crash_t = run("tree", t)
        if crash_t:
            raise SystemExit("the tree's C died on %s: tag the rows `ub:` or find the flaw"
                             % ", ".join(c[0] for c in crash_t))
        tree = read_results(t)
        check_ub(tree)
        safe = safe_cases(d)
        crash_a = run("794", a, safe)
        crash_b = run("794", b, safe)
        ra, rb = read_results(a), read_results(b)
    if crash_a or crash_b:
        raise SystemExit("7.94 died on %s: tag the rows `ub:` (ORACLE-CHECKS 5c)"
                         % ", ".join(c[0] for c in crash_a + crash_b))
    bad = []
    for cid, tags, *_ in cases:
        if "ub:iv-length-uaf" in tags:
            ra[cid] = ("ub",) + tree[cid][1:]
        elif is_ub(tags):
            ra[cid] = ("ub", "-", "")
        elif ra[cid] != rb[cid] and not any(t.startswith("nondet:") for t in tags):
            bad.append(cid)
    if bad:
        raise SystemExit("%d untagged rows differ between two 7.94 runs (tag them nondet: in the "
                         "generator): %s" % (len(bad), " ".join(bad[:30])))
    with open(GOLDEN, "w") as fh:
        fh.write("# M6.5 openssl golden: nmap 7.94 over m65_cases.txt (oracle/gen_m65.py golden).\n"
                 "# ID<TAB>STATUS<TAB>VALUES<TAB>q=N; rows tagged nondet: are compared by shape.\n"
                 "# STATUS `ub`: the C is undefined there (the case's ub: tag); the values\n"
                 "# are the repaired C's, or `-` for none.\n")
        for h in header():
            fh.write("#: " + h + "\n")
        for cid, *_ in cases:
            st, vals, q = ra[cid]
            fh.write("%s\t%s\t%s\t%s\n" % (cid, st, vals, q) if q else "%s\t%s\t%s\n" % (cid, st, vals))
    print("golden: %d rows, %d of them ub" % (len(cases), sum(1 for c in cases if is_ub(c[1]))),
          file=sys.stderr)


ALIAS = re.compile(r"'openssl\.bignum_(?:pseudo_)?rand'")


def compare(got, want, tags):
    if want[0] == "ub":
        return want[1] == "-" or (got[0] == "err" and got[1:] == want[1:])
    if "nondet:alias-name" in tags:
        got = (got[0], ALIAS.sub("'openssl.bignum_rand'", got[1])) + got[2:]
        want = (want[0], ALIAS.sub("'openssl.bignum_rand'", want[1])) + want[2:]
    if any(t.startswith("nondet:") and t != "nondet:alias-name" for t in tags):
        return got[0] == want[0] and shape(got[1]) == shape(want[1])
    return got == want


def check_794():
    want_h, have_h = read_header(GOLDEN), header()
    if want_h != have_h:
        for w, h in zip(want_h, have_h):
            if w != h:
                print("header: golden %r, this machine %r" % (w, h))
        raise SystemExit("the environment differs from the golden's header (§2): refusing to compare")
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "o")
        run("794", out, safe_cases(d))
        got = read_results(out)
    want = read_results(GOLDEN)
    bad = [cid for cid, tags, *_ in read_cases()
           if not is_ub(tags) and not compare(got[cid], want[cid], tags)]
    for cid in bad[:20]:
        print("%s\n  golden %s\n  7.94   %s" % (cid, want[cid], got[cid]))
    if bad:
        raise SystemExit("%d rows differ from the golden" % len(bad))
    print("7.94 agrees with the golden on all %d rows it runs" % len(got))


# ---- drift between 7.94 and the tree's C (§2) ---------------------------------------

YEAR = re.compile(r'"year"=i(-?\d+)')
VALIDITY = re.compile(r'validity=(\{(?:[^{}]|\{(?:[^{}]|\{[^{}]*\})*\})*\}|"(?:[^"\\]|\\x..)*"|nil)')


def drift_family(case, gold, tree):
    """The §2 family that explains a difference between 7.94 (gold) and the
    tree's C (tree), or None."""
    cid, tags, op, sub, args = case
    if op == "meta" and sub == "state":
        return "state"  # openssl.nse_openssl_state: absent in 7.94
    if op in ("call", "rt") and sub in ("encrypt", "decrypt") or op == "rt":
        if "ivnul" in tags:
            return "ivnul"  # an IV whose first byte is NUL: no IV to 7.94
    if op == "cert":
        # validity.*.year is year - 1900 in the tree (nse_ssl_cert.cc:307-309,369).
        fixed = YEAR.sub(lambda m: '"year"=i%d' % (int(m.group(1)) + 1900), tree[1])
        if (tree[0], fixed, tree[2]) == gold:
            return "year"
        # The ASN.1 time strings: 7.94's own parser against ASN1_TIME_to_tm.
        if VALIDITY.sub("validity=_", tree[1]) == VALIDITY.sub("validity=_", gold[1]) \
                and tree[0] == gold[0] and tree[2] == gold[2]:
            return "asn1time"
    return None


def drift_rows(kind="tree"):
    cases = read_cases()
    with tempfile.TemporaryDirectory() as d:
        out = os.path.join(d, "t")
        run(kind, out)
        tree = read_results(out)
    gold = read_results(GOLDEN)
    rows, unexplained = [], []
    for case in cases:
        cid, tags = case[0], case[1]
        if compare(tree[cid], gold[cid], tags):
            continue
        fam = drift_family(case, gold[cid], tree[cid])
        (rows if fam else unexplained).append((cid, fam or "?"))
    return rows, unexplained, tree, gold


def drift():
    rows, unexplained, tree, gold = drift_rows()
    for cid, _ in unexplained[:20]:
        print("%s\n  7.94 %s\n  tree %s" % (cid, gold[cid], tree[cid]))
    if unexplained:
        raise SystemExit("%d differences between 7.94 and the tree's C belong to no §2 family"
                         % len(unexplained))
    counts = {}
    for _, fam in rows:
        counts[fam] = counts.get(fam, 0) + 1
    with open(DRIFT, "w") as fh:
        fh.write("# M6.5: where this tree's C differs from nmap 7.94 (oracle/gen_m65.py drift),\n"
                 "# each row with its §2 family. Pinned: --check-tree fails on any row added\n"
                 "# or gone. Families: %s\n" % ", ".join("%s %d" % kv for kv in sorted(counts.items())))
        for cid, fam in rows:
            fh.write("%s\t%s\n" % (cid, fam))
    with open(DRIFT_TREE, "w") as fh:
        fh.write(drift_tree_text(rows, tree))
    print("drift: %d rows: %s" % (len(rows), counts), file=sys.stderr)


def drift_tree_text(rows, tree):
    """m65_drift_tree.txt: the tree's C's answer on each drift row, which the
    port is held to there: the tree is the spec (D1 (c))."""
    out = ["# M6.5: this tree's C on each row of m65_drift.txt (oracle/gen_m65.py drift):",
           "# the answer the port is held to where 7.94 differs by a §2 family.",
           "# ID<TAB>STATUS<TAB>VALUES"]
    out += ["%s\t%s\t%s" % (cid, tree[cid][0], tree[cid][1]) for cid, _ in rows]
    return "\n".join(out) + "\n"


def check_tree():
    rows, unexplained, tree, _ = drift_rows()
    pinned = [tuple(l.rstrip("\n").split("\t")) for l in open(DRIFT) if not l.startswith("#")]
    if open(DRIFT_TREE).read() != drift_tree_text(rows, tree):
        raise SystemExit("m65_drift_tree.txt is not the tree's C's answers on the drift rows: "
                         "run `gen_m65.py drift`")
    if unexplained or rows != pinned:
        added = sorted(set(rows) - set(pinned))
        gone = sorted(set(pinned) - set(rows))
        raise SystemExit("drift membership changed: %d unexplained, %d added, %d gone: %s %s %s"
                         % (len(unexplained), len(added), len(gone), unexplained[:5], added[:5], gone[:5]))
    print("the tree's C differs from 7.94 in exactly the %d pinned rows" % len(rows))


# ---- the sanitizer screen (ORACLE-CHECKS §3) -----------------------------------------


def screen_record():
    lines = ["flags: " + SCREEN_FLAGS, "ASAN_OPTIONS: " + ASAN_OPTIONS,
             "UBSAN_OPTIONS: " + UBSAN_OPTIONS]
    for p in SCREEN_INPUTS:
        lines.append("%s %s" % (sha256(p), os.path.relpath(p, TREE)))
    return lines


def screen():
    subprocess.run([os.path.join(HERE, "build_openssl_oracle.sh"), "--variant", "asan"], check=True)
    with tempfile.TemporaryDirectory() as d:
        crashes = run("asan", os.path.join(d, "s"))
    for cid, why, report in crashes:
        print("%s: %s\n%s" % (cid, why, report))
    if crashes:
        raise SystemExit("the sanitizer build reported on %d cases: no golden may record them "
                         "(ORACLE-CHECKS §3)" % len(crashes))
    with open(SCREEN, "w") as fh:
        fh.write("# M6.5 sanitizer screen (oracle/gen_m65.py screen): every case of m65_cases.txt\n"
                 "# ran under this tree's C built with the flags below, with no report.\n"
                 "# The record of what decided that; --check refuses any input that changed.\n")
        for line in screen_record():
            fh.write(line + "\n")
    print("screen: %d cases, no report" % len(read_cases()), file=sys.stderr)


# ---- reach census (ORACLE-CHECKS §2) --------------------------------------------------

EXPOSED = ["DES_string_to_key", "bignum_add", "bignum_bin2bn", "bignum_bn2bin", "bignum_bn2dec",
           "bignum_bn2hex", "bignum_bn2mpi", "bignum_clear_bit", "bignum_dec2bn", "bignum_div",
           "bignum_hex2bn", "bignum_is_bit_set", "bignum_is_prime", "bignum_is_safe_prime",
           "bignum_mod_exp", "bignum_num_bits", "bignum_num_bytes", "bignum_pseudo_rand",
           "bignum_rand", "bignum_set_bit", "decrypt", "digest", "encrypt", "hmac", "md4", "md5",
           "rand_bytes", "rand_pseudo_bytes", "ripemd160", "sha1", "supported_ciphers",
           "supported_digests", "parse_ssl_certificate"]
METHODS = ["num_bits", "num_bytes", "tobin", "tompi", "todec", "tohex", "is_prime",
           "is_safe_prime", "set_bit", "clear_bit", "is_bit_set", "__tostring"]


def census_counts():
    counts = {}
    for cid, tags, op, sub, args in read_cases():
        if op in ("call", "mut", "rlen", "cert"):
            counts[sub] = counts.get(sub, 0) + 1
        elif op == "rt":
            counts["encrypt"] = counts.get("encrypt", 0) + 1
            counts["decrypt"] = counts.get("decrypt", 0) + 1
        elif op == "meth":
            counts["method:" + sub] = counts.get("method:" + sub, 0) + 1
        elif op == "meta":
            name = {"digests": "supported_digests", "ciphers": "supported_ciphers"}.get(sub, "meta:" + sub)
            counts[name] = counts.get(name, 0) + 1
    # Every bignum result is rendered through these methods (m65_core.lua `bn_render`),
    # and every bnmeta row reads __tostring.
    bn_rows = sum(1 for l in open(GOLDEN) if "bn<" in l) if os.path.exists(GOLDEN) else 0
    for m in ("tohex", "todec", "tompi", "num_bits", "num_bytes"):
        counts["method:" + m] = counts.get("method:" + m, 0) + bn_rows
    counts["method:__tostring"] = counts.get("meta:bnmeta", 0)
    return counts


def census_text():
    counts = census_counts()
    lines = []
    zero = []
    for name in EXPOSED + ["method:" + m for m in METHODS]:
        n = counts.get(name, 0)
        lines.append("%s\t%d" % (name, n))
        if n == 0:
            zero.append(name)
    return lines, zero


def census():
    lines, zero = census_text()
    with open(CENSUS, "w") as fh:
        fh.write("# M6.5 reach census (oracle/gen_m65.py census, ORACLE-CHECKS §2): rows of\n"
                 "# m65_cases.txt reaching each function and method the module exposes.\n"
                 "# Zero means unverified.\n")
        for l in lines:
            fh.write(l + "\n")
    if zero:
        raise SystemExit("census: no row reaches %s" % ", ".join(zero))


# ---- --check: CI, no nmap --------------------------------------------------------------


def check():
    sys.path.insert(0, HERE)
    import gen_m65_cases as g
    rows, _ = g.generate(g.read_algs(ALGS), CERTS)
    with tempfile.TemporaryDirectory() as d:
        p = os.path.join(d, "c")
        g.write(rows, p)
        if open(p).read() != open(CASES).read():
            raise SystemExit("m65_cases.txt is not what gen_m65_cases.py writes: regenerate")
    hdr = read_header(GOLDEN)
    for want in ("cases: " + sha256(CASES), "certs: " + sha256(CERTS)):
        if want not in hdr:
            raise SystemExit("m65_golden.txt was made from other cases or certs: regenerate")
    ids = [c[0] for c in read_cases()]
    gold = read_results(GOLDEN)
    if list(gold) != ids:
        raise SystemExit("m65_golden.txt's rows are not m65_cases.txt's")
    for cid, tags, *_ in read_cases():
        if (gold[cid][0] == "ub") != is_ub(tags):
            raise SystemExit("%s: status %s in the golden, tags %s in the cases"
                             % (cid, gold[cid][0], ",".join(tags)))
    rec = [l.rstrip("\n") for l in open(SCREEN) if not l.startswith("#")]
    if rec != screen_record():
        raise SystemExit("the screen record does not match its inputs (cases, C sources, flags): "
                         "re-run `gen_m65.py screen` (ORACLE-CHECKS §3)")
    lines, zero = census_text()
    if [l.rstrip("\n") for l in open(CENSUS) if not l.startswith("#")] != lines or zero:
        raise SystemExit("m65_census.txt is stale, or a function has no row")
    for cid, fam in (l.rstrip("\n").split("\t") for l in open(DRIFT) if not l.startswith("#")):
        if cid not in set(ids):
            raise SystemExit("m65_drift.txt names %s, which is not a case" % cid)
    print("m65: cases current, golden/drift/census consistent, screen record matches")


def main():
    mode = sys.argv[1] if len(sys.argv) > 1 else ""
    {"golden": golden, "drift": drift, "screen": screen, "census": census, "--check": check,
     "--check-794": check_794, "--check-tree": check_tree}.get(mode, lambda: sys.exit(__doc__))()


if __name__ == "__main__":
    main()
