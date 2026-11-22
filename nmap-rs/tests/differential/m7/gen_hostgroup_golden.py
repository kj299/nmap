#!/usr/bin/env python3
"""Host-group golden: the groups nmap forms, read from nmap itself.

M7 cutover gate, step a (docs/M7-CUTOVER-ANALYSIS.md §5.1). For each case this
runs nmap under -v and records, from its own output:

  * the size of every group it scans ("Scanning N hosts", "Scanning ADDR"), for
    the first scan type of the run;
  * the order it reports the hosts in.

Groups are scanned and reported one after another, so the two together give each
group's members. `core::hostgroup` is compared with these lines
(crates/core/tests/hostgroup_differential.rs).

Targets are tokens, so the golden holds no address of the machine that made it:
  lN    the N-th loopback address, 127.0.a.b (route: lo, source 127.0.0.1)
  own   this host's own non-loopback IPv4 address (route: lo, source itself)
A token may repeat: nmap scans a repeated address in a later group.

Every run passes -Pn -n, and every target is routed over the loopback, where
nmap sends no ARP or ND ping: so every target is up, which is the only case in
which the port, with no verdict on a host when it forms a group, can form
nmap's groups (`hostgroup-every-target-counts`). A run in which nmap pings is refused, since
its "Scanning N hosts" lines would be read as groups.

As root nmap routes a run's targets whenever RawScan() holds: a raw port scan,
and also -sT with -O or --traceroute, or without -Pn. Scan `T` is the one
unrouted kind here and `TO` (-sT -O) a routed connect scan.

Needs root (raw scans) and an own non-loopback IPv4 address.

Usage: gen_hostgroup_golden.py [--nmap PATH | --port PATH] [--check [--fail-fast]]
                                [--only SUBSTR] [--timeout SECONDS] [GOLDEN]
  default: write GOLDEN (hostgroup_golden.txt beside this file)
  --check: generate, compare with GOLDEN, exit 1 on any difference
  --fail-fast: with --check, stop at the first case that differs
  --port: run nmap-rs instead, and read its groups from `-d`'s "host group k:
    n host(s)" lines (M7 cutover step b). Only the scan kinds it has are run
    (PORT_KINDS); the golden's other lines are not compared. With --check this
    is the end-to-end gate: the port's binary forms 7.94's groups.
  --timeout: per run of nmap (default 300). A run that does not finish is not a
    difference: --check goes on, and exits 3 if that is all that went wrong. A
    broken nmap can hang on a case (one that puts an address in a group twice
    waits out every probe of the copy), and a hang is not a catch (LESSONS #044).
"""
import argparse
import os
import re
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANS = {"T": ["-sT"], "S": ["-sS"], "A": ["-sA"], "U": ["-sU"], "SU": ["-sS", "-sU"],
         "US": ["-sU", "-sS"], "O": ["-sO"], "TO": ["-sT", "-O", "--max-os-tries", "1"]}
# The kinds nmap-rs has: one scan type per run, and no -sO.
PORT_KINDS = ("T", "S", "A", "U", "TO")
# What nmap calls the port scan each kind starts with. Group sizes are read from
# these phases only.
PORT_SCANS = ("Connect Scan", "SYN Stealth Scan", "ACK Scan", "UDP Scan", "IPProto Scan")


def own_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("192.0.2.1", 9))      # no packet is sent: this only picks a route
        addr = s.getsockname()[0]
    except OSError:
        addr = None
    finally:
        s.close()
    return None if addr is None or addr.startswith("127.") else addr


def loopback(n):
    """l1 is 127.0.0.1; the rest fill 127.0.x.y without .0 and .255 last bytes."""
    n -= 1
    return f"127.0.{n // 250}.{n % 250 + 1}"


def expand(tokens):
    """'l1-l70,own,l1x3' -> ['l1', ..., 'l70', 'own', 'l1', 'l1', 'l1']."""
    out = []
    for part in tokens.split(","):
        m = re.fullmatch(r"l(\d+)-l(\d+)", part)
        r = re.fullmatch(r"(\w+)x(\d+)", part)
        if m:
            out += [f"l{i}" for i in range(int(m[1]), int(m[2]) + 1)]
        elif r:
            out += [r[1]] * int(r[2])
        else:
            out.append(part)
    return out


def case(scan, ports, targets, timing=3, mn=None, mx=None):
    return {"scan": scan, "ports": ports, "T": timing, "min": mn, "max": mx, "targets": targets}


def matrix():
    c = []
    # The size rule, around each boundary (scan_engine.cc:1218). Connect scans: no
    # route, so no homogeneity rule, and the cheapest way to scan many hosts.
    c += [case("T", 1, "l1-l1030"), case("T", 2, "l1-l520"), case("T", 15, "l1-l70"),
          case("T", 16, "l1-l70"), case("T", 17, "l1-l70"), case("T", 20, "l1-l70"),
          case("T", 64, "l1-l66"), case("T", 1000, "l1-l66")]
    # Above 1,000 ports the first group is 4 (8 at -T4, none at -T5), and the second
    # is shortened by it.
    c += [case("T", 1001, "l1-l69", t) for t in (3, 4, 5)]
    # Only the second group is shortened: the third is whole again.
    c += [case("T", 1001, "l1-l130")]
    # -T0 to -T2 have the quick group too.
    c += [case("S", 1001, "l1-l9", t) for t in (0, 1, 2)]
    # A first group cut short of the quick size (a repeat ends its batch) shortens
    # nothing: the second is 64, not 60.
    c += [case("S", 1001, "l1-l3,l1x64,l4-l70")]
    # The rule reads the hosts of every group so far: a later group of four (a
    # batch ended by repeats) is followed by a whole one.
    c += [case("S", 1001, "l1-l68,l65x64,l69-l140")]
    # Neither TCP nor UDP: 16.
    c += [case("O", 3, "l1-l20")]
    c += [case("T", 1001, "l1-l3"), case("T", 1001, "l1-l4"), case("T", 1001, "l1-l5")]
    c += [case("T", 2000, "l1-l12")]
    # Raw TCP scans size like connect scans; UDP is 128, and wins when both run,
    # whichever is named first.
    c += [case("S", 1, "l1-l1030"), case("S", 20, "l1-l70"), case("A", 20, "l1-l70"),
          case("S", 1001, "l1-l9"), case("U", 1, "l1-l130"), case("U", 20, "l1-l130"),
          case("SU", 20, "l1-l130"), case("US", 20, "l1-l130"), case("SU", 1001, "l1-l9")]
    # The operator's bounds, each alone, together, and absent (above).
    c += [case("T", 1, "l1-l5", mx=2), case("T", 1, "l1-l5", mx=1),
          case("T", 20, "l1-l130", mn=100), case("T", 20, "l1-l130", mn=100, mx=100),
          case("T", 20, "l1-l70", mn=64), case("T", 20, "l1-l70", mn=65),
          case("T", 1001, "l1-l12", mx=3), case("T", 1001, "l1-l12", mn=6),
          case("T", 1001, "l1-l12", mn=5, mx=7), case("U", 1, "l1-l130", mx=100),
          case("S", 20, "l1-l70", mx=10), case("T", 1, "l1-l1030", mx=100000)]
    # Homogeneity, for raw scans: a different source, or a repeated address, waits
    # for a later group, and later targets that match overtake it (targets.cc:276,
    # :533). --min-hostgroup does not override it. A connect scan under -Pn has no
    # route, so neither applies.
    c += [case("S", 1, "l1,own,l2"), case("S", 1, "l1,own,l2", mn=3),
          case("S", 1, "own,l1,l2,own"), case("S", 1, "l1,l1,l2"), case("S", 1, "l1,l2,l1,l1,l3"),
          case("S", 1, "l1,l1,l2", mx=1), case("S", 1, "l1,own,l2,own,l3", mx=2),
          case("T", 1, "l1,own,l2"), case("T", 1, "l1,l1,l2"), case("U", 1, "l1,own,l2,l1"),
          case("A", 1, "own,own,l1")]
    # The repeat test reads every address of the group, not its first.
    c += [case("S", 1, "l1,l2,l2,l3"), case("S", 1, "l1,l2,l3,l2,l3,l4")]
    # A connect scan with -O is routed (RawScan() holds), so both rules apply.
    c += [case("TO", 1, "l1,own,l2,l1")]
    # The defer buffer holds 64 (targets.h:75): when it fills, the batch ends early.
    c += [case("S", 1, "l1,own,l1x63,l2,l3"), case("S", 1, "l1,own,l1x62,l2,l3"),
          case("S", 1, "l1,ownx64,l2"), case("S", 1, "l1,ownx65,l2")]
    # The batch is 4,096 (nmap.h), or --min-hostgroup when that is larger. A full
    # batch never looks at the next target, so `own` leads the second batch and l4097
    # waits behind it; in a larger batch `own` is deferred and l4097 overtakes it.
    c += [case("S", 1, "l1-l4096,own,l4097"), case("S", 1, "l1-l4096,own,l4097", mn=5000),
          case("S", 1, "l1-l4095,own,l4096")]
    # The batch is raised to exactly --min-hostgroup: `own` leads the next one.
    c += [case("S", 1, "l1-l5000,own,l5001", mn=5000)]
    return c


def name(c):
    return (f"scan={c['scan']} ports={c['ports']} T={c['T']} "
            f"min={c['min'] if c['min'] is not None else '-'} "
            f"max={c['max'] if c['max'] is not None else '-'} targets={c['targets']}")


def run(nmap, c, own, timeout, port=False):
    """(sizes, order), or None if nmap did not finish in `timeout` seconds."""
    tokens = expand(c["targets"])
    addr = {t: (own if t == "own" else loopback(int(t[1:]))) for t in set(tokens)}
    back = {a: t for t, a in addr.items()}
    cmd = [nmap] + SCANS[c["scan"]] + ["-Pn", "-n", "-v", f"-T{c['T']}", "-p", f"1-{c['ports']}"]
    if c["T"] < 3:
        # -T0 waits five minutes between probes. The delay is not what is measured.
        cmd += ["--scan-delay", "1ms", "--max-scan-delay", "1ms"]
    if c["min"] is not None:
        cmd += ["--min-hostgroup", str(c["min"])]
    if c["max"] is not None:
        cmd += ["--max-hostgroup", str(c["max"])]
    if port:
        cmd += ["-d"]
    cmd += [addr[t] for t in tokens]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return None
    out = r.stdout
    if port:
        if "falling back to a" in r.stderr or "lacks raw-scan support" in r.stderr:
            sys.exit(f"FAIL: {name(c)}: nmap-rs did not scan raw:\n{r.stderr[-800:]}")
        sizes = [int(m[1]) for m in re.finditer(r"\] host group \d+: (\d+) host", r.stderr)]
        order = [back[m[1]] for m in re.finditer(r"(?m)^Nmap scan report for (\S+)", out)]
        if sum(sizes) != len(tokens) or len(order) != len(tokens):
            sys.exit(f"FAIL: {name(c)}: {sum(sizes)} hosts in groups, {len(order)} reported, "
                     f"{len(tokens)} given\n{r.stderr[-1500:]}")
        return sizes, order
    sizes, order, first, current = [], [], None, None
    for line in out.splitlines():
        m = re.match(r"Initiating (.+) at ", line)
        if m:
            current = m[1]
            if "Ping" in current:
                sys.exit(f"FAIL: {name(c)}: nmap ran a {current}; a target is not routed "
                         "over the loopback, and its groups cannot be read this way")
            if first is None and current in PORT_SCANS:
                first = current
            continue
        if first is not None and current == first:
            m = re.match(r"Scanning (\d+) hosts \[", line)
            if m:
                sizes.append(int(m[1]))
            elif re.match(r"Scanning \S+ \[", line):
                sizes.append(1)
        m = re.match(r"Nmap scan report for (\S+)", line)
        if m:
            order.append(back[m[1]])
    if sum(sizes) != len(tokens) or len(order) != len(tokens):
        sys.exit(f"FAIL: {name(c)}: {sum(sizes)} hosts in groups, {len(order)} reported, "
                 f"{len(tokens)} given\n{out[-2000:]}")
    return sizes, order


def compress(order):
    """Runs of consecutive lN as lA-lB, repeats as TxN: the golden stays readable."""
    out, i = [], 0
    while i < len(order):
        t, j = order[i], i
        if t.startswith("l"):
            while j + 1 < len(order) and order[j + 1] == f"l{int(order[j][1:]) + 1}":
                j += 1
            if j > i:
                out.append(f"{t}-{order[j]}")
                i = j + 1
                continue
        while j + 1 < len(order) and order[j + 1] == t:
            j += 1
        out.append(t if j == i else f"{t}x{j - i + 1}")
        i = j + 1
    return ",".join(out)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("golden", nargs="?", default=os.path.join(HERE, "hostgroup_golden.txt"))
    ap.add_argument("--nmap", default="nmap")
    ap.add_argument("--check", action="store_true")
    ap.add_argument("--only")
    ap.add_argument("--fail-fast", action="store_true")
    ap.add_argument("--timeout", type=int, default=300)
    ap.add_argument("--port", metavar="PATH")
    a = ap.parse_args()
    if a.port and not a.check:
        sys.exit("FAIL: --port only checks; the golden is written from nmap itself")
    if os.geteuid() != 0:
        sys.exit("FAIL: needs root, for the raw scans")
    own = own_address()
    if own is None:
        sys.exit("FAIL: needs a non-loopback IPv4 address of this host's own")
    cases = [c for c in matrix() if not a.only or a.only in name(c)]
    if a.port:
        cases = [c for c in cases if c["scan"] in PORT_KINDS]
    if not cases:
        sys.exit(f"FAIL: no case matches --only {a.only!r}")
    want, golden = {}, []
    if a.check:
        names = {name(c) for c in cases} if a.port else None
        golden = [l for l in open(a.golden).read().splitlines()
                  if (not a.only or a.only in l.split(" | ")[0])
                  and (names is None or l.split(" | ")[0] in names)]
        want = {l.split(" | ")[0]: l for l in golden}
    lines, differs, unfinished = [], 0, []
    for c in cases:
        got = run(a.port or a.nmap, c, own, a.timeout, port=bool(a.port))
        if got is None:
            unfinished.append(name(c))
            print(f"DID NOT FINISH in {a.timeout}s: {name(c)}", flush=True)
            continue
        sizes, order = got
        lines.append(f"{name(c)} | groups={','.join(map(str, sizes))} | order={compress(order)}")
        print(lines[-1], file=sys.stderr, flush=True)
        if a.check and want.get(name(c)) != lines[-1]:
            differs += 1
            print(f"DIFFERS:\n  golden: {want.get(name(c), '(no such case)')}\n"
                  f"  now:    {lines[-1]}", flush=True)
            if a.fail_fast:
                break
    if a.check:
        # Case by case above, so that one difference can end a run early. The
        # golden is still compared as a file: a line for a case the matrix no
        # longer has, a second line for one it has, or another order, differ.
        # A case that did not finish has no line to compare; its golden lines are
        # left out, and every other line still has to be there, once, in order.
        hung = set(unfinished)
        rest = [l for l in golden if l.split(" | ")[0] not in hung]
        whole = not (a.fail_fast and differs)
        if whole and rest != lines and not differs:
            differs += 1
            print(f"DIFFERS: {a.golden} holds {len(rest)} line(s) for these "
                  f"{len(lines)} case(s), or holds them in another order")
        if differs:
            sys.exit(f"FAIL: {a.golden} differs in {differs} case(s)")
        if unfinished:
            print(f"INCONCLUSIVE: {len(unfinished)} case(s) did not finish; the rest match")
            sys.exit(3)
        print(f"hostgroup golden: {len(lines)} cases match {a.golden}")
    else:
        if unfinished:
            sys.exit(f"FAIL: {len(unfinished)} case(s) did not finish; nothing written")
        text = "".join(l + "\n" for l in lines)
        open(a.golden, "w").write(text)
        print(f"wrote {len(lines)} cases to {a.golden}")


if __name__ == "__main__":
    main()
