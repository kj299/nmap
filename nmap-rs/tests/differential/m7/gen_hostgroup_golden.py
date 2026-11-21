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

Every run passes -Pn -n: the port sends no host-discovery probes, so the groups
it forms are the ones nmap forms when every target is up. As root, -sT without
-Pn also splits by route (RawScan() holds for its pings); the port's connect
scan does not, which `privileged-connect-scan-no-implicit-verdicts` records.

Needs root (raw scans) and an own non-loopback IPv4 address.

Usage: gen_hostgroup_golden.py [--nmap PATH] [--check] [--only SUBSTR] [GOLDEN]
  default: write GOLDEN (hostgroup_golden.txt beside this file)
  --check: generate, compare with GOLDEN, exit 1 on any difference
"""
import argparse
import os
import re
import socket
import subprocess
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
SCANS = {"T": ["-sT"], "S": ["-sS"], "A": ["-sA"], "U": ["-sU"], "SU": ["-sS", "-sU"],
         "US": ["-sU", "-sS"]}


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
    # The defer buffer holds 64 (targets.h:75): when it fills, the batch ends early.
    c += [case("S", 1, "l1,own,l1x63,l2,l3"), case("S", 1, "l1,own,l1x62,l2,l3"),
          case("S", 1, "l1,ownx64,l2"), case("S", 1, "l1,ownx65,l2")]
    # The batch is 4,096 (nmap.h), or --min-hostgroup when that is larger. A full
    # batch never looks at the next target, so `own` leads the second batch and l4097
    # waits behind it; in a larger batch `own` is deferred and l4097 overtakes it.
    c += [case("S", 1, "l1-l4096,own,l4097"), case("S", 1, "l1-l4096,own,l4097", mn=5000),
          case("S", 1, "l1-l4095,own,l4096")]
    return c


def name(c):
    return (f"scan={c['scan']} ports={c['ports']} T={c['T']} "
            f"min={c['min'] if c['min'] is not None else '-'} "
            f"max={c['max'] if c['max'] is not None else '-'} targets={c['targets']}")


def run(nmap, c, own):
    tokens = expand(c["targets"])
    addr = {t: (own if t == "own" else loopback(int(t[1:]))) for t in set(tokens)}
    back = {a: t for t, a in addr.items()}
    cmd = [nmap] + SCANS[c["scan"]] + ["-Pn", "-n", "-v", f"-T{c['T']}", "-p", f"1-{c['ports']}"]
    if c["min"] is not None:
        cmd += ["--min-hostgroup", str(c["min"])]
    if c["max"] is not None:
        cmd += ["--max-hostgroup", str(c["max"])]
    cmd += [addr[t] for t in tokens]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=900).stdout
    sizes, order, first, current = [], [], None, None
    for line in out.splitlines():
        m = re.match(r"Initiating (.+) at ", line)
        if m:
            current = m[1]
            first = first or current
            continue
        if current == first:
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
    a = ap.parse_args()
    if os.geteuid() != 0:
        sys.exit("FAIL: needs root, for the raw scans")
    own = own_address()
    if own is None:
        sys.exit("FAIL: needs a non-loopback IPv4 address of this host's own")
    lines = []
    for c in matrix():
        if a.only and a.only not in name(c):
            continue
        sizes, order = run(a.nmap, c, own)
        lines.append(f"{name(c)} | groups={','.join(map(str, sizes))} | order={compress(order)}")
        print(lines[-1], file=sys.stderr, flush=True)
    text = "".join(l + "\n" for l in lines)
    if a.check:
        want = [l for l in open(a.golden).read().splitlines()
                if not a.only or a.only in l]
        if want != lines:
            for w, g in zip(want, lines):
                if w != g:
                    print(f"DIFFERS:\n  golden: {w}\n  now:    {g}")
            sys.exit(f"FAIL: {a.golden} differs ({len(want)} golden, {len(lines)} now)")
        print(f"hostgroup golden: {len(lines)} cases match {a.golden}")
    else:
        open(a.golden, "w").write(text)
        print(f"wrote {len(lines)} cases to {a.golden}")


if __name__ == "__main__":
    main()
