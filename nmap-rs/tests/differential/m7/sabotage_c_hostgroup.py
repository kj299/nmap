#!/usr/bin/env python3
"""Sabotage the C to measure the host-group corpus (LESSONS #044; ORACLE-CHECKS §4).

Each variant breaks one rule of nmap's group formation in a copy of the oracle's
source, rebuilds it, and runs gen_hostgroup_golden.py --check with it. The golden
must differ for every variant: one that still matches is a rule the corpus cannot
tell from its absence, and so a rule the port could get wrong unseen.

A variant is CAUGHT by the first case that runs to its end and differs. A case
the broken nmap hangs on is passed over after two minutes and is not a catch; a
variant whose only failures are such cases is INCONCLUSIVE.

Usage: sabotage_c_hostgroup.py ORACLE_SRC [--only N ...]
  ORACLE_SRC: a built tree of nmap 7.94 (3be01efb1). It is edited in place and
  restored after each variant; `make` must already have succeeded there.
Needs root, as the generator does.
"""
import os
import shutil
import subprocess
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
SE, TG, TH, NM = "scan_engine.cc", "targets.cc", "targets.h", "nmap.cc"
V = [
 ("UDP groups of 127", SE, "    groupsize = 128;\n  else if (o.SCTPScan())", "    groupsize = 127;\n  else if (o.SCTPScan())"),
 ("TCP tested before UDP", SE, "  if (o.UDPScan())\n    groupsize = 128;\n  else if (o.SCTPScan())\n    groupsize = 128;\n  else if (o.TCPScan()) {",
  "  if (o.UDPScan() && !o.TCPScan())\n    groupsize = 128;\n  else if (o.SCTPScan())\n    groupsize = 128;\n  else if (o.TCPScan()) {"),
 ("1023 / ports", SE, "MAX(1024 / (ports->tcp_count ? ports->tcp_count : 1), 64)", "MAX(1023 / (ports->tcp_count ? ports->tcp_count : 1), 64)"),
 ("a floor of 63", SE, "MAX(1024 / (ports->tcp_count ? ports->tcp_count : 1), 64)", "MAX(1024 / (ports->tcp_count ? ports->tcp_count : 1), 63)"),
 ("the quick group from 1,000 ports", SE, "ports->tcp_count > 1000 &&", "ports->tcp_count >= 1000 &&"),
 ("the quick group from 1,002 ports", SE, "ports->tcp_count > 1000 &&", "ports->tcp_count > 1001 &&"),
 ("no quick group at -T4", SE, "o.timing_level <= 4) {", "o.timing_level <= 3) {"),
 ("a quick group at -T5", SE, "o.timing_level <= 4) {", "o.timing_level <= 5) {"),
 ("a quick group of 5", SE, "int quickgroupsz = 4;", "int quickgroupsz = 5;"),
 ("-T4's quick group is 4", SE, "        quickgroupsz = 8;", "        quickgroupsz = 4;"),
 ("the second group not shortened", SE, "        groupsize -= quickgroupsz;", "        groupsize -= 0;"),
 ("every later group shortened", SE, "      else if (hosts_scanned_so_far == quickgroupsz &&", "      else if (hosts_scanned_so_far >= quickgroupsz &&"),
 ("--min-hostgroup ignored", SE, "box(o.minHostGroupSz(), o.maxHostGroupSz(), groupsize)", "box(1, o.maxHostGroupSz(), groupsize)"),
 ("--max-hostgroup ignored", SE, "box(o.minHostGroupSz(), o.maxHostGroupSz(), groupsize)", "box(o.minHostGroupSz(), 100000, groupsize)"),
 ("a different source shares a group", TG, "  if (sockaddr_storage_cmp(targets[0]->SourceSockAddr(), target->SourceSockAddr()) != 0)\n    return true;", ""),
 ("a repeated address shares a group", TG, "    if (sockaddr_storage_cmp(targets[i]->TargetSockAddr(), target->TargetSockAddr()) == 0)\n      return true;", ""),
 # Dropping the test outright leaves an nmap that scans nothing (it compares the
 # sources of targets that have none), which measures nothing. This keeps the
 # scan alive and applies one of the routed rules to it.
 ("unrouted scans hold a repeated address back too", TG,
  "  if (!(o.isr00t && target->deviceName() != NULL))\n    return false;",
  "  if (!(o.isr00t && target->deviceName() != NULL)) {\n"
  "    for (i = 0; i < targets_sz; i++)\n"
  "      if (sockaddr_storage_cmp(targets[i]->TargetSockAddr(), target->TargetSockAddr()) == 0)\n"
  "        return true;\n"
  "    return false;\n  }"),
 ("a defer buffer of 63", TH, "DEFER_LIMIT = 64;", "DEFER_LIMIT = 63;"),
 ("a defer buffer of 65", TH, "DEFER_LIMIT = 64;", "DEFER_LIMIT = 65;"),
 ("a misfit ends the batch instead of waiting", TG, "      if (hs->defer(t))\n        continue;\n      else\n        break;", "      hs->defer(t);\n      break;"),
 ("the batch not raised to --min-hostgroup", NM, "  if (o.ping_group_sz < o.minHostGroupSz())\n    o.ping_group_sz = o.minHostGroupSz();", ""),
 ("a batch of 4,095", "nmap.h", "#define PING_GROUP_SZ 4096", "#define PING_GROUP_SZ 4095"),
 ("a batch of 4,097", "nmap.h", "#define PING_GROUP_SZ 4096", "#define PING_GROUP_SZ 4097"),
 # Found by the review of step a: each of these passed the first 55 cases.
 ("a default of 17", SE, "int groupsize = 16;", "int groupsize = 17;"),
 ("no quick group below -T3", SE, "o.timing_level <= 4) {", "o.timing_level >= 3 && o.timing_level <= 4) {"),
 ("a short first group shortens the second too", SE, "      else if (hosts_scanned_so_far == quickgroupsz &&", "      else if (hosts_scanned_so_far <= quickgroupsz &&"),
 ("the repeat test reads only the group's first address", TG, "  for (i = 0; i < targets_sz; i++) {", "  for (i = 0; i < 1; i++) {"),
 ("the batch raised past --min-hostgroup", NM, "    o.ping_group_sz = o.minHostGroupSz();", "    o.ping_group_sz = o.minHostGroupSz() + 1;"),
 ("hosts scanned is the last group's", NM, "    o.numhosts_scanned += Targets.size();", "    o.numhosts_scanned = Targets.size();"),
]


def main():
    src = os.path.abspath(sys.argv[1])
    only = [int(x) for x in sys.argv[3:]] if len(sys.argv) > 2 and sys.argv[2] == "--only" else None
    gen = [sys.executable, os.path.join(HERE, "gen_hostgroup_golden.py"),
           "--nmap", os.path.join(src, "nmap"), "--check", "--fail-fast", "--timeout", "120"]
    env = dict(os.environ, NMAPDIR=src)
    quiet = dict(stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    caught = total = 0
    for i, (name, f, old, new) in enumerate(V):
        if only is not None and i not in only:
            continue
        path = os.path.join(src, f)
        saved = open(path, "rb").read()
        if saved.count(old.encode()) != 1:
            sys.exit(f"FAIL: variant {i} ({name}): its text occurs "
                     f"{saved.count(old.encode())} times in {f}")
        total += 1
        try:
            open(path, "wb").write(saved.replace(old.encode(), new.encode()))
            b = subprocess.run(["make", "-j3", "nmap"], cwd=src, **quiet)
            if b.returncode != 0:
                print(f"NOBUILD {i} {name}\n{b.stdout[-600:]}", flush=True)
                continue
            r = subprocess.run(gen, env=env, **quiet)
            differs = [l for l in r.stdout.splitlines() if l.startswith("  golden: ")]
            if r.returncode != 0 and differs:
                caught += 1
                hung = r.stdout.count("DID NOT FINISH")
                print(f"CAUGHT  {i} {name}: {differs[0][10:90]}"
                      + (f" ({hung} earlier case(s) did not finish)" if hung else ""), flush=True)
            elif r.returncode != 0:
                print(f"INCONCLUSIVE {i} {name}: {r.stdout[-300:]}", flush=True)
            else:
                print(f"MISSED  {i} {name}", flush=True)
        finally:
            open(path, "wb").write(saved)
            now = time.time()
            os.utime(path, (now, now))
    b = subprocess.run(["make", "-j3", "nmap"], cwd=src, **quiet)
    print(f"caught {caught} of {total}; restored build exit {b.returncode}")
    sys.exit(0 if caught == total else 1)


if __name__ == "__main__":
    main()
