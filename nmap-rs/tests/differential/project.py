#!/usr/bin/env python3
"""Canonical-projection filter for the M1 connect-scan differential.

Reads an nmap-style `-oX` XML document on stdin (from EITHER C nmap or nmap-rs)
and emits a small, deterministic projection of the *semantic* scan result — the
content Milestone 1 actually commits to: host up/down, and per-open-port
state+reason, plus aggregate closed/filtered counts.

Why a projection instead of a raw diff? The two tools' full output legitimately
differs in ways that are NOT fidelity bugs and are out of M1 scope (logged in
DIVERGENCES.md): the MVP renderer omits nmap's decorative XML preamble
(`<!DOCTYPE>`, `<?xml-stylesheet?>`, `<scaninfo>`, `<verbose>`, `<debugging>`,
`<times>`), collapses non-open ports into `<extraports>` where nmap lists each
individually, and does not emit latency/`reason_ttl`/service-guess elements.
Diffing raw XML would drown the load-bearing signal — did we get every port's
STATE and REASON right? — in that intentional noise. This filter canonicalizes
BOTH representations (per-port `<port state="closed">` AND aggregated
`<extraports>`) to the same shape, so a genuine regression (an open port reported
closed, a wrong reason, a miscounted closed set) breaks the match while the
ledgered abbreviations stay invisible. Service NAMES are excluded on purpose: M1
does no version detection, and the port-table service label is a decorative
nmap-services lookup, not a scan finding.

Output is line-oriented and sorted-stable:
    host <addr> <status>
    open <portid> <proto> <reason>
    openfiltered <portid> <proto> <reason>
    closed-count <proto> <n>
    filtered-count <proto> <n>

Usage: project.py            # XML on stdin -> projection on stdout
       project.py --self-test
"""
from __future__ import annotations

import sys
import xml.etree.ElementTree as ET

# States nmap collapses into <extraports state="..." count="N">. We aggregate
# both per-port and extraports representations into a single count per (state,
# proto) so the two renderers canonicalize to the same lines.
COUNTED_STATES = ("closed", "filtered")


def project(xml_text):
    lines = []
    try:
        root = ET.fromstring(xml_text)
    except ET.ParseError as e:
        # A malformed/empty document is itself a divergence worth surfacing —
        # emit a stable marker rather than crashing the harness.
        return f"parse-error {e.__class__.__name__}\n"

    for host in root.iter("host"):
        addr = ""
        for a in host.findall("address"):
            # Prefer the IP address (ipv4/ipv6) over MAC.
            if a.get("addrtype", "").startswith("ipv"):
                addr = a.get("addr", "")
                break
        status_el = host.find("status")
        status = status_el.get("state", "") if status_el is not None else ""
        lines.append(f"host {addr} {status}")

        counts = {}  # (state, proto) -> n
        ports_el = host.find("ports")
        if ports_el is not None:
            for extra in ports_el.findall("extraports"):
                st = extra.get("state", "")
                # extraports has no protocol; nmap's connect scan is tcp-only in
                # M1, so attribute the aggregate to tcp.
                try:
                    n = int(extra.get("count", "0"))
                except ValueError:
                    n = 0
                counts[(st, "tcp")] = counts.get((st, "tcp"), 0) + n
            for port in ports_el.findall("port"):
                proto = port.get("protocol", "")
                portid = port.get("portid", "")
                state_el = port.find("state")
                st = state_el.get("state", "") if state_el is not None else ""
                reason = state_el.get("reason", "") if state_el is not None else ""
                if st == "open":
                    lines.append(f"open {portid} {proto} {reason}")
                elif st == "open|filtered":
                    lines.append(f"openfiltered {portid} {proto} {reason}")
                elif st in COUNTED_STATES:
                    counts[(st, proto)] = counts.get((st, proto), 0) + 1
                else:
                    # Any other state (e.g. unfiltered) — surface it explicitly.
                    lines.append(f"{st} {portid} {proto} {reason}")

        for st in COUNTED_STATES:
            for (cst, proto), n in sorted(counts.items()):
                if cst == st and n:
                    lines.append(f"{st}-count {proto} {n}")

    # Sort for order-independence (host/port emission order is not part of the
    # M1 contract); keep it deterministic across both tools.
    lines.sort()
    return "\n".join(lines) + ("\n" if lines else "")


def _self_test():
    ok = True

    def check(name, cond):
        nonlocal ok
        print(("PASS" if cond else "FAIL") + f"  {name}")
        ok = ok and cond

    # nmap-style: every port listed individually.
    nmap_xml = """<?xml version="1.0"?><nmaprun>
      <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
      <ports>
        <port protocol="tcp" portid="18080"><state state="open" reason="syn-ack"/></port>
        <port protocol="tcp" portid="18081"><state state="closed" reason="conn-refused"/></port>
        <port protocol="tcp" portid="18443"><state state="open" reason="syn-ack"/></port>
        <port protocol="tcp" portid="19999"><state state="closed" reason="conn-refused"/><service name="dnp-sec"/></port>
      </ports></host></nmaprun>"""
    # nmap-rs-style: open listed, closed collapsed into extraports.
    rs_xml = """<?xml version="1.0"?><nmaprun>
      <host><status state="up"/><address addr="127.0.0.1" addrtype="ipv4"/>
      <ports>
        <extraports state="closed" count="2"/>
        <port protocol="tcp" portid="18080"><state state="open" reason="syn-ack"/><service name="unknown"/></port>
        <port protocol="tcp" portid="18443"><state state="open" reason="syn-ack"/><service name="unknown"/></port>
      </ports></host></nmaprun>"""
    a, b = project(nmap_xml), project(rs_xml)
    check("per-port and extraports collapse to the same projection", a == b)
    check("open ports + reason retained", "open 18080 tcp syn-ack" in a)
    check("closed aggregated to a count", "closed-count tcp 2" in a)
    check("service names excluded (decorative)", "dnp-sec" not in a and "unknown" not in b)

    # A real regression must break the match: open port mis-reported closed.
    regress = rs_xml.replace('portid="18443"><state state="open" reason="syn-ack"',
                             'portid="18443"><state state="closed" reason="conn-refused"')
    # collapse the now-3-closed into extraports to mimic the renderer
    regress = regress.replace('count="2"', 'count="3"')
    regress = regress.replace(
        '<port protocol="tcp" portid="18443"><state state="closed" reason="conn-refused"/><service name="unknown"/></port>', "")
    check("an open->closed regression breaks the match", project(regress) != a)

    check("malformed XML yields a stable marker, no crash",
          project("<not-xml").startswith("parse-error"))
    print("\nself-test:", "OK" if ok else "FAILED")
    return 0 if ok else 1


def main(argv):
    if "--self-test" in argv:
        return _self_test()
    sys.stdout.write(project(sys.stdin.read()))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
