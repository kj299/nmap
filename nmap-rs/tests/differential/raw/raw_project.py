#!/usr/bin/env python3
"""Project an `-oX` document onto what a raw scan decides: each host's state,
and each port's protocol, number, state and reason, one line apiece, sorted.

Dropped as run-to-run variable or not this gate's subject: timing, the reply's
TTL (`reason_ttl`), service names, and everything outside <host>.

Usage: raw_project.py < scan.xml
"""
import sys
import xml.etree.ElementTree as ET


def project(xml_text):
    out = []
    root = ET.fromstring(xml_text)
    for host in root.iter("host"):
        addr = host.find("address")
        name = addr.get("addr") if addr is not None else "?"
        status = host.find("status")
        out.append(f"host {name} {status.get('state') if status is not None else '?'}")
        for port in host.iter("port"):
            st = port.find("state")
            out.append(
                f"  {port.get('protocol')}/{port.get('portid')} "
                f"{st.get('state')} {st.get('reason')}"
            )
        for extra in host.iter("extraports"):
            out.append(f"  extraports {extra.get('state')} {extra.get('count')}")
    return out


def main():
    text = sys.stdin.read()
    try:
        lines = project(text)
    except ET.ParseError:
        # No document at all; the caller treats an empty projection as a failure.
        return 0
    print("\n".join(lines))
    return 0


if __name__ == "__main__":
    sys.exit(main())
