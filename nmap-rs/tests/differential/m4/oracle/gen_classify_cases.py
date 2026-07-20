#!/usr/bin/env python3
"""Generate the exhaustive scan-classification case matrix for core::classify.

Writes ../classify_cases.txt. Regenerate the golden by piping it through the oracle:
    g++ -O2 -Wall classify_oracle.cc -o classify_oracle
    ./classify_oracle < ../classify_cases.txt > ../classify_golden.txt

The matrix is exhaustive over the meaningful input space: every scan type against
every default-state input, all 256 TCP flag bytes x {0, nonzero window}, ICMP
type x code x from_target, and every SCTP chunk value.
"""
import os

SCANS = "syn connect ack window maimon fin null xmas udp ipproto sctpinit sctpcookie".split()


def main():
    out = []
    for s in SCANS:
        for d in (0, 1):
            out.append(f"default {s} {d}")
    for s in SCANS:
        for flags in range(256):
            for win in (0, 1024):
                out.append(f"tcp {s} {flags} {win}")
    for s in SCANS:
        for t in range(16):
            for c in range(16):
                for ft in (0, 1):
                    out.append(f"icmp {s} {t} {c} {ft}")
    for s in SCANS:
        for ch in range(16):
            out.append(f"sctp {s} {ch}")
    path = os.path.join(os.path.dirname(__file__), "..", "classify_cases.txt")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {len(out)} cases to {os.path.normpath(path)}")


if __name__ == "__main__":
    main()
