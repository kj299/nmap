#!/usr/bin/env python3
"""Generate the exhaustive scan-classification case matrix for core::classify.

Writes ../classify_cases.txt. Regenerate the golden by piping it through the oracle:
    g++ -O2 -Wall classify_oracle.cc -o classify_oracle
    ./classify_oracle < ../classify_cases.txt > ../classify_golden.txt

The matrix is exhaustive over the meaningful input space: every scan type against
every default-state input, all 256 TCP flag bytes x {0, nonzero window}, ICMP
type x code x from_target, and every SCTP chunk value. For ICMPv6 every code of
the two types the C reads (destination unreachable, parameter problem), and the
other error and informational types over a spread of codes.

The ICMPv6 parameter-problem code 0 cases are where the port fixes the C (D2,
classify6-param-problem-field-filtered); the golden keeps the C's answer and
classify_differential.rs pins the port's beside it.
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
    icmp6_types = [(1, range(256)), (4, range(256))]
    icmp6_types += [(t, list(range(8)) + [255]) for t in (0, 2, 3, 5, 100, 127, 128, 129, 133, 134, 135, 136, 137, 200, 255)]
    for s in SCANS:
        for t, codes in icmp6_types:
            for c in codes:
                for ft in (0, 1):
                    out.append(f"icmp6 {s} {t} {c} {ft}")
    for s in SCANS:
        for ch in range(16):
            out.append(f"sctp {s} {ch}")
    path = os.path.join(os.path.dirname(__file__), "..", "classify_cases.txt")
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {len(out)} cases to {os.path.normpath(path)}")


if __name__ == "__main__":
    main()
