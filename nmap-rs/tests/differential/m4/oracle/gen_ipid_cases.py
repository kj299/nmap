#!/usr/bin/env python3
"""Generate the IP-ID sequence-classification corpus for core::ipid.

Writes ../ipid_cases.txt (line: `<bits> <islocalhost> <n> <ipid...>`), covering every
IPID_SEQ_* class at 16 and 32 bits, localhost and not, plus edge cases. Regenerate the
golden by piping through the oracle:
    g++ -O2 -Wall ipid_oracle.cc -o ipid_oracle
    ./ipid_oracle < ../ipid_cases.txt > ../ipid_golden.txt
"""
import os

SEQS = {
    "incr": [100, 101, 102, 103],
    "incr2": [100, 102, 104, 106],
    "broken": [0x100, 0x200, 0x300, 0x400],
    "rpi": [1000, 3500, 8001, 15003],
    "rd_bigjump": [10, 40000, 5],
    "constant": [5000, 5000, 5000],
    "zero": [0, 0, 0, 0],
    "wrap16": [64000, 65000, 100],
    "two_incr": [7, 8],
    "two_zero": [0, 0],
    "mixed_small": [10, 11, 13, 14],
    "big256": [256, 25856, 25600],
    "near_thresh": [10, 20001, 3],
    "step5120": [5120, 10240, 15360],
    "step_over5120": [5121, 10242],
    "maxvals": [4294967295, 0, 1],
}


def main():
    lines = []
    for bits in (16, 32):
        for loc in (0, 1):
            for s in SEQS.values():
                lines.append(f"{bits} {loc} {len(s)} " + " ".join(str(x) for x in s))
    path = os.path.join(os.path.dirname(__file__), "..", "ipid_cases.txt")
    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} cases to {os.path.normpath(path)}")


if __name__ == "__main__":
    main()
