#!/usr/bin/env python3
"""Generate expr_match differential cases.

Emits TSV lines "<do_nested>\t<val>\t<expr>" covering:
  * every expression shape the language has (literal, alternation, range,
    comparison, nested group), including degenerate/malformed ones,
  * real attribute values and expressions harvested from the shipped nmap-os-db,
  * a deterministic pseudo-random cross-product so the corpus is wide.

Values and expressions never contain a tab, newline, or NUL, which is what the
oracle's line protocol requires.
"""
import re
import sys
from pathlib import Path

# Deterministic PRNG so the committed corpus is reproducible.
class Rng:
    def __init__(self, seed):
        self.s = seed
    def next(self):
        # xorshift32
        x = self.s
        x ^= (x << 13) & 0xFFFFFFFF
        x ^= x >> 17
        x ^= (x << 5) & 0xFFFFFFFF
        self.s = x & 0xFFFFFFFF
        return self.s
    def pick(self, seq):
        return seq[self.next() % len(seq)]

HEX = "0123456789ABCDEF"

# Hand-written shapes: the whole grammar plus its sharp edges.
EXPRS = [
    "", "A", "Z", "S", "AS", "7F", "40", "FFFF", "0", "00", "000",
    "S|A", "S|A|AS", "A|", "|A", "|", "||", "A||B",
    "1-9", "0-F", "A-F", "1-", "-1", "-", "--", "0-0", "F-1",
    ">0", ">1", ">FF", ">400", ">0400", "<0", "<1", "<FF", "<400",
    ">", "<", ">|", "<|", ">|<",
    "[", "]", "[]", "[|]", "A[", "[A", "A|[", "[[[[", "]]]]", "[1-",
    "M[1-6]ST11", "M[>500]ST11W[1-5]", "M[1-6]", "[0-F]", "A[1-9]|B",
    "M5B4ST11NW7", "M[5-6]B4ST11NW[5-8]", "AB[C|D]E|XYZ", "AB[C-D]E",
    "1-2-3", "|-|", "0-", "0>", "Z|", "R|Z", "N|S", "E|F|G",
]

VALS = [
    "", "0", "5", "A", "F", "FF", "100", "000", "0005", "7F", "40", "Z", "S",
    "AS", "R", "M5ST11", "M5B4ST11", "M5B4ST11NW7", "M9ST11", "zz", "-", "|",
    "[", "]", "ABCDEF", "FFFF", "8", "1", "9", "C",
]


def harvest_os_db(path):
    """Pull real (attribute-value, expression) shapes out of nmap-os-db."""
    exprs, vals = set(), set()
    try:
        text = Path(path).read_text(errors="replace")
    except OSError:
        return [], []
    # Lines look like: SEQ(SP=0-5%GCD=1-6%ISR=104-10E%TI=I%CI=I%II=I%TS=A)
    for line in text.splitlines():
        if not line or line[0] == "#":
            continue
        m = re.match(r"^[A-Z0-9]+\((.*)\)$", line.strip())
        if not m:
            continue
        for kv in m.group(1).split("%"):
            if "=" not in kv:
                continue
            _, v = kv.split("=", 1)
            if not v or "\t" in v or "\n" in v:
                continue
            exprs.add(v)
            # An expression's own literal alternatives double as plausible values.
            for alt in v.split("|"):
                if alt and not any(c in alt for c in "[]<>-"):
                    vals.add(alt)
    return sorted(exprs), sorted(vals)


def main():
    db = sys.argv[1] if len(sys.argv) > 1 else "../../../../../nmap-os-db"
    db_exprs, db_vals = harvest_os_db(db)
    # Cap the harvested set so the corpus stays a reviewable size.
    db_exprs = db_exprs[:600]
    db_vals = db_vals[:200]

    out = []
    seen = set()

    def emit(nested, val, expr):
        key = (nested, val, expr)
        if key in seen:
            return
        seen.add(key)
        out.append(f"{nested}\t{val}\t{expr}")

    # Full cross-product of the hand-written shapes, both nesting modes.
    for e in EXPRS:
        for v in VALS:
            emit(0, v, e)
            emit(1, v, e)

    # Real database expressions against real values.
    for e in db_exprs:
        for v in db_vals[:12]:
            emit(0, v, e)
            emit(1, v, e)

    # Deterministic random hex strings against real expressions — the widest net.
    rng = Rng(0x5EED_1234)
    for e in db_exprs[:200]:
        for _ in range(4):
            n = 1 + rng.next() % 5
            v = "".join(HEX[rng.next() % 16] for _ in range(n))
            emit(0, v, e)
            emit(1, v, e)

    # Random expressions built from the grammar's own tokens.
    toks = ["|", "-", ">", "<", "[", "]", "0", "1", "9", "A", "F", "M", "S", "W"]
    for _ in range(4000):
        n = 1 + rng.next() % 8
        e = "".join(rng.pick(toks) for _ in range(n))
        v = rng.pick(VALS + db_vals[:40])
        emit(rng.next() % 2, v, e)

    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
