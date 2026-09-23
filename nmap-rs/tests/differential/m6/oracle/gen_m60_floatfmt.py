#!/usr/bin/env python3
"""Emit a corpus of doubles for the float-to-string gate.

`tostring(1.0)` is `"1.0"` in Lua and `"1"` in Rust, and that is the small end
of the divergence: Rust's `Display` for `f64` is shortest-round-trip and never
uses exponent notation, where Lua's is `printf("%.14g")` plus a `".0"` when the
result would read back as an integer. So `1/3` differs in its digit count,
`1e300` differs by three hundred characters, and `1e13` differs from `1e14` by
which of the two styles `%g` selects. None of that is expressible as a rule to
assert; it is a reimplementation of a C library function, and the only honest
gate is the C library function itself.

So: each case is an IEEE-754 bit pattern, and the golden is what nmap's own Lua
prints for it -- both through `tostring` and through `..`, because those are
separate code paths in the VM and only one of them was wrong before.

Bits, not decimal literals, for two reasons. A literal has to survive Python's
formatting, the file, and Lua's lexer before it reaches the oracle, and any of
those could round it; and `-0.0` is not writable as a literal Lua distinguishes
from `0.0`, while it is exactly the value whose `".0"` suffix the C appends
after a sign.

The operands are chosen to cover the conversion's decision points rather than
to be numerous:

  * every power of two, all 2098 of them, from `5e-324` to `2^1023`. These are
    the values whose exact decimal expansion terminates, so they are where
    rounding to 14 significant digits can land exactly on a tie -- the case
    where "round half to even" and "round half away from zero" disagree and a
    reimplementation silently picks the wrong one.
  * every power of ten, which is where `%g` switches between `%f` and `%e`
    style (`1e13` prints as `10000000000000.0`, `1e14` as `1e+14`), and their
    neighbours one ULP away, which is where an off-by-one in the switch shows.
  * small integers and halves, which is what NSE scripts actually print.
  * the specials: both zeroes, both infinities, both NaN signs, the subnormal
    boundary, and `DBL_MAX`.
  * a deterministic pseudo-random sweep of the whole 64-bit pattern space, to
    reach the mantissas nobody would think to write down.
"""
from __future__ import annotations

import struct
import sys

def bits(v: float) -> int:
    return struct.unpack(">Q", struct.pack(">d", v))[0]


# A 64-bit LCG, written out rather than taken from `random`, so that the corpus
# is reproducible from this file alone and cannot drift with a library version.
# Multiplier and increment are Knuth's MMIX values.
class Lcg:
    def __init__(self, seed: int) -> None:
        self.s = seed & 0xFFFFFFFFFFFFFFFF

    def next(self) -> int:
        self.s = (self.s * 6364136223846793005 + 1442695040888963407) & 0xFFFFFFFFFFFFFFFF
        return self.s


CASES: list[tuple[str, int, str]] = []
seen: set[str] = set()


def add(name: str, pattern: int, note: str) -> None:
    if name in seen:
        raise SystemExit("duplicate case name: %s" % name)
    seen.add(name)
    CASES.append((name, pattern & 0xFFFFFFFFFFFFFFFF, note))


# --- the specials --------------------------------------------------------
add("zero_pos", bits(0.0), "prints 0.0, not 0")
add("zero_neg", bits(-0.0), "-0.0: the sign survives %g and the .0 is appended after it")
add("inf_pos", 0x7FF0000000000000, "inf, and NOT inf.0 -- the strspn test excludes it")
add("inf_neg", 0xFFF0000000000000, "-inf")
add("nan_quiet", 0x7FF8000000000000, "nan")
add("nan_quiet_neg", 0xFFF8000000000000, "glibc prints the sign bit of a NaN: -nan")
add("nan_payload", 0x7FF8000000ABCDEF, "the payload does not reach the output")
add("nan_signalling", 0x7FF0000000000001, "a signalling NaN still prints as nan")
add("subnormal_min", 0x0000000000000001, "4.9406564584125e-324, the smallest positive double")
add("subnormal_max", 0x000FFFFFFFFFFFFF, "the largest subnormal")
add("normal_min", 0x0010000000000000, "the smallest normal")
add("dbl_max", 0x7FEFFFFFFFFFFFFF, "1.7976931348623e+308")
add("dbl_max_neg", 0xFFEFFFFFFFFFFFFF, "-1.7976931348623e+308")

# --- every power of two --------------------------------------------------
for e in range(-1074, 1024):
    add("p2_%d" % e, bits(2.0 ** e), "2^%d" % e)

# --- every power of ten, and its two nearest neighbours ------------------
for k in range(-323, 309):
    v = float("1e%d" % k)
    add("p10_%d" % k, bits(v), "1e%d" % k)
    # One ULP either side: %g's style switch is decided by the exponent AFTER
    # rounding, so the interesting values are the ones that round across it.
    b = bits(v)
    if b > 0:
        add("p10_%d_down" % k, b - 1, "1e%d minus one ULP" % k)
    add("p10_%d_up" % k, b + 1, "1e%d plus one ULP" % k)

# --- what a script actually prints ---------------------------------------
for n in range(0, 257):
    add("int_%d" % n, bits(float(n)), "%d.0" % n)
    if n > 0:
        add("int_%d_neg" % n, bits(float(-n)), "-%d.0" % n)
    add("half_%d" % n, bits(n + 0.5), "%d.5" % n)

# Ratios: 14 significant digits is exactly where a repeating expansion is cut.
for num in range(1, 21):
    for den in (3, 7, 9, 11, 13, 1000, 1024):
        add("ratio_%d_%d" % (num, den), bits(num / den), "%d/%d" % (num, den))

# --- the whole pattern space ---------------------------------------------
rng = Lcg(0x5EED_10A0_F10A_7000)
for i in range(3000):
    add("rand_%d" % i, rng.next(), "pseudo-random bit pattern")


def main() -> int:
    out = sys.stdout
    out.write("# name\tbits_hex\tnote\n")
    out.write("# Generated by oracle/gen_m60_floatfmt.py. Do not edit by hand.\n")
    out.write("# bits_hex is the IEEE-754 binary64 pattern, big-endian, 16 hex digits.\n")
    for name, pattern, note in CASES:
        if "\t" in note or "\n" in note:
            raise SystemExit("note for %s contains a field separator" % name)
        out.write("%s\t%016x\t%s\n" % (name, pattern, note))
    return 0


if __name__ == "__main__":
    sys.exit(main())
