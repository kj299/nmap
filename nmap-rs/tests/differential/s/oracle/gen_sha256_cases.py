#!/usr/bin/env python3
"""Generate SHA-256 differential cases.

The oracle is the system `sha256sum` (GNU coreutils), not a second implementation
of the algorithm -- comparing a hand-rolled SHA-256 against another hand-rolled one
would prove only that they agree with each other.

The corpus concentrates on the padding and buffering boundaries, which is where a
hand-rolled hasher actually goes wrong. It did here: the first draft reset the
buffer length to zero whenever a call was consumed entirely by topping up a partial
block, which made `finish` loop forever. Lengths 0..=200 cover every position
relative to the 64-byte block and the 55/56-byte padding cliff; the longer cases
cover multi-block messages and the length field.

Emits one `<id> <hexbytes>` line per case on stdout.
"""
import random
import sys

random.seed(0x5A5A)

CASES = []


def case(cid, data):
    CASES.append((cid, data))


# Every length from empty through three blocks: the padding cliff (55/56), exact
# block multiples (64, 128, 192) and everything between.
for n in range(0, 201):
    case(f"len-{n}", bytes((i * 7 + 3) % 256 for i in range(n)))

# Named boundaries, so a failure names itself.
case("empty", b"")
case("abc", b"abc")
case("block-minus-1", b"a" * 63)
case("block-exact", b"a" * 64)
case("block-plus-1", b"a" * 65)
case("pad-fits", b"a" * 55)
case("pad-overflows", b"a" * 56)

# All-same-byte messages, which make an off-by-one in the schedule obvious.
for b in (0x00, 0x01, 0x7f, 0x80, 0xff):
    case(f"fill-{b:02x}", bytes([b]) * 100)

# Every single byte value alone.
for b in range(256):
    case(f"single-{b:02x}", bytes([b]))

# Multi-block random messages, including sizes either side of block multiples.
for i in range(200):
    n = random.choice([1, 63, 64, 65, 127, 128, 129, 191, 192, 193,
                       255, 256, 257, 511, 512, 1000, 4096])
    case(f"rand-{i}", bytes(random.randrange(256) for _ in range(n)))

if __name__ == "__main__":
    for cid, data in CASES:
        sys.stdout.write(f"{cid} {data.hex()}\n")
