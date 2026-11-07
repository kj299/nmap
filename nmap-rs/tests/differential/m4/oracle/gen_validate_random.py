#!/usr/bin/env python3
"""Generate the randomised IPv6 corpus for the core::recv_validate differential.

The hand cases in gen_validate_vectors.py name each header and fragment shape once.
This covers their combinations: chains of up to five extension headers in any
order and length, first and later fragments anywhere in the chain, every way a
chain can end (an upper layer, an unknown protocol, another extension header, the
end of the capture), payload lengths that match, fall short of or overshoot what
was captured, and TCP option lists both sound and broken.

Each line is `<tag> <hex>`. The tag is `frag` when the C's own walk crosses a
fragment header with a nonzero offset before it ends — the packets the port
refuses and the C reads (recv-validate6-non-initial-fragment) — and `-`
otherwise. The tag comes from a mirror of the C walk below; the test checks the
port against it independently (it must refuse exactly those), so a wrong mirror
fails the test rather than hiding a divergence. Every fragment header the C
walks has reserved byte 0, where its (reserved + 1) * 8 length rule and the
port's fixed 8 bytes agree; the reserved-byte divergence is a hand case.

Deterministic: a fixed seed, so the committed golden is reproducible.

  ./gen_validate_random.py
  cut -d' ' -f2 ../validate_random_vectors.txt | ./validate_oracle lines \\
      > ../validate_random_golden.txt
"""
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "..", "validate_random_vectors.txt")
SEED = 0x76A11D06
COUNT = 4000

EXTENSIONS = [0, 43, 44, 60]
# Where the chain ends: mostly the transports validatepkt checks, then the other
# upper layers it passes through, protocols it does not know, and an extension
# header with nothing behind it.
FINALS = [6] * 8 + [17] * 4 + [58] * 3 + [1, 132, 59, 50, 51, 41, 4, 99, 135, 0, 60, 43, 44]


def tcp_options(rnd):
    """A TCP option list padded to a 4-byte boundary, sound or (a third of the
    time) with one option's length byte or kind corrupted."""
    opts = bytearray()
    for _ in range(rnd.randrange(0, 5)):
        kind = rnd.choice(["mss", "ws", "sackok", "sack", "ts", "nop", "altck", "other"])
        if kind == "mss":
            opts += b"\x02\x04" + rnd.randrange(65536).to_bytes(2, "big")
        elif kind == "ws":
            opts += bytes([3, 3, rnd.randrange(15)])
        elif kind == "sackok":
            opts += b"\x04\x02"
        elif kind == "sack":
            blocks = rnd.randrange(1, 3)
            opts += bytes([5, 2 + 8 * blocks]) + bytes(rnd.randrange(256) for _ in range(8 * blocks))
        elif kind == "ts":
            opts += b"\x08\x0a" + bytes(rnd.randrange(256) for _ in range(8))
        elif kind == "nop":
            opts += b"\x01"
        elif kind == "altck":
            opts += bytes([14, 3, rnd.randrange(3)])
        else:
            n = rnd.randrange(2, 7)
            opts += bytes([rnd.choice([9, 30, 34, 253]), n]) + bytes(n - 2)
    if opts and rnd.random() < 0.33:
        i = rnd.randrange(len(opts))
        opts[i] = rnd.choice([0, 1, 2, 3, 5, 8, rnd.randrange(256)])
    if rnd.random() < 0.5:
        opts.append(0)  # EOL
    while len(opts) % 4:
        opts.append(0)
    return bytes(opts[:40])


def tcp(rnd):
    opts = tcp_options(rnd)
    off = 5 + len(opts) // 4
    if rnd.random() < 0.05:
        off = rnd.randrange(16)  # a data offset that lies
    h = bytearray(rnd.randrange(256) for _ in range(12))
    h.append(off << 4)
    h += bytes(rnd.randrange(256) for _ in range(7))
    return bytes(h) + opts + bytes(rnd.randrange(256) for _ in range(rnd.choice([0, 0, 1, 6, 20])))


def payload(rnd, final):
    if final == 6:
        return tcp(rnd)
    if final == 17:
        n = rnd.choice([8, 8, 9, 20, rnd.randrange(8)])
        return bytes(rnd.randrange(256) for _ in range(n))
    if final == 58:
        return bytes([rnd.choice([1, 2, 3, 4, 128, 129, 135, 136]), rnd.randrange(5)]) + bytes(
            rnd.randrange(256) for _ in range(rnd.randrange(2, 48)))
    if final in EXTENSIONS:
        return b"" if rnd.random() < 0.5 else bytes(rnd.randrange(256) for _ in range(rnd.randrange(8)))
    return bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 33)))


def chain(rnd):
    types = [rnd.choice(EXTENSIONS) for _ in range(rnd.choice([0, 0, 1, 1, 1, 2, 2, 3, 4, 5]))]
    final = rnd.choice(FINALS)
    nexts = types[1:] + [final]
    body = bytearray()
    for t, nxt in zip(types, nexts):
        if t == 44:
            offset = 0 if rnd.random() < 0.6 else rnd.choice([1, 2, 185, rnd.randrange(1, 0x2000)])
            word = (offset << 3) | rnd.randrange(2)
            body += bytes([nxt, 0]) + word.to_bytes(2, "big") + bytes(rnd.randrange(256) for _ in range(4))
        else:
            units = rnd.choice([1, 1, 1, 2, 3, 5])
            h = bytearray(rnd.randrange(256) for _ in range(units * 8))
            h[0] = nxt
            h[1] = units - 1
            if rnd.random() < 0.04:
                h[1] = rnd.randrange(256)  # a length that lies
            body += h
    first = types[0] if types else final
    return first, bytes(body), final


def packet(rnd):
    first, body, final = chain(rnd)
    data = body + payload(rnd, final)
    trailer = b""
    shape = rnd.random()
    if shape < 0.45:
        plen = len(data)
    elif shape < 0.75:
        trailer = bytes(rnd.randrange(256) for _ in range(rnd.choice([1, 2, 4, 6, 12, 18])))
        plen = len(data)
    elif shape < 0.85:
        plen = len(data) + rnd.randrange(1, 64)
    elif shape < 0.95:
        plen = rnd.randrange(0, len(data) + 1)
    else:
        plen = rnd.randrange(65536)
    hdr = bytearray([0x60, rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)])
    hdr += plen.to_bytes(2, "big")
    hdr.append(first)
    hdr.append(rnd.randrange(256))
    hdr += bytes(rnd.randrange(256) for _ in range(32))
    pkt = bytes(hdr) + data + trailer
    if rnd.random() < 0.12:
        pkt = pkt[: rnd.randrange(20, len(pkt) + 1)]
    return pkt


def c_walk(pkt):
    """Mirror ipv6_get_data_primitive's walk (netutil.cc:689) far enough to say
    whether it crosses a later fragment, and whether every fragment header it
    crosses has reserved byte 0. Returns (crosses_later_fragment, reserved_ok)."""
    if len(pkt) < 40:
        return False, True
    end, nxt, p = len(pkt), pkt[6], 40
    later = False
    while p < end and nxt in EXTENSIONS:
        if p + 8 > end:
            break
        if nxt == 44:
            if pkt[p + 1] != 0:
                return later, False
            if int.from_bytes(pkt[p + 2:p + 4], "big") >> 3:
                later = True
        nxt = pkt[p]
        p += (pkt[p + 1] + 1) * 8
    return later, True


def main():
    rnd = random.Random(SEED)
    lines = []
    while len(lines) < COUNT:
        pkt = packet(rnd)
        later, reserved_ok = c_walk(pkt)
        if not reserved_ok:
            continue  # a lying length landed the walk on a nonzero reserved byte
        lines.append(("frag" if later else "-") + " " + pkt.hex())
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines)} packets to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
