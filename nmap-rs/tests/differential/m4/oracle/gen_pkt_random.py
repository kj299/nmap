#!/usr/bin/env python3
"""Generate the randomised IPv6 chain corpus for core::packet_parser.

The hand-written cases in gen_pkt_vectors.py cover the chains a real scan meets. This
generator covers the ones a hostile sender would try: extension headers stacked in
arbitrary orders with arbitrary length fields, ICMPv6 messages of every type, options
whose TLV lengths do not tile their header, and truncations at every layer boundary.
Each packet is emitted as one hex line; the C oracle projects them all in one pass
(`parse_oracle pkt_ip_lines`), which keeps the corpus to two committed files.

Deterministic: a fixed seed, so the committed golden is reproducible.

  ./gen_pkt_random.py
  ./parse_oracle pkt_ip_lines < ../pkt_random_vectors.txt > ../pkt_random_golden.txt
"""
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "..", "pkt_random_vectors.txt")
SEED = 0x6D34F00D
COUNT = 4000

# Next-header values worth reaching for: the four extension headers, the three
# transport layers the walk descends into, IPv6-in-IPv6, and some unhandled ones.
NEXT_HEADERS = [0, 43, 44, 60, 6, 17, 58, 41, 4, 1, 132, 50, 99]
ICMPV6_TYPES = [1, 2, 3, 4, 128, 129, 130, 133, 134, 135, 136, 137, 138, 139, 200, 255]
OPT_TYPES = [0x00, 0x01, 0xC2, 0x04, 0x05, 0x26, 0x07, 0xC9, 0x33]


def ipv6(rnd, nh):
    b = bytearray()
    b += bytes([0x60, rnd.randrange(256), rnd.randrange(256), rnd.randrange(256)])
    b += rnd.randrange(65536).to_bytes(2, "big")   # payload length (parser ignores)
    b.append(nh)
    b.append(rnd.randrange(256))                   # hop limit
    b += bytes(rnd.randrange(256) for _ in range(32))
    return bytes(b)


# (option type, total bytes consumed) for the fixed-length options; CALIPSO and the
# unrecognised types are variable and handled separately.
FIXED_OPTS = [(0xC2, 6), (0x04, 3), (0x05, 4), (0x26, 8), (0xC9, 18)]


def options_header(rnd, nh):
    """A hop-by-hop / destination-options header.

    Built to tile exactly — the case that actually reaches the transport layer — and
    then corrupted a third of the time, so both the accept and the reject paths of the
    option walk are exercised rather than only the reject path.
    """
    units = rnd.randrange(0, 3)
    total = (units + 1) * 8
    room = total - 2
    body = bytearray()
    while len(body) < room:
        left = room - len(body)
        choices = [("pad1", 1)]
        if left >= 2:
            choices.append(("padn", rnd.randrange(2, min(left, 20) + 1)))
            choices.append(("unknown", rnd.randrange(2, min(left, 20) + 1)))
        if left >= 10:
            choices.append(("calipso", rnd.randrange(10, min(left, 24) + 1)))
        choices += [(t, n) for (t, n) in FIXED_OPTS if n <= left]
        kind, size = rnd.choice(choices)
        if kind == "pad1":
            body.append(0x00)
        elif kind == "padn":
            body += bytes([0x01, size - 2]) + bytes(size - 2)
        elif kind == "unknown":
            body += bytes([0x33, size - 2]) + bytes(
                rnd.randrange(256) for _ in range(size - 2)
            )
        elif kind == "calipso":
            body += bytes([0x07, size - 2]) + bytes(
                rnd.randrange(256) for _ in range(size - 2)
            )
        else:
            body += bytes([kind, size - 2]) + bytes(
                rnd.randrange(256) for _ in range(size - 2)
            )
    body = body[:room]
    hdr = bytearray([nh, units]) + body
    if rnd.randrange(3) == 0 and len(hdr) > 2:
        # Corrupt one option byte: a wrong TLV length, an invented type, or a length
        # field that no longer matches the header it sits in.
        i = rnd.randrange(2, len(hdr))
        hdr[i] = rnd.choice([0x01, 0xC2, 0x07, 0xC9, rnd.randrange(256)])
    return bytes(hdr)


def routing_header(rnd, nh):
    rtype = rnd.choice([0, 0, 2, 2, rnd.randrange(256)])
    hlen = rnd.randrange(0, 4)
    segleft = rnd.choice([0, 1, 2, rnd.randrange(256)])
    total = 24 if rtype == 2 else (hlen + 1) * 8
    b = bytearray([nh, hlen, rtype, segleft])
    b += bytes(rnd.randrange(256) for _ in range(max(0, total - 4)))
    return bytes(b[:total])


def fragment_header(rnd, nh):
    return bytes([nh, 0] + [rnd.randrange(256) for _ in range(6)])


# The header length each ICMPv6 type implies (nmap's getHeaderLengthFromType).
ICMPV6_LENS = {130: 24, 131: 24, 132: 24, 134: 16, 135: 24, 136: 24, 137: 40,
               138: 16, 139: 16, 140: 16}


def icmpv6(rnd):
    """An ICMPv6 message, usually exactly as long as its type demands and sometimes
    a byte or two short — the boundary nmap's validate() turns into accept/reject."""
    t = rnd.choice(ICMPV6_TYPES)
    want = ICMPV6_LENS.get(t, 8)
    n = rnd.choice([want, want, want, want - 1, want + 8, 4, 8])
    return bytes([t, rnd.randrange(256), 0, 0]) + bytes(
        rnd.randrange(256) for _ in range(max(0, n - 4))
    )


def tcp(rnd):
    off = rnd.choice([4, 5, 5, 6, 8, 15])
    b = bytearray(rnd.randrange(256) for _ in range(20))
    b[12] = (off << 4) | (b[12] & 0x0F)
    b += bytes(rnd.randrange(256) for _ in range(max(0, off * 4 - 20)))
    return bytes(b)


def udp(rnd):
    return bytes(rnd.randrange(256) for _ in range(8))


def build(rnd):
    """One packet: an IPv6 header, a random extension chain, a random transport."""
    layers = []
    depth = rnd.randrange(0, 4)
    kinds = [rnd.choice([0, 43, 44, 60]) for _ in range(depth)]
    # Weighted toward the transports the walk actually descends into, so the corpus
    # spends its budget on reachable chains rather than on immediate raw tails.
    final = rnd.choice(NEXT_HEADERS + [6, 17, 58, 58, 58])
    chain = kinds + [final]
    layers.append(ipv6(rnd, chain[0]))
    for i, k in enumerate(kinds):
        nh = chain[i + 1]
        if k in (0, 60):
            layers.append(options_header(rnd, nh))
        elif k == 43:
            layers.append(routing_header(rnd, nh))
        else:
            layers.append(fragment_header(rnd, nh))
    if final == 6:
        layers.append(tcp(rnd))
    elif final == 17:
        layers.append(udp(rnd))
    elif final == 58:
        layers.append(icmpv6(rnd))
        # An error report quotes the offending packet; give it something to find.
        if layers[-1][0] in (1, 2, 3, 4):
            layers.append(ipv6(rnd, 6) + tcp(rnd))
    elif final in (41, 4):
        layers.append(ipv6(rnd, 6) + tcp(rnd))
    else:
        layers.append(bytes(rnd.randrange(256) for _ in range(rnd.randrange(0, 24))))

    pkt = b"".join(layers)
    # A third of the corpus is truncated somewhere, which is where a length field the
    # parser trusts and a buffer that cannot back it disagree.
    if len(pkt) > 1 and rnd.randrange(3) == 0:
        # At least one byte: the line format cannot carry an empty packet, and the
        # zero-length case lives in the per-file corpus instead.
        pkt = pkt[: rnd.randrange(1, len(pkt))]
    return pkt


def main():
    rnd = random.Random(SEED)
    with open(OUT, "w") as f:
        f.write(f"# generated by gen_pkt_random.py, seed 0x{SEED:X}, {COUNT} cases\n")
        for _ in range(COUNT):
            f.write(build(rnd).hex() + "\n")
    print(f"wrote {COUNT} random packets to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
