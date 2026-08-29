#!/usr/bin/env python3
"""Generate the fp6 vectorize differential corpus.

Each case is a set of probe responses (IPv6 packets, with send times) plus a distance
and a distance-calculation method. The cases exercise the parts of vectorize() that
carry signal: real IPv6+TCP responses with varied options (so the option block, MSS/
SACK/wscale and the window/mss ratio are populated), IPv6+ICMPv6 responses, the SEQ
battery with spaced send times (so the ISR feature is a real rate), hop limits near
each rounding boundary and past 255 after a distance adjustment, and the hostile edges
— a 17th TCP option (the overwrite quirk), EOL followed by more options, truncated
headers, and absent probes.

Deterministic (fixed seed) so the committed golden is reproducible. Emitted in the
exact stdin format the oracle reads; the Rust side parses the same file.

  ./gen_fp6_vectorize_cases.py > ../fp6_vectorize_cases.txt
  ./fp6_vectorize_oracle < ../fp6_vectorize_cases.txt > ../fp6_vectorize_golden.txt
"""
import os
import random
import sys

SEED = 0x5EC0DE6
COUNT = 1500
ALL_PROBES = ["S1", "S2", "S3", "S4", "S5", "S6", "IE1", "IE2", "NS",
              "U1", "TECN", "T2", "T3", "T4", "T5", "T6", "T7"]
TCP_PROBES = ["S1", "S2", "S3", "S4", "S5", "S6", "TECN", "T2", "T3", "T4", "T5", "T6", "T7"]
ICMP_PROBES = ["IE1", "IE2", "NS"]


def ipv6(rnd, nh, plen=None, hlim=None, tc=None):
    tc = rnd.randrange(256) if tc is None else tc
    b = bytearray()
    b.append(0x60 | (tc >> 4))            # version 6 + high nibble of traffic class
    b.append(((tc & 0x0F) << 4) | rnd.randrange(16))  # low tc nibble + high flow
    b += bytes(rnd.randrange(256) for _ in range(2))  # rest of flow label
    b += (rnd.randrange(65536) if plen is None else plen).to_bytes(2, "big")
    b.append(nh)
    b.append(rnd.randrange(256) if hlim is None else hlim)
    b += bytes(rnd.randrange(256) for _ in range(32))
    return bytes(b)


def tcp(rnd, options=b""):
    # Pad options to a 4-byte multiple so the data offset is well formed.
    while len(options) % 4 != 0:
        options += b"\x01"  # NOP pad
    offset = 5 + len(options) // 4
    if offset > 15:
        options = options[: (15 - 5) * 4]
        offset = 15
    b = bytearray()
    b += bytes(rnd.randrange(256) for _ in range(2))   # sport
    b += bytes(rnd.randrange(256) for _ in range(2))   # dport
    b += bytes(rnd.randrange(256) for _ in range(4))   # seq
    b += bytes(rnd.randrange(256) for _ in range(4))   # ack
    b.append((offset << 4) | rnd.randrange(16))        # data offset + reserved bits
    b.append(rnd.randrange(256))                       # flags
    b += bytes(rnd.randrange(256) for _ in range(2))   # window
    b += bytes(2)                                      # checksum
    b += bytes(rnd.randrange(256) for _ in range(2))   # urgent ptr
    b += options
    return bytes(b)


def rand_options(rnd):
    """A random but well-formed TCP option block (may exceed 16 options)."""
    opts = bytearray()
    n = rnd.randrange(0, 22)   # can go past 16 to hit the overwrite quirk
    for _ in range(n):
        kind = rnd.choice([0, 1, 1, 2, 3, 4, 8, rnd.randrange(256)])
        if kind in (0, 1):
            opts.append(kind)
        elif kind == 2:
            opts += bytes([2, 4]) + bytes(rnd.randrange(256) for _ in range(2))
        elif kind == 3:
            opts += bytes([3, 3, rnd.randrange(256)])
        elif kind == 4:
            opts += bytes([4, 2])
        elif kind == 8:
            opts += bytes([8, 10]) + bytes(rnd.randrange(256) for _ in range(8))
        else:
            ln = rnd.choice([2, 3, 4, rnd.randrange(2, 20)])
            opts += bytes([kind, ln]) + bytes(rnd.randrange(256) for _ in range(ln - 2))
        if len(opts) >= 40:
            break
    return bytes(opts[:40])


def icmpv6(rnd):
    t = rnd.choice([1, 2, 3, 4, 128, 129, 133, 134, 135, 136, 137, rnd.randrange(256)])
    lens = {1: 8, 2: 8, 3: 8, 4: 8, 128: 8, 129: 8, 133: 8,
            134: 16, 135: 24, 136: 24, 137: 40}
    total = lens.get(t, 8)
    return bytes([t, rnd.randrange(256), 0, 0]) + bytes(
        rnd.randrange(256) for _ in range(total - 4))


def make_response(rnd, probe):
    """A packet for `probe`, chosen to match the shape that probe would really elicit,
    with a fraction of deliberately odd/truncated packets mixed in."""
    roll = rnd.random()
    if roll < 0.08:
        # Truncated or non-IPv6 garbage: no header found, features stay -1.
        return bytes(rnd.randrange(256) for _ in range(rnd.randrange(1, 40)))
    if probe in ICMP_PROBES and rnd.random() < 0.7:
        body = icmpv6(rnd)
        return ipv6(rnd, 58, plen=len(body), hlim=rnd.choice([None, 60, 62, 250, 255])) + body
    if probe in TCP_PROBES and rnd.random() < 0.85:
        body = tcp(rnd, rand_options(rnd) if rnd.random() < 0.7 else b"")
        return ipv6(rnd, 6, plen=len(body),
                    hlim=rnd.choice([None, 27, 30, 58, 60, 124, 250, 255, 129])) + body
    # An error-report ICMPv6 that quotes an inner packet, or a bare IPv6, etc.
    if rnd.random() < 0.5:
        inner = ipv6(rnd, 6) + tcp(rnd)
        body = bytes([1, 0, 0, 0]) + bytes(4) + inner   # ICMPv6 dest-unreach + quote
        return ipv6(rnd, 58, plen=len(body)) + body
    return ipv6(rnd, rnd.choice([6, 17, 58, 59]), plen=rnd.randrange(65536))


def seq_times(rnd, n):
    """Ascending send times ~100ms apart, as the SEQ battery is really paced."""
    sec = rnd.randrange(1000, 2_000_000_000)
    usec = rnd.randrange(1_000_000)
    out = []
    for _ in range(n):
        out.append((sec, usec))
        usec += rnd.randrange(90_000, 130_000)
        sec += usec // 1_000_000
        usec %= 1_000_000
    return out


def build_case(rnd):
    distance = rnd.choice([-1, 0, 1, 2, 5, 12, rnd.randrange(-1, 40)])
    method = rnd.randrange(0, 5)
    # Choose a subset of probes that responded.
    present = [p for p in ALL_PROBES if rnd.random() < 0.65]
    lines = ["case", f"distance {distance}", f"method {method}"]
    # Give the SEQ probes coherent ascending times so ISR is a meaningful rate;
    # occasionally collapse them to an identical time to exercise the zero-span path.
    seq_present = [p for p in ["S1", "S2", "S3", "S4", "S5", "S6"] if p in present]
    if rnd.random() < 0.1 and seq_present:
        times = [seq_present and (5, 5)] * len(seq_present)
        times = [(5, 5)] * len(seq_present)
    else:
        times = seq_times(rnd, len(seq_present))
    seq_time = dict(zip(seq_present, times))
    for p in present:
        pkt = make_response(rnd, p)
        if p in seq_time:
            sec, usec = seq_time[p]
        else:
            sec, usec = rnd.randrange(0, 2_000_000_000), rnd.randrange(0, 1_000_000)
        lines.append(f"resp {p} {sec} {usec} {pkt.hex()}")
    lines.append("end")
    return "\n".join(lines)


def main():
    rnd = random.Random(SEED)
    out = [f"# generated by gen_fp6_vectorize_cases.py, seed 0x{SEED:X}, {COUNT} cases"]
    for _ in range(COUNT):
        out.append(build_case(rnd))
    sys.stdout.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
