#!/usr/bin/env python3
"""Generate the NDP differential corpus.

Two case kinds, both fed to `ndp_oracle`:

  ns <src_mac> <src_ip> <target>   -> the solicitation frame doND() transmits
  na <offset> <frame>              -> the verdict its reply path reaches

DEFINED DOMAIN FOR `na` CASES. `accept_ns()` admits a capture holding only
offset+IP6_HDR_LEN+ICMPV6_HDR_LEN (= offset+44) bytes, but `read_ns_reply_pcap()`
then reads the 16-byte target at offset+48..offset+64 unconditionally. So the C is
well-defined only outside the gap:

  * caplen <  offset+44                       -> accept_ns rejects            (defined)
  * type != 136 or code != 0                  -> accept_ns rejects            (defined)
  * caplen >= offset+64, type 136, code 0     -> target read is in bounds     (defined)
  * caplen in [offset+44, offset+64), type 136, code 0  -> READS PAST THE CAPTURE

The last row is nmap's out-of-bounds read. There is no behavior to record for it, so
this generator emits none: the Rust rejects every frame in that gap, which is pinned
by `ndp::tests::truncated_advertisement_is_never_read_past_the_end` and by the
`ndp_advert` fuzz target, and ledgered in DIVERGENCES.md.
"""
import os

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "ndp_cases.txt")

ETH, IP6, ICMP6 = 14, 40, 4
NA, NS = 136, 135


def h(b):
    # `-` denotes the empty capture: an empty field would be indistinguishable
    # from a missing one in the whitespace-separated case format.
    return b.hex() if b else "-"


def ns_cases():
    macs = [
        bytes.fromhex("000c291a2b3c"),
        bytes.fromhex("000000000000"),
        bytes.fromhex("ffffffffffff"),
        bytes.fromhex("0250f2000001"),
    ]
    srcs = [
        bytes.fromhex("fe800000000000000" "20c29fffe1a2b3c"),
        bytes.fromhex("20010db8000000000000000000000001"),
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("ffffffffffffffffffffffffffffffff"),
    ]
    # Targets chosen to exercise the low-3-byte multicast derivation, including the
    # boundary bytes the prefix overwrite stops at.
    tgts = [
        bytes.fromhex("20010db8000000000000000000adbeef"),
        bytes.fromhex("fe80000000000000021122fffe334455"),
        bytes.fromhex("00000000000000000000000000000000"),
        bytes.fromhex("ffffffffffffffffffffffffffffffff"),
        bytes.fromhex("2001000000000000000000000000ff01"),
        bytes.fromhex("20010db800000000000000000000ffff"),
    ]
    out = []
    for i, t in enumerate(tgts):
        for j, m in enumerate(macs):
            s = srcs[(i + j) % len(srcs)]
            out.append(f"ns {h(m)} {h(s)} {h(t)}")
    return out


def frame(offset, icmp_type=NA, code=0, target=None, opt=None, trunc=None):
    """Build a capture: `offset` bytes of datalink header, an IPv6 header, then the
    ICMPv6 advertisement."""
    if target is None:
        target = bytes.fromhex("20010db8000000000000000000adbeef")
    b = bytearray(offset)
    if offset >= 14:
        b[12:14] = b"\x86\xdd"
    ip6 = bytearray(IP6)
    ip6[0] = 0x60
    ip6[4:6] = (24).to_bytes(2, "big")
    ip6[6] = 58
    ip6[7] = 255
    b += ip6
    b += bytes([icmp_type, code, 0, 0])  # type, code, checksum
    b += b"\x60\x00\x00\x00"  # flags: solicited + override
    b += target
    if opt is not None:
        b += opt
    if trunc is not None:
        b = b[:trunc]
    return bytes(b)


def na_cases():
    tlla = bytes([2, 1]) + bytes.fromhex("aabbccddeeff")
    out = []
    for offset in (14, 0, 16):
        base = offset + IP6 + ICMP6
        # Complete advertisement, with and without the target link-layer option.
        out.append(f"na {offset} {h(frame(offset, opt=tlla))}")
        out.append(f"na {offset} {h(frame(offset))}")
        # Option present but not a 6-byte Ethernet address: type or length wrong.
        for bad in (bytes([1, 1]) + bytes.fromhex("aabbccddeeff"),
                    bytes([2, 2]) + bytes.fromhex("aabbccddeeff"),
                    bytes([2, 1]) + bytes.fromhex("000000000000"),
                    bytes([0, 0]) + bytes.fromhex("aabbccddeeff")):
            out.append(f"na {offset} {h(frame(offset, opt=bad))}")
        # Not an advertisement: wrong type, or a non-zero code. Rejected by accept_ns
        # before anything is read, so these are defined at any length.
        out.append(f"na {offset} {h(frame(offset, icmp_type=NS, opt=tlla))}")
        out.append(f"na {offset} {h(frame(offset, icmp_type=1, opt=tlla))}")
        out.append(f"na {offset} {h(frame(offset, code=3, opt=tlla))}")
        # Below accept_ns's own threshold — rejected without reading further.
        for n in (0, offset, base - 1):
            if n >= 0:
                out.append(f"na {offset} {h(frame(offset, opt=tlla, trunc=n))}")
        # At and just past the point where the target read becomes in-bounds. Lengths
        # in [base, base+20) are the C's out-of-bounds gap and are deliberately absent.
        for n in (base + 20, base + 21, base + 27, base + 28):
            out.append(f"na {offset} {h(frame(offset, opt=tlla, trunc=n))}")
        # Varied target addresses.
        for t in (bytes(16), bytes.fromhex("ff" * 16),
                  bytes.fromhex("fe80000000000000021122fffe334455")):
            out.append(f"na {offset} {h(frame(offset, target=t, opt=tlla))}")
    return out


def main():
    lines = ["# Generated by gen_ndp_cases.py -- do not edit by hand."]
    lines += ns_cases()
    lines += na_cases()
    with open(OUT, "w") as f:
        f.write("\n".join(lines) + "\n")
    print(f"wrote {len(lines) - 1} cases to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
