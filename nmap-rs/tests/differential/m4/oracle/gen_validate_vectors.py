#!/usr/bin/env python3
"""Generate the receive-validation differential corpus for core::recv_validate.

Emits ../validate_vectors/<name>.hex. Goldens come from validate_oracle (the C-side
transcription of validatepkt/validateTCPhdr, with netutil.cc's own IPv6 walk). The
IPv4 cases stress the TCP-option walk — the security-critical, untrusted-input part —
with both well-formed and malformed option lists. The v6_* cases cover each extension
header, each fragment shape and each way a chain can run out; gen_validate_random.py
adds the randomised IPv6 chains.

Five v6_* cases are where the port fixes the C rather than following it
(docs/IPV6-SCAN-ANALYSIS.md D3, Q4). Their goldens are still the C's; the
differential test pins what the port answers instead, next to the ledger id:
  v6_frag_later_tcp, v6_frag_later_udp, v6_frag_reserved_tcp
      recv-validate6-non-initial-fragment
  v6_hop_tcp_trailer_untrimmed, v6_hop_tcp_trailer_short
      recv-validate6-trailer-trim
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "validate_vectors")


def ip(proto, payload, ihl=5, total_len=None, frag_off=0, opts=b""):
    assert len(opts) == (ihl - 5) * 4
    if total_len is None:
        total_len = ihl * 4 + len(payload)
    b = bytearray()
    b.append(0x40 | ihl)
    b.append(0x00)
    b += total_len.to_bytes(2, "big")
    b += (0x1234).to_bytes(2, "big")
    b += frag_off.to_bytes(2, "big")  # flags/frag
    b.append(0x40)
    b.append(proto)
    b += (0).to_bytes(2, "big")
    b += bytes([10, 0, 0, 1])
    b += bytes([10, 0, 0, 2])
    b += opts
    b += payload
    return bytes(b)


def tcp(off_words, options=b"", payload=b""):
    assert len(options) == (off_words - 5) * 4
    b = bytearray()
    b += (0x0050).to_bytes(2, "big")
    b += (0x01BB).to_bytes(2, "big")
    b += (1).to_bytes(4, "big")
    b += (0).to_bytes(4, "big")
    b.append(off_words << 4)
    b.append(0x10)
    b += (0x2000).to_bytes(2, "big")
    b += (0).to_bytes(2, "big")
    b += (0).to_bytes(2, "big")
    b += options
    b += payload
    return bytes(b)


def udp(payload=b""):
    b = bytearray()
    b += (12345).to_bytes(2, "big")
    b += (53).to_bytes(2, "big")
    b += (8 + len(payload)).to_bytes(2, "big")
    b += (0).to_bytes(2, "big")
    b += payload
    return bytes(b)


def ipv6(first_nxt, body, plen=None):
    """An IPv6 header (payload length from `plen`, or the body's own), then body."""
    if plen is None:
        plen = len(body)
    b = bytearray([0x60, 0x00, 0x00, 0x00])
    b += plen.to_bytes(2, "big")
    b.append(first_nxt)
    b.append(64)
    b += bytes.fromhex("20010db8000000000000000000000001")
    b += bytes.fromhex("20010db8000000000000000000000002")
    b += body
    return bytes(b)


def ext(nxt, units, fill=0x00):
    """A hop-by-hop / destination-options / routing header of `units` * 8 bytes."""
    h = bytearray([fill]) * (units * 8)
    h[0] = nxt
    h[1] = units - 1
    return bytes(h)


def frag(nxt, offset, more, reserved=0):
    """A fragment header: offset in 8-byte units, `more` the M flag."""
    return bytes([nxt, reserved]) + ((offset << 3) | more).to_bytes(2, "big") + b"\x00\x00\x12\x34"


def icmpv6(type_, code=0, body=b"\x00\x01\x00\x01"):
    return bytes([type_, code]) + b"\x00\x00" + body


CASES = {
    # --- accepted ---
    "tcp_plain": ip(6, tcp(5)),
    "tcp_mss": ip(6, tcp(6, b"\x02\x04\x05\xb4"), ihl=5, opts=b""),
    "tcp_mss_sackok_nop_wscale": ip(6, tcp(8, b"\x02\x04\x05\xb4\x04\x02\x01\x03\x03\x07\x00\x00")),
    "tcp_timestamp": ip(6, tcp(8, b"\x08\x0a" + b"\x00" * 8 + b"\x01\x00")),
    "tcp_sack_1block": ip(6, tcp(8, b"\x05\x0a" + b"\x00" * 8 + b"\x01\x01")),
    "udp_plain": ip(17, udp(b"hi")),
    "tcp_with_crc_trailer": ip(6, tcp(5)) + b"\xde\xad\xbe\xef",  # caplen must trim
    "tcp_payload": ip(6, tcp(5, b"", b"GET / HTTP/1.0\r\n")),
    "proto_icmp_passthrough": ip(1, b"\x08\x00\x00\x00\x00\x00\x00\x00"),
    # --- rejected ---
    "reject_fragment": ip(6, tcp(5), frag_off=0x0002),  # offset field nonzero
    "reject_short": bytes.fromhex("450000"),  # < 20 bytes
    "reject_bad_ihl": bytearray(ip(6, tcp(5))),  # ihl patched below
    "reject_mss_badlen": ip(6, tcp(6, b"\x02\x03\x05\xb4")),  # MSS length byte 3
    "reject_opt_overrun": ip(6, tcp(6, b"\x08\x0a\x00\x00")),  # TS claims 10, has 4
    "reject_sack_badblock": ip(6, tcp(7, b"\x05\x06\x00\x00\x00\x00\x00\x00")),  # (6-2)%8
    "reject_zero_len_opt": ip(6, tcp(6, b"\x09\x00\x00\x00")),  # length byte 0
    "reject_tcp_incomplete": ip(6, b"\x00\x50\x01\xbb\x00\x00\x00\x01\x00\x00"),  # 10 bytes
    "reject_udp_incomplete": ip(17, b"\x00\x00\x00\x00"),  # 4 bytes
    "reject_bad_version": b"\x75" + ip(6, tcp(5))[1:],  # version 7
    # --- IPv6, accepted ---
    "v6_tcp_plain": ipv6(6, tcp(5)),
    "v6_tcp_options": ipv6(6, tcp(8, b"\x02\x04\x05\xa0\x04\x02\x01\x03\x03\x07\x00\x00")),
    "v6_udp_plain": ipv6(17, udp(b"hi")),
    "v6_icmpv6_echo_reply": ipv6(58, icmpv6(129)),
    "v6_icmp_passthrough": ipv6(1, b"\x08\x00\x00\x00\x00\x00\x00\x00"),
    "v6_sctp_passthrough": ipv6(132, b"\x00\x50\x01\xbb" + b"\x00" * 8),
    "v6_nonext": ipv6(59, b"\x00" * 8),
    "v6_hop_tcp": ipv6(0, ext(6, 1) + tcp(5)),
    "v6_dst_udp": ipv6(60, ext(17, 2) + udp(b"x")),
    "v6_routing_tcp": ipv6(43, ext(6, 3, fill=0xAB) + tcp(6, b"\x02\x04\x05\xa0")),
    "v6_chain_hop_dst_rt_dst_tcp": ipv6(0, ext(60, 1) + ext(43, 2) + ext(60, 1) + ext(6, 1) + tcp(5)),
    "v6_frag_first_tcp": ipv6(44, frag(6, 0, 1) + tcp(5, b"", b"segment")),
    "v6_frag_atomic_udp": ipv6(44, frag(17, 0, 0) + udp(b"ok")),
    "v6_hop_frag_first_icmpv6": ipv6(0, ext(44, 1) + frag(58, 0, 1) + icmpv6(1, 4, b"\x00" * 44)),
    "v6_tcp_trailer": ipv6(6, tcp(5)) + b"\xde\xad\xbe\xef",  # no ext headers: trims to 60
    "v6_tcp_plen_over": ipv6(6, tcp(5), plen=1000),  # claims more than captured
    "v6_tcp_plen_under_hdr": ipv6(6, tcp(5), plen=0),  # trims to the header alone
    # --- IPv6, rejected ---
    "v6_short": ipv6(6, b"")[:39],
    "v6_header_only": ipv6(6, b""),  # nothing follows the header
    "v6_nonext_empty": ipv6(59, b""),
    "v6_ext_truncated": ipv6(0, b"\x06\x00\x00\x00"),  # under 8 bytes left
    "v6_ext_overrun": ipv6(60, bytes([6, 9]) + b"\x00" * 6 + tcp(5)),  # claims 80
    "v6_chain_ends_at_end": ipv6(60, ext(6, 1)),
    "v6_chain_ends_in_ext": ipv6(0, ext(60, 1) + ext(43, 1)),  # next says routing, no bytes
    "v6_unknown_esp": ipv6(50, b"\x00" * 24),
    "v6_unknown_ah_after_hop": ipv6(0, ext(51, 1) + b"\x00" * 24),
    "v6_unknown_ipv6_in_ipv6": ipv6(41, ipv6(6, tcp(5))),
    "v6_tcp_incomplete": ipv6(6, tcp(5)[:10]),
    "v6_udp_incomplete": ipv6(17, b"\x00" * 4),
    "v6_tcp_bad_mss": ipv6(60, ext(6, 1) + tcp(6, b"\x02\x05\x05\xb4")),
    "v6_frag_first_tcp_short": ipv6(44, frag(6, 0, 1) + tcp(5)[:12]),
    # --- IPv6, where the port fixes the C (pinned in the differential test) ---
    # A later fragment: the C walks it and reads mid-segment bytes as the header.
    "v6_frag_later_tcp": ipv6(44, frag(6, 185, 0) + tcp(5, b"", b"rest of segment")),
    "v6_frag_later_udp": ipv6(44, frag(17, 1, 1) + b"\x00" * 16),
    # A first fragment whose reserved byte is 2: the C skips 24 bytes, into the TCP
    # header, and reads 24 bytes from there as one (its data offset lands on payload
    # byte 8).
    "v6_frag_reserved_tcp": ipv6(44, frag(6, 0, 1, reserved=2) + tcp(5, b"", bytes(8) + b"\x50" + bytes(11))),
    # Extension headers and a 6-byte link-layer trailer: the C compares the
    # upper-layer bytes (26) with ip6_plen (36, which counts the hop-by-hop header)
    # and trims nothing.
    "v6_hop_tcp_trailer_untrimmed": ipv6(0, ext(6, 2) + tcp(5), plen=36) + b"\xee" * 6,
    # A 12-byte trailer behind an 8-byte header: the C trims 4 of it.
    "v6_hop_tcp_trailer_short": ipv6(0, ext(6, 1) + tcp(5), plen=28) + b"\xee" * 12,
}


def main():
    os.makedirs(OUT, exist_ok=True)
    cases = dict(CASES)
    # Patch reject_bad_ihl: set IHL to 4 (below the 5-word minimum).
    bad = bytearray(cases["reject_bad_ihl"])
    bad[0] = 0x44
    cases["reject_bad_ihl"] = bytes(bad)
    for name, data in sorted(cases.items()):
        with open(os.path.join(OUT, name + ".hex"), "w") as f:
            f.write(bytes(data).hex() + "\n")
    print(f"wrote {len(cases)} vectors to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
