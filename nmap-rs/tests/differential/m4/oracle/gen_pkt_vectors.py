#!/usr/bin/env python3
"""Generate the multi-header packet differential corpus for core::packet_parser.

Emits ../pkt_vectors/<name>.hex for each case below. The filename prefix selects the
C oracle's eth_included flag and the Rust test's start layer:
  - "eth_*"  -> parsed with an Ethernet frame (parse_packet(.., true))
  - "ip_*"   -> parsed starting at the network layer (parse_packet(.., false))

Every chain the C PacketParser can walk is in scope — eth/arp/ipv4/ipv6/tcp/udp,
ICMPv4, ICMPv6 and the four IPv6 extension headers — so the real C PacketParser and
the Rust port must agree byte-for-byte on all of them.

After editing, regenerate the golden .proj files with build.sh's recipe.
"""
import os

OUT = os.path.join(os.path.dirname(__file__), "..", "pkt_vectors")


def ipv4(proto, ihl=5, options=b""):
    assert len(options) == (ihl - 5) * 4
    b = bytearray()
    b.append(0x40 | ihl)          # version 4, ihl
    b.append(0x00)                # tos
    b += (0).to_bytes(2, "big")   # total length (parser ignores it)
    b += (0x1234).to_bytes(2, "big")  # id
    b += (0x4000).to_bytes(2, "big")  # flags=DF, frag 0
    b.append(0x40)                # ttl 64
    b.append(proto)               # protocol
    b += (0).to_bytes(2, "big")   # checksum (parser ignores it)
    b += bytes([10, 0, 0, 1])     # src
    b += bytes([10, 0, 0, 2])     # dst
    b += options
    return bytes(b)


def tcp(offset=5, options=b""):
    assert len(options) == (offset - 5) * 4
    b = bytearray()
    b += (0x0050).to_bytes(2, "big")   # sport 80
    b += (0x01BB).to_bytes(2, "big")   # dport 443
    b += (1).to_bytes(4, "big")        # seq
    b += (0).to_bytes(4, "big")        # ack
    b.append(offset << 4)              # data offset, reserved 0
    b.append(0x02)                     # flags = SYN
    b += (0x2000).to_bytes(2, "big")   # window
    b += (0).to_bytes(2, "big")        # checksum
    b += (0).to_bytes(2, "big")        # urgent ptr
    b += options
    return bytes(b)


def udp():
    b = bytearray()
    b += (12345).to_bytes(2, "big")    # sport
    b += (53).to_bytes(2, "big")       # dport
    b += (8).to_bytes(2, "big")        # length
    b += (0).to_bytes(2, "big")        # checksum
    return bytes(b)


def icmpv4(typ, code=0, rest=b"\x00\x00\x00\x00"):
    return bytes([typ, code, 0x00, 0x00]) + rest


def icmpv6(typ, code=0, body=None):
    """An ICMPv6 message of exactly the length its type implies.

    The C's validate() derives the header length from the type alone, so the body is
    padded to that length: too short and the whole walk stops there.
    """
    lens = {1: 8, 2: 8, 3: 8, 4: 8, 128: 8, 129: 8, 133: 8,
            130: 24, 131: 24, 132: 24, 135: 24, 136: 24,
            134: 16, 138: 16, 139: 16, 140: 16, 137: 40}
    total = lens.get(typ, 8)
    b = bytearray([typ, code, 0x00, 0x00])
    b += (body or b"")
    b += bytes(max(0, total - len(b)))
    return bytes(b[:total])


def hopopt(nh, options=b"", kind_len=None):
    """A hop-by-hop / destination-options header, Pad1-padded to an 8-byte multiple."""
    b = bytearray([nh, 0]) + bytearray(options)
    while len(b) % 8 != 0:
        b.append(0x00)  # Pad1
    b[1] = kind_len if kind_len is not None else (len(b) // 8) - 1
    return bytes(b)


def routing(nh, rtype, hdr_ext_len, segleft):
    b = bytearray([nh, hdr_ext_len, rtype, segleft])
    b += bytes(4)
    total = 24 if rtype == 2 else (hdr_ext_len + 1) * 8
    b += bytes(max(0, total - len(b)))
    return bytes(b[:total])


def fragment(nh):
    return bytes([nh, 0x00, 0x00, 0x08, 0x11, 0x22, 0x33, 0x44])


def ipv6(nh):
    b = bytearray()
    b += bytes([0x60, 0x00, 0x00, 0x00])   # version 6, tc/flow 0
    b += (8).to_bytes(2, "big")            # payload length
    b.append(nh)                           # next header
    b.append(0x40)                         # hop limit
    b += bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [1])  # src 2001:db8::1
    b += bytes([0x20, 0x01, 0x0d, 0xb8] + [0] * 11 + [2])  # dst 2001:db8::2
    return bytes(b)


def eth(ethertype):
    return bytes([0x11] * 6) + bytes([0x22] * 6) + ethertype.to_bytes(2, "big")


def arp():
    b = bytearray()
    b += (1).to_bytes(2, "big")        # hardware type = Ethernet
    b += (0x0800).to_bytes(2, "big")   # protocol type = IPv4
    b.append(6)                        # hw addr len
    b.append(4)                        # proto addr len
    b += (1).to_bytes(2, "big")        # opcode = request
    b += bytes([0xaa] * 6)             # sender MAC
    b += bytes([192, 168, 0, 1])       # sender IP
    b += bytes([0x00] * 6)             # target MAC
    b += bytes([192, 168, 0, 2])       # target IP
    return bytes(b)


ETH_IPV4 = 0x0800
ETH_IPV6 = 0x86DD
ETH_ARP = 0x0806
PAYLOAD = bytes([0xde, 0xad, 0xbe, 0xef])

CASES = {
    # Ethernet-framed chains.
    "eth_ipv4_tcp": eth(ETH_IPV4) + ipv4(6) + tcp() + PAYLOAD,
    "eth_ipv4_udp": eth(ETH_IPV4) + ipv4(17) + udp() + PAYLOAD,
    "eth_ipv6_tcp": eth(ETH_IPV6) + ipv6(6) + tcp(),
    "eth_ipv6_udp": eth(ETH_IPV6) + ipv6(17) + udp(),
    "eth_arp": eth(ETH_ARP) + arp(),
    "eth_unknown_ethertype": eth(0x9999) + PAYLOAD,
    "eth_ipv4_in_ipv4_tcp": eth(ETH_IPV4) + ipv4(4) + ipv4(6) + tcp(),
    "eth_truncated_tcp": (eth(ETH_IPV4) + ipv4(6) + tcp())[: 14 + 20 + 10],
    # Network-layer-start chains.
    "ip_ipv4_tcp": ipv4(6) + tcp() + PAYLOAD,
    "ip_ipv4_udp": ipv4(17) + udp() + PAYLOAD,
    "ip_ipv4_icmp_unreach": ipv4(1) + icmpv4(3, 1) + ipv4(17),
    "ip_ipv4_icmp_echo": ipv4(1) + icmpv4(8, 0) + PAYLOAD,
    "ip_ipv6_udp": ipv6(17) + udp(),
    "ip_ipv6_tcp": ipv6(6) + tcp(),
    "ip_bare_arp": arp(),
    # Variable-length headers (options), exercising header_len chaining.
    "ip_ipv4_opts_tcp": ipv4(6, ihl=6, options=b"\x01\x01\x01\x00") + tcp() + PAYLOAD,
    "ip_ipv4_tcp_opts": ipv4(6) + tcp(offset=6, options=b"\x02\x04\x05\xb4") + PAYLOAD,
    # ICMPv6: the type decides the header length, and only the four error reports
    # continue into the quoted IPv6 packet.
    "ip_ipv6_icmp6_echoreply": ipv6(58) + icmpv6(129),
    "ip_ipv6_icmp6_nsolicit": ipv6(58) + icmpv6(135),
    "ip_ipv6_icmp6_redirect": ipv6(58) + icmpv6(137),
    "ip_ipv6_icmp6_unknown_type": ipv6(58) + icmpv6(200) + PAYLOAD,
    "ip_ipv6_icmp6_unreach_quote": ipv6(58) + icmpv6(1) + ipv6(6) + tcp(),
    "ip_ipv6_icmp6_toobig_quote": ipv6(58) + icmpv6(2) + ipv6(17) + udp(),
    # An ICMPv6 header one byte shorter than its type demands: the C rejects it and
    # the remainder becomes raw.
    "ip_ipv6_icmp6_short_for_type": ipv6(58) + icmpv6(135)[:23],
    # IPv6 extension headers, singly and chained.
    "ip_ipv6_hopopt_tcp": ipv6(0) + hopopt(6) + tcp(),
    "ip_ipv6_hopopt_padn_tcp": ipv6(0) + hopopt(6, b"\x01\x04\x00\x00\x00\x00") + tcp(),
    "ip_ipv6_hopopt_routeralert_icmp6": ipv6(0)
    + hopopt(58, b"\x05\x02\x00\x00")
    + icmpv6(129),
    "ip_ipv6_dopts_tcp": ipv6(60) + hopopt(6) + tcp(),
    "ip_ipv6_frag_tcp": ipv6(44) + fragment(6) + tcp(),
    "ip_ipv6_route0_tcp": ipv6(43) + routing(6, 0, 2, 1) + tcp(),
    "ip_ipv6_route2_tcp": ipv6(43) + routing(6, 2, 2, 1) + tcp(),
    # An unknown routing type is accepted only at the 8-byte minimum: nmap's
    # storeRecvData reads Hdr Ext Len after clearing it, so a longer one is rejected.
    "ip_ipv6_route_unknown_type_udp": ipv6(43) + routing(17, 99, 0, 200) + udp(),
    "ip_ipv6_route_unknown_type_long": ipv6(43) + routing(17, 99, 1, 200) + udp(),
    "ip_ipv6_hopopt_frag_dopts_tcp": ipv6(0)
    + hopopt(44)
    + fragment(60)
    + hopopt(6)
    + tcp(),
    "eth_ipv6_hopopt_icmp6": eth(ETH_IPV6) + ipv6(0) + hopopt(58) + icmpv6(128),
    # Extension headers the C rejects: the walk stops and the rest becomes raw.
    "ip_ipv6_hopopt_overlong": ipv6(0) + hopopt(6, kind_len=9) + tcp(),
    "ip_ipv6_hopopt_option_overruns": ipv6(0) + hopopt(6, b"\x01\x28") + tcp(),
    "ip_ipv6_hopopt_bad_fixed_option": ipv6(0) + hopopt(6, b"\x05\x03\x00\x00") + tcp(),
    "ip_ipv6_hopopt_dangling_option_byte": ipv6(0)
    + bytes([6, 0, 0, 0, 0, 0, 0, 0x01])
    + tcp(),
    "ip_ipv6_route0_odd_len": ipv6(43) + routing(6, 0, 1, 0) + tcp(),
    "ip_ipv6_route0_segleft_too_big": ipv6(43) + routing(6, 0, 2, 2) + tcp(),
    "ip_ipv6_route2_wrong_segleft": ipv6(43) + routing(6, 2, 2, 0) + tcp(),
    "ip_ipv6_frag_truncated": ipv6(44) + fragment(6)[:5],
    # SCTP (132) has no ported parser on either side: both must call it raw.
    "ip_ipv6_unknown_proto": ipv6(132) + PAYLOAD,
    # A zero-length packet: the walk must produce no headers at all.
    "ip_empty": b"",
}


def main():
    os.makedirs(OUT, exist_ok=True)
    for name, data in sorted(CASES.items()):
        path = os.path.join(OUT, name + ".hex")
        with open(path, "w") as f:
            f.write(data.hex() + "\n")
    print(f"wrote {len(CASES)} vectors to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
