#!/usr/bin/env python3
"""Generate the multi-header packet differential corpus for core::packet_parser.

Emits ../pkt_vectors/<name>.hex for each case below. The filename prefix selects the
C oracle's eth_included flag and the Rust test's start layer:
  - "eth_*"  -> parsed with an Ethernet frame (parse_packet(.., true))
  - "ip_*"   -> parsed starting at the network layer (parse_packet(.., false))

Only chains within the M4-ported header set (eth/arp/ipv4/ipv6/tcp/udp/icmpv4) are
included, so the real C PacketParser and the Rust port must agree byte-for-byte. The
ICMPv6 / IPv6-extension-header divergence is covered by Rust unit tests, not here.

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
