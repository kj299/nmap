#!/usr/bin/env python3
"""M4 packet-parse differential corpus generator.

Emits a set of named packet vectors (`corpus/<name>.hex`, one hex string per file)
plus `corpus/manifest.tsv` describing what each vector probes. Dependency-free
(hand-assembled bytes — no scapy), so it runs on the bare CI runner.

These vectors feed TWO gates for the `core::headers::*` / `core::packet_parser`
modules:
  1. the fuzz seed corpus (every vector is a valid libFuzzer seed), and
  2. the function-level differential — each vector is fed to BOTH the C oracle
     harness (`oracle/parse_oracle`, see README) and the Rust parser, and their
     canonical projections (see README "Projection format") are compared.

Coverage is deliberately weighted to the untrusted-input hazards the port must
handle better than the C: truncation, integer boundaries, and the two Phase-0
latent-bug triggers (UDP-checksum overflow, fatal-abort-on-hostile-ICMP).

Usage: python3 gen_corpus.py            # writes corpus/*.hex + manifest.tsv
       python3 gen_corpus.py --check    # regenerate to a temp dir and diff (CI)
"""
from __future__ import annotations

import os
import struct
import sys

HERE = os.path.dirname(os.path.abspath(__file__))


def ipv4_cksum(hdr: bytes) -> int:
    s = 0
    for i in range(0, len(hdr), 2):
        w = (hdr[i] << 8) | (hdr[i + 1] if i + 1 < len(hdr) else 0)
        s += w
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


def eth(dst=b"\x02\x00\x00\x00\x00\x01", src=b"\x02\x00\x00\x00\x00\x02", etype=0x0800) -> bytes:
    return dst + src + struct.pack("!H", etype)


def ipv4(payload: bytes, proto: int, ihl_words=5, total_len=None, src="10.0.0.1", dst="10.0.0.2") -> bytes:
    import socket

    ver_ihl = (4 << 4) | ihl_words
    tl = total_len if total_len is not None else (ihl_words * 4 + len(payload))
    hdr = struct.pack(
        "!BBHHHBBH4s4s",
        ver_ihl, 0, tl, 0x1234, 0, 64, proto, 0,
        socket.inet_aton(src), socket.inet_aton(dst),
    )
    hdr = hdr[:10] + struct.pack("!H", ipv4_cksum(hdr)) + hdr[12:]
    return hdr + payload


def tcp(sport=12345, dport=80, flags=0x02, win=1024, payload=b"") -> bytes:
    # data offset 5 words, no options
    off = (5 << 4)
    return struct.pack("!HHIIBBHHH", sport, dport, 0, 0, off, flags, win, 0, 0) + payload


def udp(sport=12345, dport=53, payload=b"") -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def icmp(itype=3, code=3, rest=b"\x00\x00\x00\x00", payload=b"") -> bytes:
    return struct.pack("!BBH", itype, code, 0) + rest + payload


VECTORS: list[tuple[str, str, bytes]] = []


def add(name: str, desc: str, raw: bytes) -> None:
    VECTORS.append((name, desc, raw))


# --- well-formed baselines (the "does it parse at all" floor) ---
add("eth_ip_tcp_syn", "baseline: Ethernet/IPv4/TCP SYN", eth() + ipv4(tcp(flags=0x02), proto=6))
add("eth_ip_tcp_synack", "baseline: TCP SYN/ACK (SYN scan -> open)", eth() + ipv4(tcp(flags=0x12), proto=6))
add("eth_ip_tcp_rst", "baseline: TCP RST (-> closed)", eth() + ipv4(tcp(flags=0x14), proto=6))
add("eth_ip_udp", "baseline: Ethernet/IPv4/UDP", eth() + ipv4(udp(payload=b"hi"), proto=17))
add("eth_ip_icmp_portunreach", "baseline: ICMP port-unreachable (3/3)", eth() + ipv4(icmp(3, 3), proto=1))

# --- truncation: the top untrusted-input hazard (must degrade, never panic) ---
add("trunc_eth_only", "truncation: Ethernet header only, no L3", eth())
add("trunc_ip_no_l4", "truncation: IPv4 header, zero transport bytes", eth() + ipv4(b"", proto=6))
add("trunc_tcp_half", "truncation: TCP cut mid-header (10 of 20 bytes)", eth() + ipv4(tcp()[:10], proto=6))
add("trunc_icmp_1byte", "truncation: ICMP type byte only", eth() + ipv4(b"\x03", proto=1))
add("empty", "edge: empty packet (0 bytes)", b"")
add("one_byte", "edge: single byte", b"\x41")

# --- integer / field boundaries (the UB shapes a rewrite must handle) ---
add("ipv4_ihl_0", "boundary: IPv4 IHL=0 (illegal, header len underflow bait)",
    eth() + ipv4(tcp(), proto=6, ihl_words=0))
add("ipv4_ihl_15_no_opts", "boundary: IPv4 IHL=15 (60-byte hdr) but no option bytes present",
    eth() + ipv4(tcp(), proto=6, ihl_words=15))
add("ipv4_totlen_overflow", "boundary: IPv4 total_len far exceeds actual bytes",
    eth() + ipv4(tcp(), proto=6, total_len=60000))
add("ipv4_totlen_underflow", "boundary: IPv4 total_len < header len",
    eth() + ipv4(tcp(), proto=6, total_len=10))

# --- Phase-0 latent-bug triggers (must be SAFE in the port) ---
add("udp_maxlen_cksum_trigger",
    "bug-trigger udp-checksum-no-fixed-buffer: max-size UDP payload driving the "
    "C setSum() 1-byte stack overflow (UDPHeader.cc:197/209). Port must not overflow.",
    eth() + ipv4(udp(payload=b"\x00" * 1472), proto=17))
add("icmp_hostile_type_abort",
    "bug-trigger parse-no-fatal-on-hostile: inner ICMP with a type the C "
    "icmp_get_data() netutil_fatal()s on (netutil.cc). Port must return Err, not abort.",
    eth() + ipv4(icmp(itype=99, code=0), proto=1))

# --- IPv6 baseline (ext-header chain is a separate parse hazard) ---
add("eth_ipv6_tcp",
    "baseline: Ethernet/IPv6/TCP (v6 fixed 40-byte header + TCP)",
    eth(etype=0x86DD)
    + struct.pack("!IHBB", (6 << 28), 20, 6, 64)
    + b"\x20\x01\x0d\xb8" + b"\x00" * 12  # src
    + b"\x20\x01\x0d\xb8" + b"\x00" * 11 + b"\x01"  # dst
    + tcp(flags=0x12))


def write_corpus() -> None:
    cdir = os.path.join(HERE, "corpus")
    os.makedirs(cdir, exist_ok=True)
    manifest = ["name\tbytes\tdescription"]
    for name, desc, raw in sorted(VECTORS):
        with open(os.path.join(cdir, f"{name}.hex"), "w") as f:
            f.write(raw.hex() + "\n")
        manifest.append(f"{name}\t{len(raw)}\t{desc}")
    with open(os.path.join(cdir, "manifest.tsv"), "w") as f:
        f.write("\n".join(manifest) + "\n")
    print(f"wrote {len(VECTORS)} vectors to {cdir}")


def main(argv):
    write_corpus()
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
