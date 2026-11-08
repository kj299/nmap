#!/usr/bin/env python3
"""Generate the IPv6 scan-probe differential cases (IPv6 scans step c).

Writes ../scanprobe6_cases.txt; scanprobe6_oracle turns it into the golden, one
packet per line, through nmap's own build_tcp_raw_ipv6 / build_udp_raw_ipv6.

- `probe` cases: every scan type the port has (SYN, ACK, Window, Maimon, FIN, Null,
  Xmas, UDP) through sendIPScanProbe's argument choices, over the hop limit (o.ttl
  unset, i.e. -1, and set), attempt numbers, sequence masks, `--data` payloads,
  UDP payloads and `--badsum`.
- `tcp` / `udp` cases: the builders themselves over random fields, options and
  data. The window is never 0 and a SYN's sequence never 0: there the C invents a
  value (1024, a random ISN) where the port takes the one it is given
  (`build-explicit-fields-no-magic`).
- `--badsum` on UDP where it matters: valid checksums 0x0100, whose decrement in
  host order (build-badsum-host-order-decrement) is 0, which the C sends as 0xFFFF;
  and 0x0001, which a little-endian C sends as 0xFF00.

Deterministic: a fixed seed.
"""
import os
import random

OUT = os.path.join(os.path.dirname(__file__), "..", "scanprobe6_cases.txt")
SEED = 0x6C5CA9E5

SRC = "20010db8000000000000000000000001"
DST = "20010db8000000000000000000000002"
LINK_SRC = "fe800000000000000211223344556677"
LOOP = "00000000000000000000000000000001"
SCANS = ["syn", "ack", "window", "maimon", "fin", "null", "xmas", "udp"]

# Payloads a UDP scan really sends (nmap-payloads' DNS status request, an NTP
# client request, an SNMPv1 get), and --data of a few sizes.
DNS = "000010000000000000000000"
NTP = "e30004fa000100000001000000000000000000000000000000000000000000000000000000000000000000c54f234b71b152f3"
SNMP = "3082002f02010004067075626c6963a082002002044c33a756020100020100308200103082000c06082b060102010105000500"


def hexbytes(rnd, n):
    return "".join(f"{rnd.randrange(256):02x}" for _ in range(n)) or "-"


def addr(rnd):
    return "".join(f"{rnd.randrange(256):02x}" for _ in range(16))


def cksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(int.from_bytes(data[i:i + 2], "big") for i in range(0, len(data), 2))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def udp6_sum(src, dst, sport, dport, payload):
    seg = sport.to_bytes(2, "big") + dport.to_bytes(2, "big") + (8 + len(payload)).to_bytes(2, "big") + b"\0\0" + payload
    pseudo = bytes.fromhex(src) + bytes.fromhex(dst) + len(seg).to_bytes(4, "big") + b"\0\0\0\x11"
    return cksum(pseudo + seg)


def main():
    rnd = random.Random(SEED)
    out = []
    # --- probes: a grid over what the scan engine varies ---
    for scan in SCANS:
        for ttl in (-1, 0, 1, 64, 254, 255):
            for tryno in (0, 2, 4, 22):
                for seqmask in (0xABCD1234, 1, 0xFFFFFFFF):
                    data = "-"
                    if scan == "udp":
                        data = [DNS, NTP, SNMP, "-"][tryno % 4]
                    out.append(f"probe {scan} {SRC} {DST} {ttl} 40000 {[22, 53, 161, 443][tryno % 4]} {tryno} {seqmask} {data} 0")
        for data in ("41", hexbytes(rnd, 20), hexbytes(rnd, 1400)):
            for bad in (0, 1):
                out.append(f"probe {scan} {LINK_SRC} {DST} -1 65530 65535 10 {rnd.randrange(1 << 32)} {data} {bad}")
        out.append(f"probe {scan} {LOOP} {LOOP} -1 1 1 0 {rnd.randrange(1 << 32)} - 1")
    # --- probes: random ---
    for _ in range(600):
        scan = rnd.choice(SCANS)
        ttl = rnd.choice([-1, -1, rnd.randrange(256)])
        tryno = rnd.randrange(0, 128) * 2
        data = rnd.choice(["-", "-", hexbytes(rnd, rnd.randrange(1, 64)), DNS, SNMP])
        out.append(f"probe {scan} {addr(rnd)} {addr(rnd)} {ttl} {rnd.randrange(1, 65536)} {rnd.randrange(65536)} {tryno} {rnd.randrange(1 << 32)} {data} {rnd.randrange(2)}")
    # --- the builders over random fields ---
    for _ in range(600):
        flags = rnd.randrange(256)
        seq = rnd.randrange(1, 1 << 32) if flags & 0x02 or rnd.random() < 0.8 else 0
        opts = hexbytes(rnd, 4 * rnd.randrange(0, 11))
        data = hexbytes(rnd, rnd.choice([0, 0, 1, 7, 33, rnd.randrange(1, 600)]))
        flow = rnd.choice([0, rnd.randrange(1 << 20), rnd.randrange(1 << 32)])
        out.append(
            f"tcp {addr(rnd)} {addr(rnd)} {rnd.randrange(256)} {flow} {rnd.randrange(256)} "
            f"{rnd.randrange(65536)} {rnd.randrange(65536)} {seq} {rnd.randrange(1 << 32)} "
            f"{rnd.randrange(256)} {flags} {rnd.randrange(1, 65536)} {rnd.randrange(65536)} "
            f"{opts} {data} {rnd.randrange(2)}")
    for _ in range(300):
        data = hexbytes(rnd, rnd.choice([0, 0, 1, 2, 8, 31, rnd.randrange(1, 1500)]))
        out.append(
            f"udp {addr(rnd)} {addr(rnd)} {rnd.randrange(256)} {rnd.randrange(1 << 32)} "
            f"{rnd.randrange(256)} {rnd.randrange(65536)} {rnd.randrange(65536)} {data} {rnd.randrange(2)}")
    # --- --badsum where the valid UDP checksum is 1 ---
    found = 0
    for dport, want in ((53, 0x0100), (161, 0x0100), (53, 0x0001), (161, 0x0001)):
        for n in range(1 << 16):
            payload = n.to_bytes(2, "big")
            if udp6_sum(SRC, DST, 40000, dport, payload) == want:
                out.append(f"udp {SRC} {DST} 0 0 255 40000 {dport} {payload.hex()} 1")
                out.append(f"udp {SRC} {DST} 0 0 255 40000 {dport} {payload.hex()} 0")
                found += 1
                break
    assert found == 4
    with open(OUT, "w") as f:
        f.write("\n".join(out) + "\n")
    print(f"wrote {len(out)} cases to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
