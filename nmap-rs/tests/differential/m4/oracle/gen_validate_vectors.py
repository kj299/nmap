#!/usr/bin/env python3
"""Generate the receive-validation differential corpus for core::recv_validate.

Emits ../validate_vectors/<name>.hex. Goldens come from validate_oracle (the C-side
transcription of validatepkt/validateTCPhdr). Only the IPv4 path is exercised (the
port's scope); the corpus deliberately stresses the TCP-option walk — the security-
critical, untrusted-input part — with both well-formed and malformed option lists.
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
