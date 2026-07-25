#!/usr/bin/env python3
"""Generate TCP-option-block differential cases for `core::osprobe::analyze`.

One hex-encoded TCP segment per line. Deterministic (seeded), so the committed
cases and golden stay in lockstep. Covers nmap's own 13 probe option sets, every
option kind at valid and short lengths, the malformed-length rejections, the
data-offset clamp, and seeded random blobs to catch anything hand cases miss.
"""
import random

# nmap's prbOpts[] — the option blocks it actually puts on the wire, verbatim.
PRB_OPTS = [
    "03030A01020405b4080Affffffff000000000402",
    "020405780303000402080Affffffff0000000000",
    "080Affffffff00000000010103030501020402 80",
    "0402080Affffffff0000000003030A00",
    "020402180402080Affffffff0000000003030A00",
    "020401090402080Affffffff00000000",
    "03030A01020405b404020101",
    "03030A0102040109080Affffffff000000000402",
    "03030f0102040109080Affffffff000000000402",
]

def seg(options: bytes, data_offset=None) -> str:
    s = bytearray(20)
    if data_offset is None:
        data_offset = -(-(20 + len(options)) // 4)
    s[12] = (data_offset & 0xF) << 4
    s += options
    return s.hex()

cases = []

# 1. nmap's own probe option blocks (whitespace in the literals above is cosmetic).
for h in PRB_OPTS:
    cases.append(seg(bytes.fromhex(h.replace(" ", ""))))

# 2. Each option kind on its own, at its correct length.
cases.append(seg(bytes([0])))                       # EOL
cases.append(seg(bytes([1])))                       # NOP
cases.append(seg(bytes([2, 4, 0x05, 0xb4])))        # MSS 1460
cases.append(seg(bytes([2, 4, 0x00, 0x01])))        # MSS 1
cases.append(seg(bytes([2, 4, 0xff, 0xff])))        # MSS 65535
cases.append(seg(bytes([3, 3, 0])))                 # WScale 0
cases.append(seg(bytes([3, 3, 10])))                # WScale 10
cases.append(seg(bytes([3, 3, 255])))               # WScale 255
cases.append(seg(bytes([4, 2])))                    # SACK permitted
for tsval, tsecr in [(0, 0), (1, 0), (0, 1), (0x01020304, 0x05060708)]:
    cases.append(seg(bytes([8, 10]) + tsval.to_bytes(4, "big") + tsecr.to_bytes(4, "big")))

# 3. Short forms of the known options — each sets `valid = false` in the C.
cases.append(seg(bytes([2, 3, 0])))
cases.append(seg(bytes([2, 2])))
cases.append(seg(bytes([3, 2])))
cases.append(seg(bytes([4, 2])))
cases.append(seg(bytes([8, 9] + [0] * 7)))
cases.append(seg(bytes([8, 2])))

# 4. Malformed lengths: below the 2-byte minimum, or past the end.
cases.append(seg(bytes([2, 0, 0, 0])))
cases.append(seg(bytes([2, 1, 0, 0])))
cases.append(seg(bytes([2, 40, 0, 0])))
cases.append(seg(bytes([5])))          # TLV kind with no length byte
cases.append(seg(bytes([255, 255])))

# 5. Unknown kinds, consumed but not encoded.
cases.append(seg(bytes([5, 6, 0xde, 0xad, 0xbe, 0xef, 4, 2])))
cases.append(seg(bytes([1, 5, 2, 0, 0, 4, 2])))
cases.append(seg(bytes([30, 4, 1, 2])))            # MPTCP

# 6. End-of-list followed by more options (the C keeps walking).
cases.append(seg(bytes([0, 1, 4, 2])))
cases.append(seg(bytes([0, 0, 0, 0])))
cases.append(seg(bytes([4, 2, 0, 3, 3, 7])))

# 7. Data-offset edges: no options, below minimum, larger than the capture.
cases.append(seg(b"", data_offset=5))
cases.append(seg(b"", data_offset=4))
cases.append(seg(b"", data_offset=0))
cases.append(seg(bytes([4, 2]), data_offset=15))
cases.append(seg(bytes([4, 2, 1, 1, 3, 3, 7, 0]), data_offset=6))
cases.append(seg(bytes([1] * 40), data_offset=15))

# 8. Truncated segments — shorter than a TCP header.
cases.append("")
cases.append("00" * 19)
cases.append("00" * 12)

# 9. Randomly assembled *well-formed* option sequences. Purely random bytes almost
# never parse, so without these the corpus would be dominated by the error path and
# would barely exercise the encoder itself.
rng = random.Random(0x05B4)

def rand_option():
    kind = rng.choice([0, 1, 2, 3, 4, 8, 5, 30, 254])
    if kind in (0, 1):
        return bytes([kind])
    if kind == 2:
        return bytes([2, 4]) + rng.randrange(0x10000).to_bytes(2, "big")
    if kind == 3:
        return bytes([3, 3, rng.randrange(256)])
    if kind == 4:
        return bytes([4, 2])
    if kind == 8:
        return bytes([8, 10]) + rng.randrange(0x100000000).to_bytes(4, "big") \
                              + rng.randrange(0x100000000).to_bytes(4, "big")
    n = rng.randrange(2, 8)
    return bytes([kind, n]) + bytes(rng.randrange(256) for _ in range(n - 2))

for _ in range(200):
    block = b""
    while True:
        opt = rand_option()
        if len(block) + len(opt) > 40:
            break
        block += opt
    cases.append(seg(block))

# 10. Seeded random blobs, both as option payloads and as whole segments — the
# malformed side, which must be rejected rather than mis-parsed.
for _ in range(120):
    n = rng.randrange(0, 41)
    cases.append(seg(bytes(rng.randrange(256) for _ in range(n))))
for _ in range(60):
    n = rng.randrange(0, 61)
    cases.append(bytes(rng.randrange(256) for _ in range(n)).hex())

with open("tcpopt_cases.txt", "w") as f:
    for c in cases:
        f.write(c + "\n")
print(f"{len(cases)} cases")
