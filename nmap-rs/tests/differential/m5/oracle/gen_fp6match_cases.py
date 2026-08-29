#!/usr/bin/env python3
"""Generate the IPv6 response-matching corpus for core::fp6_match::is_response.

Each line is "<sent hex> <rcvd hex>": a battery probe and a candidate response. The C
oracle (nmap's real PacketParser::is_response) labels each pair match/nomatch, and the
Rust port must agree.

The `sent` packets are the real build6 battery for several parameter sets (dumped from
the build6 oracle). For each, we craft:
  * the genuine response nmap would attribute to it (TCP RST/SYN-ACK, echo reply, NA,
    or an ICMPv6 error quoting the probe);
  * near-miss non-responses (mirrored addresses but wrong ports / id / seq / target /
    flag, an error quoting the wrong datagram, a reply from the wrong host).

Determinism: the parameter sets and crafted responses are fixed, so the golden is
reproducible.

  ./gen_fp6match_cases.py                 # regenerates ../fp6match_cases.txt
"""
import os
import subprocess

HERE = os.path.dirname(__file__)
ORACLE = os.path.join(HERE, "build6_oracle")
OUT = os.path.join(HERE, "..", "fp6match_cases.txt")

# Parameter sets fed to the build6 oracle to get real sent probes. Addresses vary so the
# address-mirror check is exercised; all have both ports and are directly connected so the
# whole 17-probe battery is present.
PARAM_SETS = [
    "2001:db8::1 2001:db8::2 22 1 42 33000 34000 305419896 64 4660 1 " + " ".join(str(100+i) for i in range(13)),
    "fe80::1 fe80::dead:beef 443 9 53 40000 41000 1 128 7 1 " + " ".join(str(7000+i) for i in range(13)),
    "::1 2606:4700:4700::1111 80 33333 40125 5000 6000 4294967288 59 65535 1 " + " ".join(str(200+i) for i in range(13)),
]

NH_TCP, NH_UDP, NH_ICMPV6 = 6, 17, 58
FLOW = 0x12345


def ipv6(src, dst, nh, payload):
    vtf = (6 << 28) | (FLOW & 0xFFFFF)
    h = bytearray()
    h += vtf.to_bytes(4, "big")
    h += len(payload).to_bytes(2, "big")
    h += bytes([nh, 64])
    h += src + dst
    return bytes(h) + payload


def tcp(sport, dport, flags=0x14):  # RST+ACK by default
    b = bytearray()
    b += sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
    b += (0).to_bytes(4, "big")  # seq
    b += (0).to_bytes(4, "big")  # ack
    b += bytes([0x50, flags])    # data offset 5, flags
    b += (0).to_bytes(2, "big")  # window
    b += (0).to_bytes(2, "big")  # checksum (is_response ignores it)
    b += (0).to_bytes(2, "big")  # urg
    return bytes(b)


def udp(sport, dport, dlen=0):
    b = bytearray()
    b += sport.to_bytes(2, "big") + dport.to_bytes(2, "big")
    b += (8 + dlen).to_bytes(2, "big")
    b += (0).to_bytes(2, "big")
    b += bytes(dlen)
    return bytes(b)


def icmp6(typ, code, body):
    return bytes([typ, code, 0, 0]) + body


def echo_reply(ident, seq, payload=b""):
    return icmp6(129, 0, ident.to_bytes(2, "big") + seq.to_bytes(2, "big") + payload)


def echo(ident, seq, code=0):
    return icmp6(128, code, ident.to_bytes(2, "big") + seq.to_bytes(2, "big"))


def na(target, solicited=True):
    flags = 0x40 if solicited else 0x00
    return icmp6(136, 0, bytes([flags, 0, 0, 0]) + target)


def icmp6_error(typ, quoted):
    # 4 unused/MTU/pointer bytes, then the quoted datagram.
    return icmp6(typ, 0, bytes(4) + quoted)


def parse_sent(hexstr):
    """Pull the fields a response must mirror out of a build6 probe."""
    p = bytes.fromhex(hexstr)
    src, dst = p[8:24], p[24:40]
    nh = p[6]
    off = 40
    # Skip extension headers (hop-by-hop 0, dstopts 60, routing 43).
    while nh in (0, 60, 43):
        ext_nh = p[off]
        ext_len = (p[off + 1] + 1) * 8
        nh = ext_nh
        off += ext_len
    l4 = p[off:]
    info = {"src": src, "dst": dst, "nh": nh, "raw": p}
    if nh in (NH_TCP, NH_UDP):
        info["sport"] = int.from_bytes(l4[0:2], "big")
        info["dport"] = int.from_bytes(l4[2:4], "big")
    elif nh == NH_ICMPV6:
        info["type"] = l4[0]
        info["code"] = l4[1]
        info["ident"] = int.from_bytes(l4[4:6], "big")
        info["seq"] = int.from_bytes(l4[6:8], "big")
        info["target"] = l4[8:24] if l4[0] == 135 else None
    return info


OTHER_HOST = bytes.fromhex("20010db8" + "00" * 11 + "99")  # 2001:db8::99


def responses_for(info):
    """Yield (rcvd_bytes, expect_match) pairs for one sent probe."""
    src, dst = info["src"], info["dst"]  # probe src/dst (we are src, target is dst)
    mirror = lambda payload, nh=info["nh"]: ipv6(dst, src, nh, payload)

    if info["nh"] == NH_TCP:
        sp, dp = info["sport"], info["dport"]
        yield mirror(tcp(dp, sp), NH_TCP), True                      # mirrored ports
        yield mirror(tcp(sp, dp), NH_TCP), False                     # ports not mirrored
        yield ipv6(OTHER_HOST, src, NH_TCP, tcp(dp, sp)), False      # wrong source host
        # ICMPv6 error quoting our TCP datagram.
        quoted = ipv6(src, dst, NH_TCP, tcp(sp, dp))
        yield mirror(icmp6_error(1, quoted), NH_ICMPV6), True        # dest unreachable
        bad = ipv6(src, dst, NH_TCP, tcp(sp ^ 1, dp))
        yield mirror(icmp6_error(1, bad), NH_ICMPV6), False          # wrong inner port
    elif info["nh"] == NH_UDP:
        sp, dp = info["sport"], info["dport"]
        yield mirror(udp(dp, sp), NH_UDP), True
        yield mirror(udp(sp, dp), NH_UDP), False
        quoted = ipv6(src, dst, NH_UDP, udp(sp, dp))
        yield mirror(icmp6_error(1, quoted), NH_ICMPV6), True
        quoted_bad = ipv6(src, dst, NH_UDP, udp(sp, dp ^ 1))
        yield mirror(icmp6_error(1, quoted_bad), NH_ICMPV6), False
    elif info["nh"] == NH_ICMPV6 and info["type"] == 128:  # echo
        i, s = info["ident"], info["seq"]
        yield mirror(echo_reply(i, s)), True
        yield mirror(echo_reply(i, (s + 1) & 0xFFFF)), False         # wrong seq
        yield mirror(echo_reply((i + 1) & 0xFFFF, s)), False         # wrong id
        yield mirror(echo(i, s)), False                              # reply is another echo, not a reply
        # error quoting our echo
        quoted = ipv6(src, dst, NH_ICMPV6, echo(i, s, code=info["code"]))
        yield mirror(icmp6_error(1, quoted), NH_ICMPV6), True
    elif info["nh"] == NH_ICMPV6 and info["type"] == 135:  # NS
        t = info["target"]
        yield mirror(na(t, solicited=True)), True
        yield mirror(na(t, solicited=False)), False                  # solicited flag clear
        other_target = bytes(t[:15]) + bytes([t[15] ^ 1])
        yield mirror(na(other_target, solicited=True)), False        # wrong target


def main():
    lines = []
    for params in PARAM_SETS:
        out = subprocess.run([ORACLE], input=params + "\n", capture_output=True, text=True).stdout
        for line in out.splitlines():
            if not line.startswith("probe "):
                continue
            _, _pid, hexstr = line.split()
            info = parse_sent(hexstr)
            for rcvd, _expect in responses_for(info):
                lines.append(f"{hexstr} {rcvd.hex()}")

    with open(OUT, "w") as f:
        f.write(f"# generated by gen_fp6match_cases.py, {len(lines)} (sent,rcvd) pairs\n")
        for line in lines:
            f.write(line + "\n")
    print(f"wrote {len(lines)} match cases to {os.path.normpath(OUT)}")


if __name__ == "__main__":
    main()
