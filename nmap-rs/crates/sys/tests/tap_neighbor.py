#!/usr/bin/env python3
"""A scripted IPv6 link behind a TAP interface, for scan6_tap_e2e (IPv6 scans step e).

The kernel need not have IPv6: everything here is Ethernet frames read from and
written to the TAP device, so the scan's own neighbor discovery, framing, capture and
matching all run over a real Ethernet interface. The link holds:

  fd00:6e7::2   a host on the link, answering like Linux: neighbor solicitations,
                SYN/ACK on OPEN_TCP, RST elsewhere (RST to ACK-flagged probes), silence
                to FIN/NULL/Xmas on OPEN_TCP, and ICMPv6 port unreachable on UDP_CLOSED
  fd00:6e7::3   an address nobody answers for, not even a solicitation
  fd00:6e7::fe  a gateway that answers solicitations, with 2001:db8:1::5 behind it,
                which answers as the on-link host does, through the gateway's MAC
  fd00:6e7::fd  a gateway that never answers
  fd00:6e7::fc  a gateway that answers solicitations without its link-layer address,
                so cannot be framed to; 2001:db8:3::5 behind it answers nothing

Probes and solicitations count only from our address, fd00:6e7::1, or SRC when set: a
scan under -S must send both from the spoofed address, as 7.94 does, and take the
replies to it. With EXT=1 every reply carries a destination-options header. A probe framed to any MAC
but its next hop's is counted as misframed. Anything else we send that is not a
solicitation, to an address no host here answers for (the silent one, or one behind
the silent gateway), is counted as stray: 7.94 sends neither. When the run ends (after
SECONDS, or on SIGTERM) a summary line goes to stdout:
"solicited=... replies=... misframed=... stray=...".

Usage: tap_neighbor.py IFACE OPEN_TCP CLOSED_TCP UDP_OPEN UDP_CLOSED SECONDS
"""
import fcntl
import os
import select
import signal
import socket
import struct
import sys
import time

TUNSETIFF = 0x400454CA
IFF_TAP = 0x0002
IFF_NO_PI = 0x1000
SIOCGIFFLAGS = 0x8913
SIOCSIFFLAGS = 0x8914
IFF_UP = 0x1

US = socket.inet_pton(socket.AF_INET6, os.environ.get("SRC") or "fd00:6e7::1")
NEAR = socket.inet_pton(socket.AF_INET6, "fd00:6e7::2")
SILENT = socket.inet_pton(socket.AF_INET6, "fd00:6e7::3")
GW = socket.inet_pton(socket.AF_INET6, "fd00:6e7::fe")
DEAD_GW = socket.inet_pton(socket.AF_INET6, "fd00:6e7::fd")
FAR = socket.inet_pton(socket.AF_INET6, "2001:db8:1::5")
NEAR_MAC = bytes.fromhex("020000000002")
GW_MAC = bytes.fromhex("0200000000fe")
BARE_GW = socket.inet_pton(socket.AF_INET6, "fd00:6e7::fc")
BARE_GW_MAC = bytes.fromhex("0200000000fc")
# Who answers a solicitation, with which MAC.
ADVERTISED = {NEAR: NEAR_MAC, GW: GW_MAC}
# The hosts that answer probes, and the MAC their probes must be framed to.
HOSTS = {NEAR: NEAR_MAC, FAR: GW_MAC}


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    s = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while s >> 16:
        s = (s & 0xFFFF) + (s >> 16)
    return (~s) & 0xFFFF


def l4_sum(src, dst, nh, payload):
    pseudo = src + dst + struct.pack("!IxxxB", len(payload), nh)
    return checksum(pseudo + payload)


def ipv6(src, dst, nh, payload, hlim=64, ext=False):
    chain = b""
    if ext:
        chain = bytes([nh, 0, 1, 4, 0, 0, 0, 0])
        nh = 60
    body = chain + payload
    return struct.pack("!IHBB", 0x60000000, len(body), nh, hlim) + src + dst + body


def main():
    iface, open_tcp, closed_tcp, udp_open, udp_closed, seconds = sys.argv[1:7]
    open_tcp, udp_closed = int(open_tcp), int(udp_closed)
    ext = os.environ.get("EXT") == "1"
    tap = os.open("/dev/net/tun", os.O_RDWR)
    fcntl.ioctl(tap, TUNSETIFF, struct.pack("16sH", iface.encode(), IFF_TAP | IFF_NO_PI))
    ctl = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    flags = struct.unpack("16sH", fcntl.ioctl(ctl, SIOCGIFFLAGS, struct.pack("16sH", iface.encode(), 0)))[1]
    fcntl.ioctl(ctl, SIOCSIFFLAGS, struct.pack("16sH", iface.encode(), flags | IFF_UP))
    print("ready", flush=True)

    stats = {"solicited": 0, "replies": 0, "misframed": 0, "stray": 0}
    stop = [False]
    signal.signal(signal.SIGTERM, lambda *_: stop.__setitem__(0, True))
    end = time.time() + float(seconds)
    while not stop[0] and time.time() < end:
        r, _, _ = select.select([tap], [], [], 0.1)
        if not r:
            continue
        f = os.read(tap, 65535)
        if len(f) < 54 or f[12:14] != b"\x86\xdd":
            continue
        eth_dst, eth_src, ip = f[0:6], f[6:12], f[14:]
        nh, src, dst = ip[6], ip[8:24], ip[24:40]
        l4 = ip[40:]
        if nh == 58 and l4[0] == 135 and len(l4) >= 24:
            target = l4[8:24]
            mac = ADVERTISED.get(target)
            # A solicitation from anyone else (the kernel's own, or ours from the
            # wrong source) goes unanswered.
            if src != US:
                continue
            if target == BARE_GW:
                # An advertisement with no target link-layer address option.
                stats["solicited"] += 1
                body = struct.pack("!BBHI", 136, 0, 0, 0x60000000) + target
                body = body[:2] + struct.pack("!H", l4_sum(target, src, 58, body)) + body[4:]
                os.write(tap, eth_src + BARE_GW_MAC + b"\x86\xdd" + ipv6(target, src, 58, body, hlim=255))
                continue
            if mac is None:
                continue
            stats["solicited"] += 1
            body = struct.pack("!BBHI", 136, 0, 0, 0x60000000) + target + b"\x02\x01" + mac
            body = body[:2] + struct.pack("!H", l4_sum(target, src, 58, body)) + body[4:]
            os.write(tap, eth_src + mac + b"\x86\xdd" + ipv6(target, src, 58, body, hlim=255))
            continue
        # The kernel's own traffic (router solicitations, MLD, from its link-local
        # address) is not ours.
        if src != US:
            continue
        if dst not in HOSTS:
            stats["stray"] += 1
            continue
        # A probe: hop limit 255 (`build6-scan-hop-limit-255`), to a host that answers.
        if ip[7] != 255:
            continue
        if eth_dst != HOSTS[dst]:
            stats["misframed"] += 1
            continue
        mac = HOSTS[dst]
        reply = None
        if nh == 6 and len(l4) >= 20:
            sport, dport, seq, ack, off, flg = struct.unpack("!HHIIBB", l4[:14])
            if flg & 0x04:
                continue
            syn, fin, ackf = flg & 0x02, flg & 0x01, flg & 0x10
            if dport == open_tcp and syn and not ackf:
                rep = (0x12, 1000, (seq + 1) & 0xFFFFFFFF, 65483)
            elif ackf:
                rep = (0x04, ack, 0, 0)
            elif dport == open_tcp:
                continue  # FIN/NULL/Xmas to a listener: silence
            else:
                ln = len(l4) - (off >> 4) * 4 + (1 if syn else 0) + (1 if fin else 0)
                rep = (0x14, 0, (seq + ln) & 0xFFFFFFFF, 0)
            fl, rseq, rack, win = rep
            tcp = struct.pack("!HHIIBBHHH", dport, sport, rseq, rack, 0x50, fl, win, 0, 0)
            tcp = tcp[:16] + struct.pack("!H", l4_sum(dst, src, 6, tcp)) + tcp[18:]
            reply = ipv6(dst, src, 6, tcp, ext=ext)
        elif nh == 17 and len(l4) >= 8:
            dport = struct.unpack("!H", l4[2:4])[0]
            if dport == udp_closed:
                body = struct.pack("!BBHI", 1, 4, 0, 0) + ip
                body = body[:2] + struct.pack("!H", l4_sum(dst, src, 58, body)) + body[4:]
                reply = ipv6(dst, src, 58, body, ext=ext)
        if reply is not None:
            stats["replies"] += 1
            os.write(tap, eth_src + mac + b"\x86\xdd" + reply)
    print(" ".join(f"{k}={v}" for k, v in stats.items()), flush=True)


if __name__ == "__main__":
    main()
