#!/usr/bin/env python3
"""Generate service-fingerprint differential cases.

The corpus deliberately concentrates on the places the C's behaviour is decided by
something other than the obvious rule:

  * the WRAP boundary, which counts the inserted "\\nSF:" bytes as well, so cases
    are shaped to land a continuation inside a multi-byte escape;
  * the NUL rule, whose spelling depends on whether the NEXT byte is an ASCII
    digit -- and on whether that next byte is inside the truncation window;
  * the escape-class ladder, where `strchr("\\\\?\\"[]().*+$^|")` is tested before
    ispunct, so a metacharacter is backslashed and any other punctuation is not;
  * the per-response truncation (900 / 1300) versus the reported length, which is
    the response's TOTAL length even when truncated;
  * the total ceiling (2200 / 10000), compared with `>` not `>=`.

Emitted on stdout in the oracle's line format; the same cases are written as JSON
for the Rust side.
"""
import json
import random
import sys

random.seed(0x5EED)

CASES = []


def case(cid, responses, port=22, proto="TCP", version="7.94",
         platform="x86_64-pc-linux-gnu", intensity=7, ssl=0,
         mon=8, mday=31, time=0x66D3A1B2, debug=0):
    CASES.append({
        "id": cid, "port": port, "proto": proto, "version": version,
        "platform": platform, "intensity": intensity, "ssl": ssl,
        "mon": mon, "mday": mday, "time": time, "debug": debug,
        "responses": [{"probe": p, "bytes": list(b)} for p, b in responses],
    })


# --- the ordinary shape -----------------------------------------------------
case("empty-no-responses", [])
case("simple-ssh", [("NULL", b"SSH-2.0-OpenSSH_8.9p1\r\n")])
case("simple-http", [("GetRequest", b"HTTP/1.1 200 OK\r\nServer: nginx\r\n\r\n")])
case("two-probes", [("NULL", b"hello"), ("GetRequest", b"world")])
case("three-probes", [("NULL", b"a"), ("GenericLines", b"bb"), ("Help", b"ccc")])

# --- every byte value, which walks the whole escape ladder -------------------
case("all-256-bytes", [("NULL", bytes(range(256)))])
case("all-256-reversed", [("NULL", bytes(reversed(range(256))))])

# --- the escape classes individually ----------------------------------------
case("regex-metas", [("NULL", b'\\?"[]().*+$^|')])
case("other-punct", [("NULL", b"!#%&,-/:;<=>@_`{}~'")])
case("whitespace", [("NULL", b"\r\n\t \x0b\x0c")])
case("alnum-only", [("NULL", b"abcXYZ0189")])
case("high-bytes", [("NULL", bytes(range(0x80, 0x90)))])

# --- the NUL rule -----------------------------------------------------------
case("nul-then-digit", [("NULL", b"\x005")])
case("nul-then-alpha", [("NULL", b"\x00a")])
case("nul-at-end", [("NULL", b"abc\x00")])
case("nul-run", [("NULL", b"\x00\x00\x00\x001\x00")])
case("nul-then-each-digit", [("NULL", b"".join(b"\x00" + bytes([d]) for d in range(0x30, 0x3a)))])
# The next byte falls OUTSIDE the truncation window: the C tests
# `srcidx + 1 >= respused`, so the digit after the cut does not count.
case("nul-at-truncation-edge", [("NULL", b"x" * 899 + b"\x00" + b"5" * 10)])

# --- the wrap boundary ------------------------------------------------------
for n in range(60, 96):
    case(f"wrap-len-{n}", [("NULL", b"a" * n)])
# Land a continuation inside a 4-char \xHH escape.
for n in range(60, 84):
    case(f"wrap-escape-{n}", [("NULL", b"a" * n + b"\x01\x02\x03")])
# And inside a 2-char backslash escape.
for n in range(60, 84):
    case(f"wrap-meta-{n}", [("NULL", b"a" * n + b"|||")])

# --- truncation and the reported length -------------------------------------
case("exactly-900", [("NULL", b"z" * 900)])
case("901-truncated", [("NULL", b"z" * 901)])
case("2000-truncated", [("NULL", b"z" * 2000)])
case("exactly-1300-debug", [("NULL", b"z" * 1300)], debug=1)
case("1301-truncated-debug", [("NULL", b"z" * 1301)], debug=1)

# --- the total ceiling ------------------------------------------------------
# The C compares `servicefplen > 2200`, strictly greater, so the boundary is only
# observable when the accumulated length lands EXACTLY on the cap: at 2200 one more
# response is still accepted, at 2201 it is not. A first pass at this corpus used
# round 400-byte responses, never hit the exact value, and a `>` -> `>=` mutation
# survived the differential. Sweeping a range of sizes guarantees some case lands on
# it without having to compute where it lands -- which would mean deriving the
# corpus from the port it is supposed to be checking.
case("over-total-cap", [("P%d" % i, b"y" * 400) for i in range(12)])
case("over-total-cap-debug", [("P%d" % i, b"y" * 400) for i in range(40)], debug=1)
for n in range(100, 320):
    case(f"total-cap-sweep-{n}",
         [("A", b"a" * 900), ("B", b"b" * 900), ("C", b"c" * n), ("D", b"d" * 40)])
for n in range(100, 320):
    case(f"total-cap-sweep-debug-{n}",
         [("A", b"a" * 1300)] * 7 + [("C", b"c" * n), ("D", b"d" * 40)], debug=1)

# --- header variation -------------------------------------------------------
case("udp", [("NULL", b"hi")], proto="UDP", port=53)
case("sctp", [("NULL", b"hi")], proto="SCTP", port=9)
case("ssl-tunnel", [("NULL", b"hi")], ssl=1, port=443)
case("port-max", [("NULL", b"hi")], port=65535)
case("port-min", [("NULL", b"hi")], port=1)
case("intensity-0", [("NULL", b"hi")], intensity=0)
case("intensity-9", [("NULL", b"hi")], intensity=9)
case("localtime-failed", [("NULL", b"hi")], mon=0, mday=0)
case("time-zero", [("NULL", b"hi")], time=0)
case("time-large", [("NULL", b"hi")], time=0x7FFFFFFF)
case("long-version", [("NULL", b"hi")], version="7.94SVN-with-a-long-suffix")
case("long-probe-name", [("ThisIsAVeryLongProbeNameIndeed", b"hi")])

# --- randomised bulk --------------------------------------------------------
for i in range(300):
    nresp = random.randint(1, 4)
    responses = []
    for j in range(nresp):
        n = random.choice([1, 2, 3, 7, 15, 31, 64, 73, 74, 75, 76, 128, 300, 950])
        responses.append((f"P{j}", bytes(random.randrange(256) for _ in range(n))))
    case(f"rand-{i}", responses, port=random.randint(1, 65535),
         proto=random.choice(["TCP", "UDP", "SCTP"]),
         intensity=random.randint(0, 9), ssl=random.randint(0, 1),
         mon=random.randint(0, 12), mday=random.randint(0, 31),
         time=random.randrange(1 << 31), debug=random.randint(0, 1))


def emit_oracle(out):
    for c in CASES:
        out.write("CASE {id} {port} {proto} {version} {platform} {intensity} "
                  "{ssl} {mon} {mday} {time} {debug}\n".format(**c))
        for r in c["responses"]:
            out.write("RESP {} {}\n".format(r["probe"], bytes(r["bytes"]).hex()))
        out.write("FINISH\n")


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "--json":
        json.dump(CASES, sys.stdout)
    else:
        emit_oracle(sys.stdout)
