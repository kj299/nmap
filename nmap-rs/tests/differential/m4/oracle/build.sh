#!/usr/bin/env bash
# Build the M4 IPv4 differential oracle — a harness linking nmap's real
# libnetutil IPv4Header, emitting the canonical projection for a hex packet on
# stdin. Regenerate the committed golden after building:
#
#   ./build.sh
#   for f in ../ipv4_vectors/*.hex; do
#     ./parse_oracle < "$f" > "../ipv4_golden/$(basename "$f" .hex).proj"
#   done
#
# De-risked at Phase 0 (docs/M4-ANALYSIS.md §S-oracle). Three things the standalone
# compile needs that nmap's own build supplies implicitly:
#   1. -DHAVE_CONFIG_H  — nbase.h only includes the generated nbase_config.h under
#      this define; without it nbase re-declares gettimeofday/getopt and clashes
#      with glibc.
#   2. nbase configured  — run `( cd "$NROOT/nbase" && ./configure )` once to
#      generate nbase_config.h (<60s, no extra packages). Gitignored; the C tree
#      stays clean.
#   3. a stub pcap.h     — netutil.h #include <pcap.h> only for opaque pcap_t /
#      pcap_pkthdr *declarations* (the parse path never calls libpcap), so
#      pcap_stub.h (copied to ./pcap.h, first on the include path) satisfies it.
# Symbols referenced only by IPv4Header methods the oracle never calls (print,
# randomizing setters, checksum, option formatting) are inert-stubbed in stubs.cc,
# avoiding a link against netutil.cc + libpcap + libdnet.
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
NROOT="$(cd "$HERE/../../../../.." && pwd)"   # repo root (nmap/)

[ -f "$NROOT/nbase/nbase_config.h" ] || ( cd "$NROOT/nbase" && ./configure >/dev/null )
cp "$HERE/pcap_stub.h" "$HERE/pcap.h"

INC="-I$HERE -I$NROOT/libnetutil -I$NROOT/nbase -I$NROOT/libdnet-stripped/include"
CXX="${CXX:-g++}"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/EthernetHeader.cc"       -o "$HERE/eth.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/ARPHeader.cc"            -o "$HERE/arp.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/IPv4Header.cc"            -o "$HERE/ipv4.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/IPv6Header.cc"            -o "$HERE/ipv6.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/TCPHeader.cc"             -o "$HERE/tcp.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/UDPHeader.cc"             -o "$HERE/udp.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/ICMPv4Header.cc"          -o "$HERE/icmp.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/PacketElement.cc"         -o "$HERE/pe.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/NetworkLayerElement.cc"   -o "$HERE/nle.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/TransportLayerElement.cc" -o "$HERE/tle.o"
# The multi-header PacketParser::parse_packet chains every header class plus the
# ICMPv6 + IPv6 extension-header classes it can dispatch into (project_packet mode).
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/PacketParser.cc"          -o "$HERE/pp.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/ICMPv6Header.cc"          -o "$HERE/icmp6.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/HopByHopHeader.cc"        -o "$HERE/hbh.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/DestOptsHeader.cc"        -o "$HERE/dopts.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/FragmentHeader.cc"        -o "$HERE/frag.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/RoutingHeader.cc"         -o "$HERE/routing.o"
$CXX -DHAVE_CONFIG_H $INC -c "$NROOT/libnetutil/RawData.cc"               -o "$HERE/rawdata.o"
$CXX -DHAVE_CONFIG_H $INC -c "$HERE/stubs.cc"                             -o "$HERE/stubs.o"
$CXX -DHAVE_CONFIG_H $INC -c "$HERE/parse_oracle.cc"                      -o "$HERE/po.o"
$CXX "$HERE"/po.o "$HERE"/eth.o "$HERE"/arp.o "$HERE"/ipv4.o "$HERE"/ipv6.o "$HERE"/tcp.o "$HERE"/udp.o "$HERE"/icmp.o "$HERE"/pp.o "$HERE"/icmp6.o "$HERE"/hbh.o "$HERE"/dopts.o "$HERE"/frag.o "$HERE"/routing.o "$HERE"/rawdata.o "$HERE"/pe.o "$HERE"/nle.o "$HERE"/tle.o "$HERE"/stubs.o -o "$HERE/parse_oracle"
echo "built $HERE/parse_oracle"
