#!/usr/bin/env bash
# Build the fp6 vectorize oracle: nmap's real vectorize() (pasted verbatim into
# fp6_vectorize_oracle.cc) linked against the real libnetutil packet parser. Mirrors
# the M4 parse_oracle build — same nbase-config + pcap-stub requirements.
#
#   ./build_fp6_vectorize_oracle.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M4ORACLE="$(cd "$HERE/../../m4/oracle" && pwd)"
NROOT="$(cd "$HERE/../../../../.." && pwd)"   # repo root (nmap/)

[ -f "$NROOT/nbase/nbase_config.h" ] || ( cd "$NROOT/nbase" && ./configure >/dev/null )
# Reuse the M4 oracle's pcap.h stub (netutil.h includes <pcap.h> for opaque decls only).
cp "$M4ORACLE/pcap_stub.h" "$HERE/pcap.h"

INC="-I$HERE -I$M4ORACLE -I$NROOT/libnetutil -I$NROOT/nbase -I$NROOT/libdnet-stripped/include"
CXX="${CXX:-g++}"
OBJ="$HERE/.fp6vec_obj"
mkdir -p "$OBJ"

for src in EthernetHeader ARPHeader IPv4Header IPv6Header TCPHeader UDPHeader \
           ICMPv4Header ICMPv6Header PacketElement NetworkLayerElement \
           TransportLayerElement PacketParser HopByHopHeader DestOptsHeader \
           FragmentHeader RoutingHeader RawData; do
  $CXX -DHAVE_CONFIG_H $INC -O2 -c "$NROOT/libnetutil/$src.cc" -o "$OBJ/$src.o"
done
# The M4 oracle's stubs.cc inert-stubs symbols referenced only by header methods the
# parse path never calls (print, checksum, randomizing setters).
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$M4ORACLE/stubs.cc" -o "$OBJ/stubs.o"
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$HERE/fp6_vectorize_oracle.cc" -o "$OBJ/oracle.o"

$CXX "$OBJ"/*.o -o "$HERE/fp6_vectorize_oracle"
echo "built $HERE/fp6_vectorize_oracle"
