#!/usr/bin/env bash
# Build the fp6 IPv6 probe-battery oracle: nmap's real FPHost6::build_probe_list() (pasted into
# build6_oracle.cc) linked against the real libnetutil packet parser. Mirrors
# the M4 parse_oracle build — same nbase-config + pcap-stub requirements.
#
#   ./build_build6_oracle.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M4ORACLE="$(cd "$HERE/../../m4/oracle" && pwd)"
NROOT="$(cd "$HERE/../../../../.." && pwd)"   # repo root (nmap/)

[ -f "$NROOT/nbase/nbase_config.h" ] || ( cd "$NROOT/nbase" && ./configure >/dev/null )
# Reuse the M4 oracle's pcap.h stub (netutil.h includes <pcap.h> for opaque decls only).
cp "$M4ORACLE/pcap_stub.h" "$HERE/pcap.h"

INC="-I$HERE -I$M4ORACLE -I$NROOT/libnetutil -I$NROOT/nbase -I$NROOT/libdnet-stripped/include"
CXX="${CXX:-g++}"
OBJ="$HERE/.build6_obj"
mkdir -p "$OBJ"

for src in EthernetHeader ARPHeader IPv4Header IPv6Header TCPHeader UDPHeader \
           ICMPv4Header ICMPv6Header PacketElement NetworkLayerElement \
           TransportLayerElement PacketParser HopByHopHeader DestOptsHeader \
           FragmentHeader RoutingHeader RawData; do
  $CXX -DHAVE_CONFIG_H $INC -O2 -c "$NROOT/libnetutil/$src.cc" -o "$OBJ/$src.o"
done
# build6_stubs.cc is the M4 stubs.cc MINUS its three checksum functions, which return
# zero. A probe BUILDER must compute real checksums — a zero-checksum golden would
# assert a paraphrase of the C rather than the C — so those come from
# checksums_real.cc, which copies nmap's own ipv6/ipv4_pseudoheader_cksum and
# libdnet's ip_cksum_add verbatim.
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$HERE/build6_stubs.cc"    -o "$OBJ/stubs.o"
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$HERE/checksums_real.cc"  -o "$OBJ/cksum.o"
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$HERE/build6_oracle.cc" -o "$OBJ/oracle.o"

$CXX "$OBJ"/*.o -o "$HERE/build6_oracle"
echo "built $HERE/build6_oracle"
