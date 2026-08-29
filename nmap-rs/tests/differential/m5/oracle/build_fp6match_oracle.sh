#!/usr/bin/env bash
# Build the IPv6 response-matching oracle: nmap's real PacketParser::is_response linked
# against the full libnetutil parser. Mirrors the M4 parse_oracle build.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
M4ORACLE="$(cd "$HERE/../../m4/oracle" && pwd)"
NROOT="$(cd "$HERE/../../../../.." && pwd)"

[ -f "$NROOT/nbase/nbase_config.h" ] || ( cd "$NROOT/nbase" && ./configure >/dev/null )
cp "$M4ORACLE/pcap_stub.h" "$HERE/pcap.h"

INC="-I$HERE -I$M4ORACLE -I$NROOT/libnetutil -I$NROOT/nbase -I$NROOT/libdnet-stripped/include"
CXX="${CXX:-g++}"
OBJ="$HERE/.fp6match_obj"
mkdir -p "$OBJ"

for src in EthernetHeader ARPHeader IPv4Header IPv6Header TCPHeader UDPHeader \
           ICMPv4Header ICMPv6Header PacketElement NetworkLayerElement \
           TransportLayerElement PacketParser HopByHopHeader DestOptsHeader \
           FragmentHeader RoutingHeader RawData; do
  $CXX -DHAVE_CONFIG_H $INC -O2 -c "$NROOT/libnetutil/$src.cc" -o "$OBJ/$src.o"
done
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$M4ORACLE/stubs.cc" -o "$OBJ/stubs.o"
$CXX -DHAVE_CONFIG_H $INC -O2 -c "$HERE/fp6match_oracle.cc" -o "$OBJ/oracle.o"
$CXX "$OBJ"/*.o -o "$HERE/fp6match_oracle"
echo "built $HERE/fp6match_oracle"
