#!/usr/bin/env bash
# Build the NDP oracle: nmap's real doND() frame construction and reply validation
# (pasted into ndp_oracle.cc) compiled against the real libdnet packing macros.
#
# Needs nothing but the libdnet headers — doND's frame is built entirely by the
# dnet.h macros, so no libnetutil objects or pcap stubs are required here.
#
#   ./build_ndp_oracle.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NROOT="$(cd "$HERE/../../../../.." && pwd)"   # repo root (nmap/)

CXX="${CXX:-g++}"
$CXX -I"$NROOT/libdnet-stripped/include" -O2 -o "$HERE/ndp_oracle" "$HERE/ndp_oracle.cc"
echo "built $HERE/ndp_oracle"

# --demo also builds the ASAN witness for the reply-path overread (not a CI gate;
# see DIVERGENCES.md `ndp-advert-target-read-past-capture`).
if [[ "${1:-}" == "--demo" ]]; then
  $CXX -I"$NROOT/libdnet-stripped/include" -g -O0 -fsanitize=address \
       -o "$HERE/ndp_oob_demo" "$HERE/ndp_oob_demo.cc"
  echo "built $HERE/ndp_oob_demo"
fi
