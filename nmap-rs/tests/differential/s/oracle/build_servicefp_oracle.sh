#!/usr/bin/env bash
# Build the service-fingerprint oracle: nmap's real addServiceChar /
# addServiceString / addToServiceFingerprint / getServiceFingerprint, pasted
# verbatim from service_scan.cc:1663-1795 into servicefp_oracle.cc.
#
# Self-contained: those four functions touch only libc, so nothing from the
# service-scan engine, nsock or OpenSSL needs to be linked.
#
#   ./build_servicefp_oracle.sh
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CXX="${CXX:-g++}"
$CXX -O2 -o "$HERE/servicefp_oracle" "$HERE/servicefp_oracle.cc"
echo "built $HERE/servicefp_oracle"
