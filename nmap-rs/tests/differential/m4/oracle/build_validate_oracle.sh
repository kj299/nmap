#!/usr/bin/env bash
# Build the receive-validation oracle (self-contained transcription of tcpip.cc's
# static validatepkt()/validateTCPhdr(); see validate_oracle.cc for the line map).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CXX="${CXX:-g++}"
$CXX -O2 -Wall "$HERE/validate_oracle.cc" -o "$HERE/validate_oracle"
echo "built $HERE/validate_oracle"
