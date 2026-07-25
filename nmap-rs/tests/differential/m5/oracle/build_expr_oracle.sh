#!/usr/bin/env bash
# Build the expr_match oracle (self-contained transcription of osscan.cc's
# expr_match() plus nbase's strchr_p(); see expr_oracle.cc for the line map).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CXX="${CXX:-g++}"
$CXX -O2 -Wall "$HERE/expr_oracle.cc" -o "$HERE/expr_oracle"
echo "built $HERE/expr_oracle"
