#!/usr/bin/env bash
# Build the IPv6-model oracle.
#
# nmap's generated FPModel.cc includes FingerPrintResults.h, which drags in FPEngine.h,
# nsock and most of the tree. The oracle needs only the numeric tables, so this trims the
# file at load_fp_matches() and substitutes fp6_defs.h for the liblinear/nmap headers.
# The numbers themselves are untouched — this is nmap's own model data, compiled by the
# same toolchain.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SRC="${1:-$HERE/../../../../../FPModel.cc}"
OUT="${2:-$HERE/fp6_oracle}"

if [[ ! -f "$SRC" ]]; then
  echo "FPModel.cc not found at $SRC" >&2
  exit 1
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# Keep everything up to (not including) load_fp_matches(); replace the nmap/liblinear
# includes with the local struct definitions.
LINE="$(grep -n 'load_fp_matches' "$SRC" | head -1 | cut -d: -f1)"
head -n "$((LINE - 1))" "$SRC" \
  | sed 's|#include "FingerPrintResults.h"|#include "fp6_defs.h"|; s|#include "linear.h"||' \
  > "$WORK/fpmodel_data.cc"

g++ -O2 -I"$HERE" -o "$OUT" "$HERE/fp6_oracle.cc" "$WORK/fpmodel_data.cc"
echo "built $OUT"
