#!/usr/bin/env bash
# Build the time-specification oracle (verbatim transcription of nbase_misc.c's
# tval2secs/tval2msecs/tval_unit; see tval_oracle.c for the line map).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-gcc}"
$CC -O2 -Wall "$HERE/tval_oracle.c" -o "$HERE/tval_oracle"
echo "built $HERE/tval_oracle"
