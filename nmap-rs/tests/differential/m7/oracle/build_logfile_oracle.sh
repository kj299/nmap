#!/usr/bin/env bash
# Build the output-filename oracle (verbatim transcription of output.cc's
# logfilename; see logfile_oracle.c for the line map).
set -euo pipefail
HERE="$(cd "$(dirname "$0")" && pwd)"
CC="${CC:-gcc}"
$CC -O2 -Wall "$HERE/logfile_oracle.c" -o "$HERE/logfile_oracle"
echo "built $HERE/logfile_oracle"
