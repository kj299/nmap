#!/usr/bin/env bash
# Regenerate the scan-classification case matrix and its golden from the C oracle,
# or (with --check) prove the committed golden is exactly what the oracle produces.
#
# The oracle (oracle/classify_oracle.cc) is a line-annotated transcription of
# get_pcap_result's decision branches (scan_engine_raw.cc), ICMPv4 and ICMPv6, and
# set_default_port_state. The cargo test (crates/core/tests/classify_differential.rs)
# compares against the committed golden, so without this a hand-edited golden would
# make the differential agree with a paraphrase. `--check` runs in CI.
#
#   ./regen_classify_golden.sh            # rebuild oracle + regenerate cases and golden
#   ./regen_classify_golden.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CXX="${CXX:-g++}"

$CXX -O2 -Wall "$HERE/oracle/classify_oracle.cc" -o "$HERE/oracle/classify_oracle"
python3 "$HERE/oracle/gen_classify_cases.py"
"$HERE/oracle/classify_oracle" < "$HERE/classify_cases.txt" > "$HERE/classify_golden.txt"
echo "regenerated $(wc -l < "$HERE/classify_cases.txt") classification cases"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(classify_cases.txt classify_golden.txt)
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed classification golden does not match what the C oracle produces" >&2
    exit 1
  fi
  echo "committed golden matches the C oracle"
fi
