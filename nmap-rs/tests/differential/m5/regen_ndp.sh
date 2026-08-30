#!/usr/bin/env bash
# Regenerate the NDP neighbor-discovery differential corpus + golden from nmap's *real*
# FPHost6::build_probe_list(), or (with --check) prove the committed golden is exactly
# what that builder produces today.
#
# The committed golden is what CI's cargo test compares against, so without this a
# hand-edited golden would make the differential agree with a paraphrase instead of with
# nmap. `--check` runs in CI and fails on any drift.
#
#   ./regen_ndp.sh            # rebuild oracle + regenerate cases and golden
#   ./regen_ndp.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORACLE="$HERE/oracle/ndp_oracle"

bash "$HERE/oracle/build_ndp_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_ndp_cases.py"
"$ORACLE" < "$HERE/ndp_cases.txt" > "$HERE/ndp_golden.txt"
echo "regenerated ndp corpus + golden ($(grep -c . "$HERE/ndp_golden.txt") cases)"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(ndp_cases.txt ndp_golden.txt)
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed ndp corpus does not match what the C oracle produces" >&2
    exit 1
  fi
  echo "committed ndp corpus matches the C oracle"
fi
