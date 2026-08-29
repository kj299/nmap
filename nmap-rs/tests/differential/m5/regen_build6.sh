#!/usr/bin/env bash
# Regenerate the IPv6 probe-battery differential corpus + golden from nmap's *real*
# FPHost6::build_probe_list(), or (with --check) prove the committed golden is exactly
# what that builder produces today.
#
# The committed golden is what CI's cargo test compares against, so without this a
# hand-edited golden would make the differential agree with a paraphrase instead of with
# nmap. `--check` runs in CI and fails on any drift.
#
#   ./regen_build6.sh            # rebuild oracle + regenerate cases and golden
#   ./regen_build6.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORACLE="$HERE/oracle/build6_oracle"

bash "$HERE/oracle/build_build6_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_build6_cases.py"
"$ORACLE" < "$HERE/build6_cases.txt" > "$HERE/build6_golden.txt"
echo "regenerated build6 corpus + golden ($(grep -c '^probe' "$HERE/build6_golden.txt") probes)"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(build6_cases.txt build6_golden.txt)
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed build6 corpus does not match what the C oracle produces" >&2
    exit 1
  fi
  echo "committed build6 corpus matches the C oracle"
fi
