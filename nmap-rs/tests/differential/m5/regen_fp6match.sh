#!/usr/bin/env bash
# Regenerate the IPv6 response-matching corpus + golden from nmap's real
# PacketParser::is_response, or (with --check) prove the committed golden is exactly what
# that function decides today. Same anti-paraphrase guard as the other M5 goldens.
#
#   ./regen_fp6match.sh
#   ./regen_fp6match.sh --check
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bash "$HERE/oracle/build_build6_oracle.sh" >/dev/null   # gen uses build6_oracle for sent probes
bash "$HERE/oracle/build_fp6match_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_fp6match_cases.py"
"$HERE/oracle/fp6match_oracle" < "$HERE/fp6match_cases.txt" > "$HERE/fp6match_golden.txt"
echo "regenerated fp6match corpus + golden ($(grep -c ' match$' "$HERE/fp6match_golden.txt") matches, $(grep -c ' nomatch$' "$HERE/fp6match_golden.txt") non-matches)"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(fp6match_cases.txt fp6match_golden.txt)
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed fp6match corpus does not match what the C oracle produces" >&2
    exit 1
  fi
  echo "committed fp6match corpus matches the C oracle"
fi
