#!/usr/bin/env bash
# Rebuild the fp6 vectorize oracle (nmap's real vectorize() linked against libnetutil)
# and regenerate the committed corpus + golden, or (with --check) require the committed
# files to be exactly what the C produces today. CI runs --check so the golden the Rust
# differential compares against can never drift into agreeing with a paraphrase.
#
#   ./regen_fp6_vectorize.sh            # rebuild oracle + regenerate cases and golden
#   ./regen_fp6_vectorize.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORACLE="$HERE/oracle/fp6_vectorize_oracle"

bash "$HERE/oracle/build_fp6_vectorize_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_fp6_vectorize_cases.py" > "$HERE/fp6_vectorize_cases.txt"
"$ORACLE" < "$HERE/fp6_vectorize_cases.txt" > "$HERE/fp6_vectorize_golden.txt"
echo "regenerated $(grep -c '^case' "$HERE/fp6_vectorize_cases.txt") vectorize cases"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(fp6_vectorize_cases.txt fp6_vectorize_golden.txt)
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed fp6 vectorize corpus does not match the C oracle" >&2
    exit 1
  fi
  echo "committed fp6 vectorize corpus matches the C oracle"
fi
