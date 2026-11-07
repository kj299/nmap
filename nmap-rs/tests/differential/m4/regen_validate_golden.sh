#!/usr/bin/env bash
# Regenerate the receive-validation corpus and its golden from the C oracle, or
# (with --check) prove the committed golden is exactly what the C produces today.
#
# The oracle transcribes validatepkt()/validateTCPhdr() from tcpip.cc and compiles
# netutil.cc's own IPv6 extension-header walk (oracle/build_validate_oracle.sh).
# The cargo test (crates/core/tests/validate_differential.rs) compares against the
# committed golden, so without this a hand-edited golden would make the
# differential agree with a paraphrase instead of with nmap. `--check` runs in CI
# and fails on any drift, including a change to netutil.cc's walk.
#
#   ./regen_validate_golden.sh            # rebuild oracle + regenerate vectors and golden
#   ./regen_validate_golden.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORACLE="$HERE/oracle/validate_oracle"

bash "$HERE/oracle/build_validate_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_validate_vectors.py"
python3 "$HERE/oracle/gen_validate_random.py"

for f in "$HERE"/validate_vectors/*.hex; do
  "$ORACLE" < "$f" > "$HERE/validate_golden/$(basename "$f" .hex).proj"
done
# Each random line is `<tag> <hex>`; the oracle reads the hex.
cut -d' ' -f2 "$HERE/validate_random_vectors.txt" | "$ORACLE" lines > "$HERE/validate_random_golden.txt"
echo "regenerated $(ls "$HERE"/validate_vectors/*.hex | wc -l) vectors + the random IPv6 corpus"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(validate_vectors validate_golden validate_random_vectors.txt validate_random_golden.txt)
  # `git diff` ignores untracked files, so mark any new ones intent-to-add first —
  # otherwise a corpus file that was generated but never committed passes silently.
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed receive-validation corpus does not match what the C oracle produces" >&2
    exit 1
  fi
  echo "committed corpus matches the C oracle"
fi
