#!/usr/bin/env bash
# Regenerate the packet-walk differential corpus and its golden from the *real* C
# PacketParser, or (with --check) prove the committed golden is exactly what the C
# produces today.
#
# The committed golden is what CI's cargo test compares against, so without this a
# hand-edited golden would make the differential agree with a paraphrase instead of
# with nmap. `--check` runs in CI and fails on any drift.
#
#   ./regen_pkt_golden.sh            # rebuild oracle + regenerate vectors and golden
#   ./regen_pkt_golden.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ORACLE="$HERE/oracle/parse_oracle"

bash "$HERE/oracle/build.sh" >/dev/null
python3 "$HERE/oracle/gen_pkt_vectors.py"
python3 "$HERE/oracle/gen_pkt_random.py"

for f in "$HERE"/pkt_vectors/*.hex; do
  n="$(basename "$f" .hex)"
  case "$n" in eth_*) mode=pkt_eth ;; *) mode=pkt_ip ;; esac
  "$ORACLE" "$mode" < "$f" > "$HERE/pkt_golden/$n.proj"
done
"$ORACLE" pkt_ip_lines < "$HERE/pkt_random_vectors.txt" > "$HERE/pkt_random_golden.txt"
echo "regenerated $(ls "$HERE"/pkt_vectors/*.hex | wc -l) vectors + the random corpus"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(pkt_vectors pkt_golden pkt_random_vectors.txt pkt_random_golden.txt)
  # `git diff` ignores untracked files, so mark any new ones intent-to-add first —
  # otherwise a corpus file that was generated but never committed passes silently.
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed packet-differential corpus does not match what the C oracle produces" >&2
    exit 1
  fi
  echo "committed corpus matches the C oracle"
fi
