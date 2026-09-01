#!/usr/bin/env bash
# Re-derive the service-fingerprint golden FROM THE C and compare it with what is
# committed.
#
#   ./regen_servicefp.sh           rebuild oracle, regenerate golden in place
#   ./regen_servicefp.sh --check   rebuild and FAIL if the committed golden differs
#
# The --check form runs in CI. Without it the golden could drift into agreeing with
# the port rather than with nmap, which is how a differential quietly stops being
# one (LESSONS: an oracle must copy the C, not restate it).
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GOLDEN="$HERE/servicefp_golden.txt"
CASES="$HERE/servicefp_cases.txt"

bash "$HERE/oracle/build_servicefp_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_servicefp_cases.py" > "$HERE/.servicefp_cases.new"
"$HERE/oracle/servicefp_oracle" < "$HERE/.servicefp_cases.new" > "$HERE/.servicefp_golden.new"

if [[ "${1:-}" == "--check" ]]; then
  rc=0
  diff -u "$CASES" "$HERE/.servicefp_cases.new" || rc=1
  diff -u "$GOLDEN" "$HERE/.servicefp_golden.new" || rc=1
  rm -f "$HERE/.servicefp_cases.new" "$HERE/.servicefp_golden.new"
  if [[ $rc -ne 0 ]]; then
    echo "servicefp corpus/golden differs from what the C produces" >&2
    exit 1
  fi
  echo "servicefp golden matches the C ($(wc -l < "$GOLDEN") cases)"
else
  mv "$HERE/.servicefp_cases.new" "$CASES"
  mv "$HERE/.servicefp_golden.new" "$GOLDEN"
  echo "regenerated $GOLDEN ($(wc -l < "$GOLDEN") cases)"
fi
