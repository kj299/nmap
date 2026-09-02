#!/usr/bin/env bash
# Re-derive the SHA-256 golden from the SYSTEM sha256sum and compare it with what is
# committed.
#
#   ./regen_sha256.sh           regenerate corpus + golden in place
#   ./regen_sha256.sh --check   FAIL if either differs from what is committed
#
# The oracle is GNU coreutils' sha256sum, deliberately: `core::sigstore::digest` is a
# hand-rolled SHA-256, and the only gate worth having on that is agreement with an
# independent, widely-exercised implementation. A second hand-rolled one would prove
# only that the two agree with each other.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CASES="$HERE/sha256_cases.txt"
GOLDEN="$HERE/sha256_golden.txt"

command -v sha256sum >/dev/null || { echo "sha256sum not found" >&2; exit 1; }

python3 "$HERE/oracle/gen_sha256_cases.py" > "$HERE/.sha256_cases.new"

# python3 does the hex->bytes decoding and pipes each case to sha256sum. `xxd` is
# not present on every runner; python3 already is, since the generator needs it.
# The DIGEST still comes from sha256sum -- python only moves the bytes.
python3 - "$HERE/.sha256_cases.new" > "$HERE/.sha256_golden.new" <<'PY'
import subprocess, sys
with open(sys.argv[1]) as f:
    for line in f:
        parts = line.split()
        cid = parts[0]
        data = bytes.fromhex(parts[1]) if len(parts) > 1 else b""
        out = subprocess.run(["sha256sum"], input=data,
                             capture_output=True, check=True).stdout
        print(cid, out.split()[0].decode())
PY

if [[ "${1:-}" == "--check" ]]; then
  rc=0
  diff -u "$CASES" "$HERE/.sha256_cases.new" || rc=1
  diff -u "$GOLDEN" "$HERE/.sha256_golden.new" || rc=1
  rm -f "$HERE/.sha256_cases.new" "$HERE/.sha256_golden.new"
  if [[ $rc -ne 0 ]]; then
    echo "sha256 corpus/golden differs from what sha256sum produces" >&2
    exit 1
  fi
  echo "sha256 golden matches sha256sum ($(wc -l < "$GOLDEN") cases)"
else
  mv "$HERE/.sha256_cases.new" "$CASES"
  mv "$HERE/.sha256_golden.new" "$GOLDEN"
  echo "regenerated $GOLDEN ($(wc -l < "$GOLDEN") cases)"
fi
