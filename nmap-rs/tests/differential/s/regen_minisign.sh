#!/usr/bin/env bash
# Re-derive the S2 minisign/Ed25519 corpus with OPENSSL and compare it with what
# is committed.
#
#   ./regen_minisign.sh           regenerate corpus, golden and fixtures in place
#   ./regen_minisign.sh --check   FAIL if any of the three differs
#
# The oracle is the OpenSSL CLI, deliberately: every signature the port is asked
# to verify was produced by an unrelated implementation, and the generator
# refuses to emit anything unless OpenSSL first reproduces the RFC 8032 section
# 7.1 test vectors byte for byte. So a green run says "an independent signer's
# output is accepted, and its near-misses are refused", not "we agree with
# ourselves".
#
# Three files are derived, and all three are checked:
#   minisign_cases.txt      the corpus
#   minisign_golden.txt     OpenSSL's verdict and the verdict this port must reach
#   minisign_fixtures.rs    the same signatures as Rust consts, `include!`d by the
#                           unit tests in `core::sigstore::verify` (which run under
#                           Miri, where there is no filesystem)
# Checking the fixtures here is what stops the Miri-visible tests from drifting
# away from the corpus.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMES=(minisign_cases.txt minisign_golden.txt minisign_fixtures.rs)

command -v openssl >/dev/null || { echo "openssl not found" >&2; exit 1; }
openssl list -signature-algorithms 2>/dev/null | grep -q ED25519 || {
  echo "this openssl does not support Ed25519" >&2; exit 1; }

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 "$HERE/oracle/gen_minisign_cases.py" "$WORK" >/dev/null

if [[ "${1:-}" == "--check" ]]; then
  rc=0
  for name in "${NAMES[@]}"; do
    diff -u "$HERE/$name" "$WORK/$name" || rc=1
  done
  if [[ $rc -ne 0 ]]; then
    echo "minisign corpus/golden/fixtures differ from what openssl produces" >&2
    exit 1
  fi
  echo "minisign corpus matches openssl ($(grep -cv '^#' "$HERE/minisign_golden.txt") cases)"
else
  for name in "${NAMES[@]}"; do
    mv "$WORK/$name" "$HERE/$name"
  done
  echo "regenerated $(grep -cv '^#' "$HERE/minisign_golden.txt") cases"
fi
