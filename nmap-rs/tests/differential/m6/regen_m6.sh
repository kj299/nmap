#!/usr/bin/env bash
# Re-derive the M6.1 corpus with nmap's OWN Lua and compare it with what is
# committed.
#
#   ./regen_m6.sh           regenerate corpus, golden and fixtures in place
#   ./regen_m6.sh --check   FAIL if any of the five differs
#
# The oracle is `liblua/` compiled from this repository, running loading logic
# sliced verbatim out of `nse_main.lua` (see oracle/extract_nse_main.py). Nothing
# about how nmap reads script.db or `.nse` metadata is restated in the harness;
# it is pasted in, and generation fails loudly if upstream moves the anchors.
#
# Five files are derived, and all five are checked:
#   m6_scriptdb_cases.txt    the script.db corpus
#   m6_scriptdb_golden.txt   Lua's verdict and the verdict this port must reach
#   m6_nse_cases.txt         the `.nse` metadata corpus
#   m6_nse_golden.txt        Lua's verdict and the verdict this port must reach
#   m6_fixtures.rs           the same inputs as Rust consts, `include!`d by the
#                            unit tests in `core::nse::script` (which run under
#                            Miri, where there is no filesystem)
# Checking the fixtures here is what stops the Miri-visible tests from drifting
# away from the corpus.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NAMES=(m6_scriptdb_cases.txt m6_scriptdb_golden.txt m6_nse_cases.txt m6_nse_golden.txt m6_fixtures.rs)

bash "$HERE/oracle/build_lua_oracle.sh" >/dev/null

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT
python3 "$HERE/oracle/gen_m6_cases.py" "$WORK" >/dev/null

if [[ "${1:-}" == "--check" ]]; then
  rc=0
  for name in "${NAMES[@]}"; do
    diff -u "$HERE/$name" "$WORK/$name" || rc=1
  done
  if [[ $rc -ne 0 ]]; then
    echo "M6 corpus is stale: re-run tests/differential/m6/regen_m6.sh" >&2
    exit 1
  fi
  echo "M6 corpus matches the oracle."
  exit 0
fi

for name in "${NAMES[@]}"; do cp "$WORK/$name" "$HERE/$name"; done
echo "M6 corpus regenerated."
