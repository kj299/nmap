#!/usr/bin/env bash
# Re-derive the M6.6 LPeg corpus (step 0b) with this tree's OWN Lua and LPeg,
# and compare it with what is committed.
#
#   ./regen_m66_lpeg.sh               regenerate the cases, golden and step map in place,
#                                     and check nmap 7.94 against them (needs nmap)
#   ./regen_m66_lpeg.sh --no-794      the same without the 7.94 check (says so)
#   ./regen_m66_lpeg.sh --check       FAIL unless two standalone runs agree and the three
#                                     committed files are what the oracle gives now
#   ./regen_m66_lpeg.sh --check-794   FAIL if nmap 7.94 drifts from the committed golden
#                                     outside the named classes (needs nmap)
#
# The spec is `liblua/` + `lpeg.c` from this repository (oracle/build_lua_oracle.sh,
# M6.5 D1(c)); nmap 7.94, through the prerule probe oracle/m66_lpeg_probe.nse
# with --datadir set to this tree, is the second oracle. Both run the same case
# runner, oracle/m66_lpeg_core.lua, which reaches every LPeg entry point through
# a direct pcall, so no error carries a position prefix (docs/M6.6-ANALYSIS.md E6).
#
# Three files are derived and checked:
#   m66_lpeg_cases.txt   the corpus (oracle/gen_m66_lpeg_cases.py, seed 1), less
#                        the quarantined rows
#   m66_lpeg_golden.txt  the tree's answer for every row, hash-order masked
#   m66_lpeg_steps.txt   the first step (b, c or d) whose engine can run each row
# and one is an input, written only by the local sanitizer screen
# (oracle/screen_m66_lpeg.py) and checked by digest:
#   m66_lpeg_quarantine.txt  rows that crash, trip ASan/UBSan, or are undefined in
#                        the C; they never reach an oracle or a golden
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

MODE="${1:-}"
case "$MODE" in ""|--no-794|--check|--check-794) ;; *) echo "usage: $0 [--no-794|--check|--check-794]" >&2; exit 2 ;; esac

bash "$HERE/oracle/build_lua_oracle.sh" >/dev/null

if [[ "$MODE" == "--check-794" ]]; then
  python3 oracle/gen_m66_lpeg.py agree
  exit 0
fi

NAMES=(m66_lpeg_cases.txt m66_lpeg_golden.txt m66_lpeg_steps.txt)
WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

if [[ -z "$MODE" ]]; then
  command -v nmap >/dev/null || { echo "FAIL: regeneration checks nmap 7.94 and needs it; --no-794 skips that" >&2; exit 1; }
  python3 oracle/gen_m66_lpeg.py build "$WORK" --with-794
else
  [[ "$MODE" == "--no-794" ]] && echo "m6.6 lpeg: NOT checking nmap 7.94 (--no-794)" >&2
  python3 oracle/gen_m66_lpeg.py build "$WORK"
fi

rc=0
for n in "${NAMES[@]}"; do
  if [[ "$MODE" == "--check" ]]; then
    if ! cmp -s "$n" "$WORK/$n"; then
      echo "FAIL: $n is stale — run ./regen_m66_lpeg.sh" >&2
      diff -u "$n" "$WORK/$n" | head -40 >&2 || true
      rc=1
    fi
  else
    cp "$WORK/$n" "$n"
  fi
done

rows=$(grep -cv '^#' m66_lpeg_golden.txt)
held=$(grep -cv '^#' m66_lpeg_quarantine.txt)
if [[ "$MODE" == "--check" ]]; then
  (( rc == 0 )) && echo "m6.6 lpeg: cases, golden and step map are current ($rows rows, $held quarantined)"
  exit $rc
fi
echo "m6.6 lpeg: regenerated ($rows rows, $held quarantined)"
