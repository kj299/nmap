#!/usr/bin/env bash
# M6.6 step 0b: adversarial slowness search over the network-facing LPeg
# patterns (README.md). LOCAL ONLY: CI never runs it.
#
#   run_search.sh [--work DIR] [--budget SECONDS] [-j JOBS] [--selmin N] [--rebuild] [PATTERN ...]
#
#   --work DIR        builds and outputs (default $LPEG_SEARCH_WORK, else
#                     ${TMPDIR:-/tmp}/nmap-lpeg-search); never inside the repo
#   --budget SECONDS  CPU seconds of search per pattern (default $LPEG_SEARCH_BUDGET, else 600)
#   -j JOBS           patterns searched at once (default $LPEG_SEARCH_JOBS, else 4)
#   --selmin N        selection floor: fitness = steps / max(#s, N) (default 1024)
#   --rebuild         rebuild the instrumented interpreter even if it looks current
#   PATTERN ...       a subset of: json coap get_response parse_fp ntp fpstrings
#                     aff_ga aff_ad aff_amz aff_short escaped_quote (default: all)
#
# Prints one row per pattern: the max sustained steps/byte (subjects of at
# least SELMIN bytes), the growth exponents and K = 1.25 x that maximum.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../../.." && pwd -P)"
ALL=(json coap get_response parse_fp ntp fpstrings aff_ga aff_ad aff_amz aff_short escaped_quote)

WORK="${LPEG_SEARCH_WORK:-${TMPDIR:-/tmp}/nmap-lpeg-search}"
BUDGET="${LPEG_SEARCH_BUDGET:-600}"
JOBS="${LPEG_SEARCH_JOBS:-4}"
SELMIN=1024
REBUILD=0
IDS=()
usage() { sed -n '2,17p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    --budget) BUDGET="$2"; shift 2 ;;
    -j) JOBS="$2"; shift 2 ;;
    --selmin) SELMIN="$2"; shift 2 ;;
    --rebuild) REBUILD=1; shift ;;
    -h|--help) usage ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) IDS+=("$1"); shift ;;
  esac
done
[[ ${#IDS[@]} -eq 0 ]] && IDS=("${ALL[@]}")
for id in "${IDS[@]}"; do
  [[ " ${ALL[*]} " == *" $id "* ]] || { echo "unknown pattern: $id" >&2; exit 2; }
done
[[ "$BUDGET" =~ ^[0-9]+([.][0-9]+)?$ ]] || { echo "--budget wants seconds" >&2; exit 2; }
[[ "$JOBS" =~ ^[1-9][0-9]*$ ]] || { echo "-j wants a positive integer" >&2; exit 2; }
[[ "$SELMIN" =~ ^[1-9][0-9]*$ ]] || { echo "--selmin wants a positive integer" >&2; exit 2; }

WORK="$(realpath -m "$WORK")"
case "$WORK/" in "$REPO"/*) echo "refusing a work directory inside the repository: $WORK" >&2; exit 2 ;; esac
OUT="$WORK/out"
LUA="$WORK/lua-instr"
mkdir -p "$OUT"

# Build unless the interpreter is newer than every input.
stale() {
  [[ -x "$LUA" ]] || return 0
  [[ -n "$(find "$REPO/liblua" -name '*.[ch]' -newer "$LUA" -print -quit)" ]] && return 0
  local f
  for f in "$REPO/lpeg.c" "$REPO/nse_lpeg.cc" "$REPO/nse_lpeg.h" "$REPO/nse_lua.h" \
           "$HERE/patch_lpeg.py" "$HERE/build_patched_lua.sh" "$HERE/build_instrumented.sh" \
           "$REPO/nmap-rs/tests/differential/m6/oracle/build_lua_oracle.sh"; do
    [[ "$f" -nt "$LUA" ]] && return 0
  done
  return 1
}
if [[ $REBUILD -eq 1 ]] || stale; then
  echo "building the instrumented interpreter in $WORK ..." >&2
  bash "$HERE/build_instrumented.sh" "$WORK" >&2
fi

echo "lpeg search: ${#IDS[@]} pattern(s), budget ${BUDGET}s CPU each, SELMIN $SELMIN, $JOBS at once, outputs in $OUT" >&2
run_one() {
  local id=$1
  rm -f "$OUT/res_$id.txt" "$OUT/err_$id.txt" "$OUT/best_$id.bin" "$OUT/sustained_$id.bin" "$OUT/beststeps_$id.bin"
  if "$LUA" "$HERE/search.lua" "$id" "$BUDGET" "$OUT" "$SELMIN" >"$OUT/res_$id.txt" 2>"$OUT/err_$id.txt"; then
    echo "  done $id" >&2
  else
    echo "  FAILED $id (see $OUT/err_$id.txt)" >&2
  fi
}
for id in "${IDS[@]}"; do
  while (( $(jobs -rp | wc -l) >= JOBS )); do wait -n || true; done
  run_one "$id" &
done
wait

# The auxiliary checks take about a second together.
"$LUA" "$HERE/verify_wellformed.lua" >"$OUT/wellformed.txt"
"$LUA" "$HERE/scriptside.lua" >"$OUT/scriptside.txt"

fail=0
{
  echo "M6.6 0b adversarial search: budget ${BUDGET}s CPU per pattern, SELMIN $SELMIN"
  printf '%-14s %10s %8s %8s %8s %8s %8s %8s %8s %8s\n' \
    pattern evals max_spb at_size best_64 grow_exp env_exp pre_exp tail_exp K_1.25
  for id in "${IDS[@]}"; do
    line="$(grep '^SUMMARY' "$OUT/res_$id.txt" 2>/dev/null || true)"
    if [[ -z "$line" ]]; then
      printf '%-14s FAILED: see %s\n' "$id" "$OUT/err_$id.txt"
      continue
    fi
    IFS=$'\t' read -r _ pid evals sus size best g e p t k <<<"$line"
    printf '%-14s %10s %8s %8s %8s %8s %8s %8s %8s %8s\n' "$pid" "$evals" "$sus" "$size" "$best" "$g" "$e" "$p" "$t" "$k"
  done
  echo
  echo "max_spb: the highest (vm + cap) steps per subject byte over every subject of at"
  echo "  least SELMIN bytes; at_size: that subject's size (OUTDIR/sustained_ID.bin)"
  echo "best_64: the same over subjects of at least 64 bytes (start-up cost included)"
  echo "grow_exp / env_exp / pre_exp / tail_exp: log-log slope of steps against size"
  echo "  over the grow(n) family / the search's envelope from 64 B / prefixes of the"
  echo "  most-steps subject / the envelope from 8 KiB (-1: too few points); 1.0 is"
  echo "  linear. env_exp needs a long budget to settle, and pre_exp reads high for"
  echo "  get_response and parse_fp because a prefix that cuts the closing quote skips"
  echo "  the unescape pass (wellformed.txt fits closed families); the warning below"
  echo "  uses grow_exp and tail_exp"
  echo "K_1.25: 1.25 x max_spb, the regression gate's suggested ceiling"
  awk '/^== /{name=$0; gsub(/^== | ==$/, "", name)} /EXP=/{print "wellformed family " name ": " $1}' "$OUT/wellformed.txt"
} | tee "$OUT/table.txt"
for id in "${IDS[@]}"; do
  line="$(grep '^SUMMARY' "$OUT/res_$id.txt" 2>/dev/null || true)"
  if [[ -z "$line" ]]; then fail=1; continue; fi
  IFS=$'\t' read -r _ _ _ _ _ _ g _ _ t _ <<<"$line"
  for x in "$g" "$t"; do
    if awk -v x="$x" 'BEGIN { exit !(x > 1.10) }'; then
      echo "WARNING: $id has a growth exponent of $x (> 1.10): look for super-linear structure in $OUT/res_$id.txt" | tee -a "$OUT/table.txt"
      break
    fi
  done
done
exit $fail
