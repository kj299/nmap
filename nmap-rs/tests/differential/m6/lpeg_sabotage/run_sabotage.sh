#!/usr/bin/env bash
# M6.6 step 0b: does the committed LPeg corpus catch a sabotaged lpeg.c?
# Builds the variants (variants.py) and runs the corpus through each against
# the committed golden (README.md). LOCAL ONLY: CI never runs it.
#
#   run_sabotage.sh [--work DIR] [-j JOBS] [--limit N] [--timeout SECONDS] [VARIANT ...]
#
#   --work DIR         builds and outputs (default $LPEG_SABOTAGE_WORK, else
#                      ${TMPDIR:-/tmp}/nmap-lpeg-sabotage); never inside the repo
#   -j JOBS            variants built at once (default 4)
#   --limit N          run only the first N rows of the cases (a smoke test;
#                      only the baseline check applies)
#   --timeout SECONDS  how long one driver process may run before the row it is
#                      on counts as hung (default 120)
#   VARIANT ...        full names or S-numbers, e.g. S00 S13 (default: all 17)
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$HERE/../../../../.." && pwd -P)"

WORK="${LPEG_SABOTAGE_WORK:-${TMPDIR:-/tmp}/nmap-lpeg-sabotage}"
JOBS=4
CMP_ARGS=()
VARIANTS=()
usage() { sed -n '2,16p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 2; }
while [[ $# -gt 0 ]]; do
  case "$1" in
    --work) WORK="$2"; shift 2 ;;
    -j) JOBS="$2"; shift 2 ;;
    --limit|--timeout) CMP_ARGS+=("$1" "$2"); shift 2 ;;
    -h|--help) usage ;;
    -*) echo "unknown option $1" >&2; usage ;;
    *) VARIANTS+=("$1"); shift ;;
  esac
done
WORK="$(realpath -m "$WORK")"
case "$WORK/" in "$REPO"/*) echo "refusing a work directory inside the repository: $WORK" >&2; exit 2 ;; esac
mkdir -p "$WORK"

python3 -I -B "$HERE/build_variants.py" --work "$WORK" -j "$JOBS" "${VARIANTS[@]}"
python3 -I -B "$HERE/sabcmp.py" --work "$WORK" "${CMP_ARGS[@]}" "${VARIANTS[@]}"
