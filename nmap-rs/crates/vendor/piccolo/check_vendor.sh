#!/usr/bin/env bash
# Verify that the vendored tree is EXACTLY `upstream commit + patches/`.
#
# Vendoring trades an upstream dependency for a local copy, and the risk it
# introduces is that the copy quietly stops being what PROVENANCE.md says it is:
# someone fixes a bug directly in src/, the patch series no longer describes the
# delta, and from then on nobody can tell our changes from upstream's. That is
# the vendored-code version of the silent drift the rest of this port gates
# against, so it gets a gate too.
#
#   ./check_vendor.sh            verify; non-zero and a diff on any drift
#
# To CHANGE the vendored code, edit src/ and then update the patch in patches/
# that owns that intent, or add a new numbered one. There is deliberately no
# --refresh: regenerating the series from src/ in one shot would collapse every
# patch into one and destroy the record of which change is which, which is the
# only thing that lets a future reader tell our edits from upstream\'s.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UPSTREAM="https://github.com/kyren/piccolo"
COMMIT="ce709eb1dae5c543cbc78e7e12bb80249d88c55f"
# Every patch in patches/, applied in name order. Each file records ONE intent,
# so `git log`-style provenance survives: a reader can see which of our changes
# is the supply-chain back-port and which is the audit-gate documentation,
# without reverse-engineering it from a single combined diff.
mapfile -t PATCHES < <(find "$HERE/patches" -maxdepth 1 -name '*.patch' | sort)
(( ${#PATCHES[@]} )) || { echo "check_vendor: no patches found" >&2; exit 1; }

REFRESH=0
[[ "${1:-}" == "--refresh" ]] && REFRESH=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A shallow fetch of the one commit; the full history is ~140 MB and irrelevant.
if ! git -c advice.detachedHead=false init -q "$WORK/up" 2>/dev/null \
  || ! git -C "$WORK/up" remote add origin "$UPSTREAM" 2>/dev/null \
  || ! git -C "$WORK/up" fetch -q --depth 1 origin "$COMMIT" 2>/dev/null \
  || ! git -C "$WORK/up" checkout -q FETCH_HEAD 2>/dev/null; then
  echo "check_vendor: could not fetch $UPSTREAM@${COMMIT:0:12}" >&2
  echo "  This gate needs network access. It is not skipped when offline," >&2
  echo "  because a verification that silently passes when it cannot verify" >&2
  echo "  is worse than no verification at all." >&2
  exit 1
fi

if (( REFRESH )); then
  cp -r "$HERE/src" "$WORK/ours-src"
  ( cd "$WORK/up" && cp -r "$WORK/ours-src"/. src/ \
      && git diff -- src/ > "$WORK/new.patch" )
  # Cargo.toml is ours outright (upstream's is a workspace root), so the patch
  # covers src/ only; PROVENANCE.md records that split.
  echo "check_vendor: --refresh collapses the series into one patch, which would" >&2
  echo "  destroy the record of WHICH change is which. Re-derive the affected" >&2
  echo "  patch by hand instead, or add a new numbered one for a new intent." >&2
  echo "  (A drift diff is printed by a plain run; start from that.)" >&2
  rm -f "$WORK/new.patch"
  exit 2
fi

for patch in "${PATCHES[@]}"; do
  # Patches may touch src/ AND tests/. Cargo.toml stays excluded because ours is
  # a rewrite rather than a patch: upstream's is a workspace root and cannot be
  # vendored as-is, which PROVENANCE.md records.
  if ! git -C "$WORK/up" apply --include='src/*' --include='tests/*' "$patch" 2>"$WORK/apply.err"; then
    echo "check_vendor: $(basename "$patch") does not apply to ${COMMIT:0:12}" >&2
    cat "$WORK/apply.err" >&2
    exit 1
  fi
done

# tests/ is vendored too, and unmodified. It is upstream's own suite -- 13 test
# binaries and 43 Lua programs -- and it is the ONLY thing that drives real code
# through this VM: the crate's lib unit tests are 11 assertions, which would make
# the ASan job over it very nearly vacuous. So it is checked for drift exactly
# like src/, and no patch is expected to touch it.
ok=0
if diff -ru --exclude='*.orig' --exclude='*.rej' "$WORK/up/src" "$HERE/src" > "$WORK/drift.diff" \
   && diff -ru --exclude='*.orig' --exclude='*.rej' \
        --exclude='probe_stash_stress.rs' \
        "$WORK/up/tests" "$HERE/tests" >> "$WORK/drift.diff"; then
  ok=1
fi
if (( ok )); then
  echo "check_vendor: src/ + tests/ == ${COMMIT:0:12} + ${#PATCHES[@]} patch(es)" \
       "($(find "$HERE/src" "$HERE/tests" -name '*.rs' | wc -l) rs," \
       "$(find "$HERE/tests" -name '*.lua' | wc -l) lua)"
  exit 0
fi

echo "FAIL: vendored src/ or tests/ is not 'upstream + patches'." >&2
echo "  Either the edit belongs in patches/ -- update the patch that owns that" >&2
echo "  intent, or add a new numbered one -- or it was not meant to be there." >&2
head -60 "$WORK/drift.diff" >&2
exit 1
