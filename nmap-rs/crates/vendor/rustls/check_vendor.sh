#!/usr/bin/env bash
# Verify that the vendored rustls is EXACTLY `upstream tag + patches/`.
#
# The same gate as crates/vendor/piccolo/check_vendor.sh, for the same reason:
# a vendored copy is only worth having while it is provably upstream plus a
# named series of our changes. Someone fixing a bug directly in rustls/src/
# would end that, and from then on nobody could tell our edits from upstream's.
#
#   ./check_vendor.sh            verify; non-zero and a diff on any drift
#
# To CHANGE the vendored code, edit rustls/src/ and then update the patch in
# patches/ that owns that intent, or add a new numbered one. There is no
# --refresh, for the reason piccolo's script gives: one regenerated patch
# would erase the record of which change is which.
#
# What is compared, file for file, against upstream's repository at the tag:
#   rustls/src/                 the whole tree (code and src/testdata)
#   rustls/LICENSE-*            the three licence texts
#   .rustfmt.toml               upstream's, so `cargo fmt --check` formats this
#                               tree as upstream does
#   test-ca/...                 the nine files the unit tests include_bytes!
#   fuzz/corpus/message/        the corpus `test_read_fuzz_corpus` reads
# rustls/Cargo.toml is OURS (upstream's names workspace dependencies and the
# C providers); PROVENANCE.md records how it differs.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

UPSTREAM="https://github.com/rustls/rustls"
TAG="v/0.23.46"
COMMIT="f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb"
mapfile -t PATCHES < <(find "$HERE/patches" -maxdepth 1 -name '*.patch' | sort)

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# A shallow fetch of the one commit the tag names.
if ! git -c advice.detachedHead=false init -q "$WORK/up" 2>/dev/null \
  || ! git -C "$WORK/up" remote add origin "$UPSTREAM" 2>/dev/null \
  || ! git -C "$WORK/up" fetch -q --depth 1 origin "$COMMIT" 2>/dev/null \
  || ! git -C "$WORK/up" checkout -q FETCH_HEAD 2>/dev/null; then
  echo "check_vendor: could not fetch $UPSTREAM@${COMMIT:0:12} ($TAG)" >&2
  echo "  This gate needs network access. It is not skipped when offline:" >&2
  echo "  a verification that passes when it cannot verify is worse than none." >&2
  exit 1
fi

for patch in "${PATCHES[@]}"; do
  if ! git -C "$WORK/up" apply --include='rustls/src/*' "$patch" 2>"$WORK/apply.err"; then
    echo "check_vendor: $(basename "$patch") does not apply to ${COMMIT:0:12}" >&2
    cat "$WORK/apply.err" >&2
    exit 1
  fi
done

: > "$WORK/drift.diff"
ok=1
diff -ru --exclude='*.orig' --exclude='*.rej' "$WORK/up/rustls/src" "$HERE/rustls/src" \
  >> "$WORK/drift.diff" || ok=0
diff -ru "$WORK/up/fuzz/corpus/message" "$HERE/fuzz/corpus/message" >> "$WORK/drift.diff" || ok=0
for f in rustls/LICENSE-APACHE rustls/LICENSE-ISC rustls/LICENSE-MIT .rustfmt.toml; do
  diff -u "$WORK/up/$f" "$HERE/$f" >> "$WORK/drift.diff" || ok=0
done
# test-ca: each vendored file must be upstream's; the set is what the unit
# tests name, so a file the tests stop naming is caught by the next one's
# absence rather than kept as dead weight.
n_ca=0
while IFS= read -r -d '' f; do
  rel="${f#"$HERE"/}"
  cmp -s "$WORK/up/$rel" "$f" || { echo "differs from upstream: $rel" >> "$WORK/drift.diff"; ok=0; }
  n_ca=$((n_ca + 1))
done < <(find "$HERE/test-ca" -type f -print0)
while IFS= read -r ref; do
  [[ -f "$HERE/$ref" ]] || { echo "named by a test, not vendored: $ref" >> "$WORK/drift.diff"; ok=0; }
done < <(grep -rhoE '"\.\./\.\./\.\./test-ca/[^"]+"' "$HERE/rustls/src" | tr -d '"' | sed 's#^\.\./\.\./\.\./##' | sort -u)

if (( ok )); then
  echo "check_vendor: rustls/src + test-ca ($n_ca) + fuzz corpus == $TAG (${COMMIT:0:12})" \
       "+ ${#PATCHES[@]} patch(es) ($(find "$HERE/rustls/src" -name '*.rs' | wc -l) rs)"
  exit 0
fi
echo "FAIL: vendored rustls is not 'upstream + patches'." >&2
echo "  Either the edit belongs in patches/ -- update the patch that owns that" >&2
echo "  intent, or add a new numbered one -- or it was not meant to be there." >&2
head -60 "$WORK/drift.diff" >&2
exit 1
