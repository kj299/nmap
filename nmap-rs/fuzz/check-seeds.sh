#!/usr/bin/env bash
# Seed-corpus hygiene. Run it locally exactly as CI does:
#
#   nmap-rs/fuzz/check-seeds.sh
#
# Two things go wrong with fuzz seeds, and green CI has historically objected to
# neither:
#
# 1. POLLUTION. `cargo fuzz run <t> fuzz/seeds/<t>` treats that directory as a
#    *corpus*, not a read-only seed set, so libFuzzer writes every newly discovered
#    input straight into it. A local smoke run therefore drops dozens of
#    SHA1-named blobs into the tree, and they get committed with the next change.
#    979 such files accumulated across seven targets before anyone noticed. Run
#    fuzz targets with a scratch corpus directory FIRST and the seed directory
#    second, so writes land somewhere disposable:
#
#      cargo +nightly fuzz run <t> /tmp/corp fuzz/seeds/<t>
#
# 2. A MISSING OR EMPTY SEED DIRECTORY. CI invokes `cargo fuzz run <t>
#    fuzz/seeds/<t>`, so a target without one fails the job — but only once that
#    shard gets to it, minutes in.
#
# Seeds are curated, reviewable inputs that a human wrote or derived on purpose.
# Anything the fuzzer discovered belongs in a corpus, which is not this directory.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SEEDS="$HERE/seeds"
rc=0

# Target names come from fuzz/Cargo.toml's [[bin]] entries so this needs no
# toolchain and no cargo-fuzz: it runs in the fast build job, not the 9-minute
# fuzz shards.
targets=$(sed -n 's/^name = "\(.*\)"$/\1/p' "$HERE/Cargo.toml" | tail -n +2)
if [ -z "$targets" ]; then
  echo "check-seeds: found no [[bin]] targets in fuzz/Cargo.toml" >&2
  exit 1
fi

for t in $targets; do
  d="$SEEDS/$t"
  if [ ! -d "$d" ]; then
    echo "FAIL $t: no seed directory at fuzz/seeds/$t" >&2
    rc=1
  elif [ -z "$(ls -A "$d")" ]; then
    echo "FAIL $t: fuzz/seeds/$t is empty" >&2
    rc=1
  fi
done

# libFuzzer names what it discovers after the SHA-1 of its contents. A curated
# seed is named for what it *is*, so a 40-hex-character filename is the signature
# of a machine-written file that should never have been committed.
generated=$(find "$SEEDS" -type f -regextype posix-extended -regex '.*/[0-9a-f]{40}$' | sort)
if [ -n "$generated" ]; then
  count=$(printf '%s\n' "$generated" | wc -l)
  echo "FAIL: $count fuzzer-generated file(s) committed under fuzz/seeds/:" >&2
  printf '%s\n' "$generated" | sed 's|^|  |' | head -20 >&2
  [ "$count" -gt 20 ] && echo "  ... and $((count - 20)) more" >&2
  echo "These are discovered corpus entries, not seeds. Delete them, and re-run the" >&2
  echo "target with a scratch corpus dir first: cargo +nightly fuzz run <t> /tmp/corp fuzz/seeds/<t>" >&2
  rc=1
fi

if [ $rc -eq 0 ]; then
  echo "seed hygiene ok ($(printf '%s\n' "$targets" | wc -l) targets, $(find "$SEEDS" -type f | wc -l) curated seeds)"
fi
exit $rc
