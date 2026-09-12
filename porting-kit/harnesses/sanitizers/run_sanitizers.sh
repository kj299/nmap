#!/usr/bin/env bash
# Sanitizer & Miri gate — catch UB the compiler can't. For a C-to-Rust port the
# FFI/unsafe layer is the residual risk surface; these tools interrogate it:
#   * Miri            — UB in the pure/unsafe Rust (OOB, use-after-free, invalid
#                       aligns, data races in `unsafe`). Runs the test suite.
#                       CANNOT execute a foreign function, so it is never the gate
#                       for the FFI boundary itself — only for the Rust around it.
#   * ASan            — the same classes at the real FFI boundary (needs nightly
#                       -Zsanitizer). TSan for threaded code (the winlsof hang
#                       class — worker threads over shared handles).
# (PLAYBOOK Phase 4 gate 4; SECURITY-CHECKLIST "no UB at the FFI boundary".)
#
# THERE IS NO UBSan FOR RUST (LESSONS #026). `-Zsanitizer` accepts address, cfi,
# dataflow, hwaddress, kcfi, kernel-address, kernel-hwaddress, leak, memory, memtag,
# safestack, shadow-call-stack, thread and realtime — `undefined` is rejected by
# rustc outright. "ASan/UBSan" is a C/C++ pairing; this script used to offer a
# `ubsan` mode that could not run on any Rust project, and nothing noticed because no
# port had wired the template's sanitizers job. The Rust equivalents of what UBSan
# buys are Miri (aliasing, alignment, OOB, uninit) and `overflow-checks`/
# `debug-assertions`, both of which the kit already gates elsewhere.
#
# --all-features IS LOAD-BEARING (LESSONS #026). The unsafe an FFI port cares about
# is routinely behind a non-default feature — the kit's own Option-C escape hatch
# recommends exactly that. A sanitizer run without the flag compiles that module out
# and reports green having sanitized nothing. Count what executed, not what the job
# was named: in nmap, `cargo test -p nmap-sys --lib` ran 93 tests and
# `--features raw-ffi` ran 94, and that 94th was the only test in the whole project
# that executed any `unsafe`.
#
# TSan CAVEAT (LESSONS #10): TSan is *unsound as a gate over an async-runtime
# application* (tokio/async-std). The runtime's own lock-free work-stealing
# scheduler is not TSan-instrumentation-clean, so TSan reports false-positive
# races inside the runtime's atomics — and because your task code runs *inside*
# the runtime, a suppressions file can't cleanly separate a runtime false-positive
# from a real app race. Prefer *structural* race-freedom for such code (no shared
# mutable state + the compiler's Send/Sync bounds on spawn) plus Miri on the pure
# logic. Reserve TSan for code that spawns OS threads over genuinely shared state.
#
# SCOPE IT. Sanitizer builds use a SEPARATE target triple directory, so an ASan run
# over a whole workspace is a second full build tree on top of the one you already
# have — it cost 2.4 GB here and filled the disk mid-run. Point CRATE_DIR at the
# crate that actually holds the `unsafe` (the quarantine crate) rather than the
# workspace root. ASan over pure safe Rust finds nothing Miri and the fuzzers do not.
#
# Usage:
#   run_sanitizers.sh [miri|asan|lsan|tsan|all] [CRATE_DIR]
#   run_sanitizers.sh --check      # smoke: validate script + report tool avail
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
have() { command -v "$1" >/dev/null 2>&1; }

if [[ "${1:-}" == "--check" ]]; then
  bash -n "$0" && echo "PASS  script syntax ok"
  if have rustup; then
    rustup component list 2>/dev/null | grep -q "miri" && echo "note: miri component known to rustup" || echo "note: install miri:  rustup +nightly component add miri"
  else
    echo "note: rustup not installed (needed for miri/nightly sanitizers)"
  fi
  echo "self-test: OK"
  exit 0
fi

MODE="${1:-all}"; DIR="${2:-.}"
cd "$DIR"
TRIPLE="$(rustc -vV 2>/dev/null | awk '/host:/{print $2}')"
rc=0

run_miri() {
  if have cargo && rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo ">> cargo +nightly miri test --all-features"
    cargo +nightly miri test --all-features || rc=1
  else
    echo "!! miri needs nightly:  rustup toolchain install nightly && rustup +nightly component add miri" >&2
    rc=1
  fi
}

run_san() {
  local san="$1"
  if ! rustup toolchain list 2>/dev/null | grep -q nightly; then
    echo "!! $san sanitizer needs the nightly toolchain" >&2
    rc=1
    return
  fi
  # --target is REQUIRED, not stylistic: without it cargo builds build scripts and
  # proc macros with the same RUSTFLAGS and links them against a sanitizer runtime
  # they have no business carrying.
  #
  # -Zbuild-std instruments std as well, which catches more but needs the `rust-src`
  # component and rebuilds the world. Use it when available and fall back to an
  # uninstrumented std otherwise — a sanitizer over your own code is worth far more
  # than no sanitizer, and the FFI boundary this gate exists for is in your code.
  local extra=()
  if rustup component list --toolchain nightly 2>/dev/null | grep -q '^rust-src.*(installed)'; then
    extra+=(-Zbuild-std)
  else
    echo "note: rust-src not installed; running with an uninstrumented std" >&2
    echo "note: for full coverage:  rustup +nightly component add rust-src" >&2
  fi
  echo ">> cargo +nightly test --all-features with -Zsanitizer=$san"
  RUSTFLAGS="-Zsanitizer=$san" RUSTDOCFLAGS="-Zsanitizer=$san" \
    cargo +nightly test --all-features "${extra[@]}" --target "$TRIPLE" || rc=1
}

case "$MODE" in
  miri)  run_miri;;
  asan)  run_san address;;
  lsan)  run_san leak;;
  ubsan)
    # Refuse loudly rather than shelling out to a flag rustc rejects. The old
    # behaviour was to pass -Zsanitizer=undefined and fail with a rustc usage error
    # that read like a toolchain problem rather than a kit bug (LESSONS #026).
    echo "!! There is no UndefinedBehaviorSanitizer for Rust. -Zsanitizer accepts" >&2
    echo "!! address, cfi, dataflow, hwaddress, kcfi, kernel-address,"           >&2
    echo "!! kernel-hwaddress, leak, memory, memtag, safestack,"                 >&2
    echo "!! shadow-call-stack, thread and realtime — not 'undefined'."          >&2
    echo "!! Use 'miri' for aliasing/alignment/OOB/uninit, and keep"             >&2
    echo "!! overflow-checks on. See LESSONS #026."                              >&2
    rc=2;;
  tsan)
    echo "!! NOTE: TSan is unsound as a gate over an async runtime (tokio/async-std)" >&2
    echo "!! — it flags the runtime's own scheduler, not your code. See the header" >&2
    echo "!! caveat (LESSONS #10) before trusting a red/green result here." >&2
    run_san thread;;
  all)   run_miri; run_san address;;
  *) echo "usage: $0 [miri|asan|lsan|tsan|all] [CRATE_DIR] | --check" >&2; exit 2;;
esac
exit "$rc"
