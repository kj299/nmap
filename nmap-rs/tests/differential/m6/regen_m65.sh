#!/usr/bin/env bash
# Re-derive the M6.5 `openssl` corpus (step a), and check what is committed.
#
#   ./regen_m65.sh               regenerate the cases, the golden (nmap 7.94, run
#                                twice), the drift pins, the sanitizer screen and the
#                                census in place, then cross-check (needs nmap)
#   ./regen_m65.sh --check       FAIL unless the committed files are consistent and
#                                current, this tree's C differs from the golden in
#                                exactly the pinned rows, the independent references
#                                agree, and the sabotage record is for these cases
#                                (no nmap needed)
#   ./regen_m65.sh --check-794   FAIL unless this machine is the environment the
#                                golden's header pins and nmap 7.94 agrees with the
#                                golden on every row it runs (needs nmap)
#
# The oracle is the installed nmap 7.94 (oracle/m65_probe.nse, --datadir set to this
# tree); the spec is this tree's nse_openssl.cc and nse_ssl_cert.cc, built
# standalone with liblua (oracle/build_openssl_oracle.sh, D1). Both run the one
# case runner, oracle/m65_core.lua. oracle/gen_m65.py says what each file is.
# The C sabotage (oracle/sabotage_m65.py, about five minutes) is local only; its
# record, m65_sabotage.txt, names the cases it measured, and --check refuses it
# for any other cases.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

case "${1:-}" in
  "")
    command -v nmap >/dev/null || { echo "FAIL: regeneration runs nmap 7.94 and needs it" >&2; exit 1; }
    python3 -B oracle/gen_m65_cases.py m65_algs.txt m65_certs.txt m65_cases.txt
    python3 -B oracle/gen_m65.py golden
    python3 -B oracle/gen_m65.py drift
    python3 -B oracle/gen_m65.py screen
    python3 -B oracle/gen_m65.py census
    python3 -I -B oracle/xref_m65.py
    echo "m6.5 openssl: regenerated; run oracle/sabotage_m65.py to re-measure the corpus"
    ;;
  --check)
    python3 -B oracle/gen_m65_cases.py --self-test
    python3 -B oracle/gen_m65.py --check
    bash oracle/build_openssl_oracle.sh >/dev/null
    python3 -B oracle/gen_m65.py --check-tree
    python3 -I -B oracle/xref_m65.py
    want="$(sha256sum m65_cases.txt | cut -c1-16)"
    grep -q "(cases $want)" m65_sabotage.txt || {
      echo "FAIL: m65_sabotage.txt measured other cases: run oracle/sabotage_m65.py" >&2; exit 1; }
    ! grep -q MISSED m65_sabotage.txt || { echo "FAIL: m65_sabotage.txt records a missed variant" >&2; exit 1; }
    echo "m6.5 openssl: committed files current and consistent"
    ;;
  --check-794)
    python3 -B oracle/gen_m65.py --check-794
    ;;
  *) echo "usage: $0 [--check | --check-794]" >&2; exit 2 ;;
esac
