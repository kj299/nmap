#!/usr/bin/env bash
# Re-derive the M6.5 TLS fixture golden from nmap itself, and compare it with
# what is committed.
#
#   ./regen_m65_tls.sh                 regenerate m65_tls_golden.txt in place
#   ./regen_m65_tls.sh --check         FAIL if it differs
#   ./regen_m65_tls.sh --check-header  FAIL if this machine's environment is
#                                      not the one the golden pins
#
# The oracle is the installed nmap 7.94 with --datadir set to this repository,
# connecting through m65_tls/s0probe.nse to each of the 61 fixture servers of
# m65_tls/ on 127.0.0.1:47301-47361 (oracle/gen_m65_tls.py): s_server with each
# suite, group and signature scheme forced, STARTTLS, odd certificates and
# chains, SNI, legacy versions, the fake TLS 1.2 server's negative fixtures, the
# corrupt TLS 1.3 CertificateVerify, a silent server and a closed port. The
# generator runs the matrix twice and refuses to write a golden if an untagged
# row differs. The two needs-badserver rows are recorded only when the spike's
# badserver binary is found (BADSERVER, $CARGO_TARGET_DIR/release/badserver,
# spikes/m65-tls-provider/target/release/badserver); without it they are
# carried over from the committed golden. The golden's header pins nmap,
# OpenSSL, OPENSSL_CONF, the security level and the legacy provider; a check on
# another environment reports that first. Step f1 adds the port's side
# (gen_m65_tls.py --check GOLDEN --client CMD). Needs nmap and openssl.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

N=m65_tls_golden.txt

if [[ "${1:-}" == "--check-header" ]]; then
  exec python3 -B oracle/gen_m65_tls.py --check-header "$N"
fi

CHECK=0
[[ "${1:-}" == "--check" ]] && CHECK=1

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

CARRY=()
[[ -f "$N" ]] && CARRY=(--carry "$HERE/$N")
python3 -B oracle/gen_m65_tls.py "$WORK" "${CARRY[@]}"

rows=$(grep -vc '^#' "$WORK/$N")
if (( CHECK )); then
  if ! python3 -B oracle/gen_m65_tls.py --check-header "$N" >&2; then
    echo "FAIL: this machine is not the environment $N pins (above)" >&2
    exit 1
  fi
  if ! cmp -s "$N" "$WORK/$N"; then
    echo "FAIL: $N is stale — run ./regen_m65_tls.sh" >&2
    diff -u "$N" "$WORK/$N" | head -40 >&2 || true
    exit 1
  fi
  echo "m6.5 tls: golden is current ($rows rows)"
  exit 0
fi
cp "$WORK/$N" "$N"
echo "m6.5 tls: regenerated ($rows rows)"
