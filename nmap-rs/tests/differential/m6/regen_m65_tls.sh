#!/usr/bin/env bash
# Re-derive the M6.5 TLS fixture golden from nmap itself, and compare it with
# what is committed.
#
#   ./regen_m65_tls.sh                 regenerate m65_tls_golden.txt in place
#   ./regen_m65_tls.sh --check         FAIL if it differs
#   ./regen_m65_tls.sh --check-header  FAIL if this machine's environment is
#                                      not the one the golden pins
#   ./regen_m65_tls.sh --check-port    the port over the same fixtures (steps
#                                      f1 and f2's gate): builds nmap-rs in
#                                      release, and FAILs on any row neither
#                                      equal to the golden nor pinned
#                                      (PORT_PINS)
#
# The oracle is the installed nmap 7.94 with --datadir set to this repository,
# connecting through m65_tls/s0probe.nse to each of the 125 fixture servers of
# m65_tls/ on 127.0.0.1:47301-47425 (oracle/gen_m65_tls.py): s_server with each
# suite, group and signature scheme forced, STARTTLS, odd certificates and
# chains, SNI, legacy versions, the fake TLS 1.2 server's negative fixtures, the
# corrupt TLS 1.3 CertificateVerify, a silent server and a closed port; and
# step f1's rows: how reads meet the end of a TLS connection, the
# get_ssl_certificate contract, UDP sockets, server names from a target name,
# and teardown mid-handshake; and step f2's: get_ssl_certificate's whole table,
# after handshakes that succeed and fail, and parse_ssl_certificate of the leaf
# with bytes after it; and M6.7's legacy-* rows (docs/M6.7-ANALYSIS.md §13):
# RSA key exchange, CBC, CCM, ARIA, Camellia, SEED, DHE and TLS 1.3 FFDHE and
# X448, which 7.94 reaches and the port does not yet. The
# generator runs the matrix twice and refuses to write a golden if an untagged
# row differs. The three needs-badserver rows are recorded only when the spike's
# badserver binary is found (BADSERVER, $CARGO_TARGET_DIR/release/badserver,
# spikes/m65-tls-provider/target/release/badserver); without it they are
# carried over from the committed golden. The golden's header pins nmap,
# OpenSSL, OPENSSL_CONF, the security level and the legacy provider; a check on
# another environment reports that first. Needs nmap, openssl and stdbuf.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

N=m65_tls_golden.txt

if [[ "${1:-}" == "--check-header" ]]; then
  exec python3 -B oracle/gen_m65_tls.py --check-header "$N"
fi

if [[ "${1:-}" == "--check-port" ]]; then
  ROOT="$(cd "$HERE/../../.." && pwd)"
  (cd "$ROOT" && cargo build --release -p nmap-cli --bins)
  T="${CARGO_TARGET_DIR:-$ROOT/target}/release"
  exec python3 -B oracle/gen_m65_tls.py --check "$N" --nmap-rs "$T/nmap-rs"
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
