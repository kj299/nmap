#!/usr/bin/env bash
# Regenerate the IPv6 scan-probe cases and their golden from nmap's own builders,
# or (with --check) prove the committed golden is exactly what they produce today.
#
# The oracle (oracle/scanprobe6_oracle.cc) compiles build_tcp_raw_ipv6,
# build_udp_raw_ipv6 and what they call out of tcpip.cc, netutil.cc and libdnet,
# and seq32_encode / sport_encode out of scan_engine_raw.cc
# (oracle/build_scanprobe6_oracle.sh). The cargo test
# (crates/core/tests/scanprobe6_differential.rs) requires the port's packets to be
# byte-identical to the committed golden, so without this a hand-edited golden would
# make it agree with a paraphrase. `--check` runs in CI and fails on any drift,
# including a change to those C functions.
#
#   ./regen_scanprobe6_golden.sh            # rebuild oracle + regenerate cases and golden
#   ./regen_scanprobe6_golden.sh --check    # same, then require `git diff` to be empty
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

bash "$HERE/oracle/build_scanprobe6_oracle.sh" >/dev/null
python3 "$HERE/oracle/gen_scanprobe6_cases.py"
"$HERE/oracle/scanprobe6_oracle" < "$HERE/scanprobe6_cases.txt" > "$HERE/scanprobe6_golden.txt"
echo "regenerated $(wc -l < "$HERE/scanprobe6_cases.txt") IPv6 scan-probe cases"

if [[ "${1:-}" == "--check" ]]; then
  PATHS=(scanprobe6_cases.txt scanprobe6_golden.txt)
  git -C "$HERE" add -N -- "${PATHS[@]}"
  if ! git -C "$HERE" diff --exit-code -- "${PATHS[@]}"; then
    echo "error: the committed IPv6 scan-probe golden does not match what nmap's builders produce" >&2
    exit 1
  fi
  echo "committed golden matches nmap's builders"
fi
