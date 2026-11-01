#!/usr/bin/env bash
# M6.7 step f: the two fixture keys 7.94's signature_algorithms reach that
# the M6.5 set lacked, made as the others were (self-signed, ten years,
# `CN = m65-<name>`): an Ed448 leaf (`ed448`) and an RSA-PSS leaf
# (`rsapss2048`, id-RSASSA-PSS with no parameters, which signs with
# rsa_pss_pss_*). Run once; the outputs are committed.
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"
openssl genpkey -algorithm ed448 -out ed448.key
openssl req -x509 -new -key ed448.key -subj "/CN=m65-ed448" -days 3650 -out ed448.crt
openssl genpkey -algorithm RSA-PSS -pkeyopt rsa_keygen_bits:2048 -out rsapss2048.key
openssl req -x509 -new -key rsapss2048.key -subj "/CN=m65-rsapss2048" -days 3650 \
  -sigopt rsa_padding_mode:pss -sigopt rsa_pss_saltlen:digest -out rsapss2048.crt
