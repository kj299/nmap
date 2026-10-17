#!/bin/sh
# Reproduce the E5 spike end to end (read-only on /home/user/nmap).  ~2 min.
set -e
S=$(cd "$(dirname "$0")/.." && pwd)                      # this spike
M=${1:?usage: run_all.sh DIR-holding-certs.tsv}       # the Phase 0 corpus (step a commits its generator)
export CARGO_TARGET_DIR=$S/target
mkdir -p $S/out
/usr/bin/python3.12 -I $S/src/mkber.py $M/certs.tsv $S/ber.tsv                          # 144 BER rows (3 bases)
gcc -O2 -Wall -o $S/c/oracle $S/c/oracle.c -lcrypto                                       # OpenSSL 3.0.13
$S/c/oracle $M/certs.tsv $S/ber.tsv > $S/c_oracle.tsv
(cd $S/rs_x509cert   && cargo build --release && cargo tree -e normal --prefix none | sort -u > $S/out/tree_x509cert.txt   && cargo +1.88 check)
(cd $S/rs_x509parser && cargo build --release && cargo tree -e normal --prefix none | sort -u > $S/out/tree_x509parser.txt && cargo +1.88 check)
$S/target/release/x509cert_probe   $M/certs.tsv $S/ber.tsv > $S/x509cert.tsv
$S/target/release/x509parser_probe $M/certs.tsv $S/ber.tsv > $S/x509parser.tsv
/usr/bin/python3.12 -I $S/src/compare.py $S $M/certs.tsv $S/ber.tsv > $S/out/compare_stdout.txt   # -> out/compare.md, out/joined.tsv
/usr/bin/python3.12 -I $M/tools/audit_src.py $S/rs_x509cert/Cargo.lock   > $S/out/audit_x509cert.txt
/usr/bin/python3.12 -I $M/tools/audit_src.py $S/rs_x509parser/Cargo.lock > $S/out/audit_x509parser.txt
/usr/bin/python3.12 -I $S/src/inspect.py $S $M/certs.tsv $S/ber.tsv x02299 x02253 b00009 b00130 > $S/out/inspect_examples.txt
rm -rf $S/target
