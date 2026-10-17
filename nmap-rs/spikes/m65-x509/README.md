# M6.5 step 0 — the E5 spike: can a crate be the X.509 reader?

Scratch, detached from the workspace: OpenSSL 3.0.13's `d2i_X509` (the call
nmap makes, `nse_ssl_cert.cc:538`) as the oracle over the 2,876-certificate
Phase 0 corpus plus 144 BER rows made here (`ber.tsv`, `src/mkber.py`),
against `x509-cert` 0.3.0 in every configuration it offers and
`x509-parser` 0.18.1. The verdict, the per-family agreement tables, the
re-encoding comparison and the eleven behaviours a first-party reader must
reproduce are in `RESULT.md`; it decided E5 in `docs/M6.5-ANALYSIS.md` §14.

`src/run_all.sh` reproduces everything (gcc with libcrypto, cargo, python3);
the three per-row output TSVs it writes are not committed, `out/compare.md`
and the crate audits are.
