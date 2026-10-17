# M6.5 step 0 — the bignum spike: what peer-chosen operand sizes cost

Scratch, detached from the workspace: OpenSSL 3.0.13's BIGNUM (what nmap
7.94's `openssl` module calls) against `num-bigint` 0.4.8, timed at the
sizes a network peer can choose (a TLS DH `p` is at most 524,280 bits; an
ssh2 group-exchange `p` is unbounded) for `mod_exp` in three shapes,
`is_prime` (trial division and Miller-Rabin as `BN_check_prime` does them),
`bn2dec`/`dec2bn`; OpenSSL's own 536,870,848-bit cap confirmed in C and
through nmap 7.94 (`nse/bncap.nse`); `num-bigint`'s four panics. The
tables, the 1 s / 10 s / 60 s / 600 s crossings and the per-operation caps
the port adopts are in `RESULT.md`; the decision is in
`docs/M6.5-ANALYSIS.md` §14.3. Raw timing outputs are in `raw/`.
