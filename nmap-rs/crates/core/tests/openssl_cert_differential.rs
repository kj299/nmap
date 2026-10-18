//! Differential: the M6.5 `openssl` corpus, every row of step e
//! (`parse_ssl_certificate` and the `SSL_CERT` object).
//!
//! `tests/differential/m6/m65_cases.txt` is run by nmap 7.94 into
//! `m65_golden.txt` (`oracle/gen_m65.py`, step a). This gate runs every row
//! tagged `e` through the port's `parse_ssl_certificate` (test-only, before
//! the socket module that holds it is registered) by the oracle's own runner
//! (`m65` harness), which renders what comes back: every field
//! `parse_ssl_cert` sets, a field it does not, the RSA key's numbers as
//! `BIGNUM`s, and `cert:digest` over four algorithms and an unknown one. It
//! compares status and values byte for byte with the golden.
//!
//! The corpus is `m65_certs.txt`: Phase 0's 2,876 certificates (1,092 OIDs
//! as subject attributes and as extensions, 11 string tags, time edge cases,
//! 18 key types with 13 well-formed extensions each, 143 truncations, 400
//! byte flips) and the 144 BER rows of E5's spike, plus the argument checks.
//!
//! - **Not compared:** `q=N` (the harness's doc).
//! - **The year** (`nse-sslcert-validity-year`, D1 (c)): the port follows
//!   7.94, the full year; so do the 13 `asn1time` rows, 7.94's own parser.
//!   Neither needs an adjustment: the golden is 7.94's.
//! - **No exemption.** Every row must agree exactly.
#![cfg(not(miri))] // reads the corpus from disk

mod m65;

/// The fewest rows the gate must run: the 3,030 rows tagged `e`.
const MIN_ROWS: usize = 3_030;

#[test]
#[ignore = "step e2: the extension printers are not ported yet"]
fn every_certificate_row_matches_nmap_794() {
    let ran = m65::run_step_with(true, MIN_ROWS, |row| row.tags.contains(&"e"), |_, _, _| {});
    assert!(ran >= MIN_ROWS);
}
