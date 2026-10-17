//! Differential: the M6.5 `openssl` corpus, every row of step c (digests,
//! HMAC and randomness).
//!
//! `tests/differential/m6/m65_cases.txt` is run by nmap 7.94 into
//! `m65_golden.txt` (`oracle/gen_m65.py`, step a). This gate runs every row
//! tagged `c` — `digest` over each name `supported_digests` lists at the
//! block edges of every digest, the names' aliases, case variants and near
//! misses, `md4`, `md5`, `sha1` and `ripemd160` at the same lengths,
//! `hmac` around each block size, `rand_bytes` and `rand_pseudo_bytes`, and
//! every argument check — through the port with the test-only registration,
//! by the oracle's own runner (`m65` harness), and compares status and
//! values byte for byte with the golden.
//!
//! - **Not compared:** `q=N` (the harness's doc).
//! - **Random rows** (`nondet:random`) are compared on status and shape.
//! - **`openssl-algorithm-subset`** (D4(b)): a `digest` or `hmac` row whose
//!   name 7.94 resolves to a digest outside D4 — SHA-3, SHAKE, BLAKE2, SM3,
//!   whirlpool, `MD5-SHA1` and their aliases, `other` in
//!   `m65_digest_names.txt` — must instead raise `Unknown digest algorithm:
//!   <name>`, the error 7.94 gives a name it does not know. Only rows on
//!   which 7.94 *succeeded* are pinned so (a pin cannot hide an error the
//!   port gets wrong), and the gate counts them.
//! - **No other exemption.** Every other row must agree exactly.
#![cfg(not(miri))] // reads the corpus from disk

mod m65;

use std::collections::HashMap;

/// The fewest rows the gate must run: the 2,322 rows tagged `c`.
const MIN_ROWS: usize = 2_322;

/// The rows pinned to `openssl-algorithm-subset`: 590 `digest` rows over
/// 43 names outside D4 (the 21 `supported_digests` names at 26 lengths
/// each, and their aliases twice each) and 150 `hmac` rows over 25.
const PINNED: usize = 740;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).expect("ascii"), 16).expect("hex"))
        .collect()
}

#[test]
fn every_digest_row_matches_nmap_794() {
    // `m65_digest_names.txt`: the oracle's class of each spelling.
    let classes: HashMap<Vec<u8>, String> = m65::read("m65_digest_names.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (h, c) = l.split_once('\t').expect("HEX<TAB>CLASS");
            (unhex(h), c.to_string())
        })
        .collect();
    let mut pinned = 0usize;
    m65::run_step(
        MIN_ROWS,
        |row| row.tags[0] == "c",
        |row, _got, want| {
            let f = &row.fields;
            if !(f[2] == "call" && (f[3] == "digest" || f[3] == "hmac")) {
                return;
            }
            let Some(name) = f.get(4).and_then(|a| a.strip_prefix("s:")) else {
                return;
            };
            let name = unhex(name);
            let class = classes
                .get(&name)
                .unwrap_or_else(|| panic!("{}: a name the table lacks", row.line));
            if class == "other" && want.status == "ok" {
                let shown = name.split(|&b| b == 0).next().unwrap_or_default();
                let mut msg = b"Unknown digest algorithm: ".to_vec();
                msg.extend_from_slice(shown);
                want.status = "err".into();
                want.values = format!("e{}", m65::render_str(&msg));
                pinned += 1;
            }
        },
    );
    assert_eq!(pinned, PINNED, "openssl-algorithm-subset pins");
}
