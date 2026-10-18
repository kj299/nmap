//! Differential: the M6.5 `openssl` corpus, every row of step d (`encrypt`,
//! `decrypt`, `DES_string_to_key`).
//!
//! `tests/differential/m6/m65_cases.txt` is run by nmap 7.94 into
//! `m65_golden.txt` (`oracle/gen_m65.py`, step a). This gate runs every row
//! tagged `d` through the port with the test-only registration, by the
//! oracle's own runner (`m65` harness), and compares status and values byte
//! for byte with the golden. That covers each of the 170 cipher names'
//! key-length sweep, its data sweep at the block edges with and without
//! padding, every IV shape (the right one, none, empty, NUL-led, one byte
//! long and short), encrypt-then-decrypt round trips, the padding argument's
//! truthiness, every alias and near miss, `DES_string_to_key` over 200
//! random strings and the wrong lengths, and every argument check.
//!
//! - **Not compared:** `q=N` (the harness's doc).
//! - **`openssl-algorithm-subset`** (D4(b)): every row whose cipher 7.94
//!   resolves outside D4 (`other` in `m65_cipher_names.txt`: 3DES, DESX,
//!   RC2, RC4, Blowfish, CAMELLIA, ARIA, SEED, SM4, ChaCha20, the AES
//!   modes but ECB and CBC, ...) must raise `Unknown cipher algorithm:
//!   <name>`. The C looks the name up before it reads any other argument
//!   (`nse_openssl.cc:407-409`), so the port's answer on such a row depends
//!   on the name alone, and every such row is pinned whatever 7.94 said
//!   there: these include the `nondet:random-iv` rows (GCM and key wrap)
//!   and the two `ub:rc4-empty-key` rows. The gate counts them by 7.94's
//!   status.
//! - **`ivnul` drift** (D1 (c)): on a D4 cipher, an IV whose first byte is
//!   NUL is no IV to 7.94 (which read it with `luaL_optstring`) and an IV to
//!   this tree's C. The port follows the tree: those rows are held to its
//!   answers, `m65_drift_tree.txt`.
//! - **`ub:iv-length-uaf`** (`nse-openssl-iv-length-uaf`): on a D4 cipher,
//!   an IV of the wrong length; the golden holds the message the C means,
//!   from the oracle's one named repair, and the port must raise it.
//! - **No other exemption.** Every other row must agree exactly.
#![cfg(not(miri))] // reads the corpus from disk

mod m65;

use std::collections::HashMap;

/// The fewest rows the gate must run: the 12,949 rows tagged `d`.
const MIN_ROWS: usize = 12_949;

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).expect("ascii"), 16).expect("hex"))
        .collect()
}

#[test]
fn every_cipher_row_matches_nmap_794() {
    let classes: HashMap<Vec<u8>, String> = m65::read("m65_cipher_names.txt")
        .lines()
        .filter(|l| !l.starts_with('#'))
        .map(|l| {
            let (h, c) = l.split_once('\t').expect("HEX<TAB>CLASS");
            (unhex(h), c.to_string())
        })
        .collect();
    let tree = m65::drift_tree();
    let families = m65::drift_families();
    let mut pinned: HashMap<String, usize> = HashMap::new();
    let (mut ivnul, mut uaf) = (0usize, 0usize);
    m65::run_step(
        MIN_ROWS,
        |row| row.tags[0] == "d",
        |row, _got, want| {
            let f = &row.fields;
            let name = match (f[2], f[3]) {
                ("call", "encrypt" | "decrypt") => {
                    match f.get(4).and_then(|a| a.strip_prefix("s:")) {
                        Some(h) => unhex(h),
                        None => return,
                    }
                }
                ("rt", cipher) => cipher.as_bytes().to_vec(),
                _ => return,
            };
            let class = classes
                .get(&name)
                .unwrap_or_else(|| panic!("{}: a name the table lacks", row.line));
            if class == "other" {
                *pinned.entry(want.status.clone()).or_default() += 1;
                let shown = name.split(|&b| b == 0).next().unwrap_or_default();
                let mut msg = b"Unknown cipher algorithm: ".to_vec();
                msg.extend_from_slice(shown);
                want.status = "err".into();
                want.values = format!("e{}", m65::render_str(&msg));
            } else if families
                .get(row.fields[0])
                .is_some_and(|fam| fam == "ivnul")
            {
                *want = tree[row.fields[0]].clone();
                ivnul += 1;
            } else if row.tags.contains(&"ub:iv-length-uaf") {
                assert!(
                    want.values.starts_with("e\"Length of iv is "),
                    "{}",
                    row.line
                );
                want.status = "err".into();
                uaf += 1;
            }
        },
    );
    let mut counts: Vec<_> = pinned.into_iter().collect();
    counts.sort();
    eprintln!("openssl-algorithm-subset pins by 7.94's status: {counts:?}; ivnul {ivnul}, iv-length-uaf {uaf}");
    let total: usize = counts.iter().map(|(_, n)| n).sum();
    assert_eq!(total, PINNED, "openssl-algorithm-subset pins");
    assert_eq!(
        (ivnul, uaf),
        (IVNUL, UAF),
        "ivnul drift rows, iv-length-uaf rows"
    );
}

/// The rows pinned to `openssl-algorithm-subset`: 6,336 on which 7.94
/// succeeded, 3,825 on which it raised an error, and 1,588 it never ran
/// (`ub:`, on ciphers outside D4).
const PINNED: usize = 11_749;
/// The `ivnul` drift rows on D4 ciphers, held to the tree's answers.
const IVNUL: usize = 30;
/// The `ub:iv-length-uaf` rows on D4 ciphers, held to the message the C means.
const UAF: usize = 102;
