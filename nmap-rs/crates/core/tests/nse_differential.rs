//! M6.1 differential: `core::nse::script` against nmap's own Lua.
//!
//! The corpus and its golden verdicts are derived by
//! `tests/differential/m6/regen_m6.sh`, which builds `liblua/` from this
//! repository and runs loading logic sliced verbatim out of `nse_main.lua`. The
//! golden file records two columns: what that interpreter did, and what this
//! port must do. Where they disagree the divergence is deliberate and ledgered
//! in `DIVERGENCES.md`; the second test below pins that set exactly, so a new
//! divergence cannot appear without editing this file.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

use nmap_core::nse::script::{parse_nse_metadata, parse_script_db, Field};
use std::path::{Path, PathBuf};

fn corpus_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .ancestors()
        .nth(2)
        .expect("repository layout")
        .join("tests/differential/m6")
}

fn rows(name: &str) -> Vec<Vec<String>> {
    let text =
        std::fs::read_to_string(corpus_dir().join(name)).unwrap_or_else(|e| panic!("{name}: {e}"));
    text.lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
        .map(|l| l.split('\t').map(str::to_owned).collect())
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2), "odd-length hex");
    s.as_bytes()
        .chunks(2)
        .map(|p| {
            u8::from_str_radix(std::str::from_utf8(p).expect("hex is ASCII"), 16).expect("hex")
        })
        .collect()
}

/// The oracle's `esc()`: everything outside `[%w%.%-_/ ]` becomes `%XX`.
fn esc(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'/' | b' ') {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

/// This port's verdict on a `script.db`, in the golden file's vocabulary.
fn db_verdict(input: &[u8]) -> String {
    match parse_script_db(input) {
        Err(_) => "REJECT".to_owned(),
        Ok(db) => {
            let body: Vec<String> = db
                .entries()
                .iter()
                .map(|e| {
                    let cats: Vec<String> = e.categories().iter().map(|c| esc(c)).collect();
                    format!("{}={}", esc(e.filename()), cats.join(","))
                })
                .collect();
            format!("ACCEPT:{}", body.join("|"))
        }
    }
}

/// This port's verdict on a `.nse` source. A field this parser will not claim to
/// know is a refusal here, not a guess.
fn nse_verdict(input: &[u8]) -> String {
    let Ok(m) = parse_nse_metadata(input) else {
        return "REJECT".to_owned();
    };
    let (Field::Literal(cats), Field::Literal(deps)) = (m.categories(), m.dependencies()) else {
        return "REJECT".to_owned();
    };
    let (Field::Literal(desc), Field::Literal(author), Field::Literal(license)) =
        (m.description(), m.author(), m.license())
    else {
        return "REJECT".to_owned();
    };
    let list = |v: &[Vec<u8>]| v.iter().map(|s| esc(s)).collect::<Vec<_>>().join(",");
    let r = m.rules();
    let mut names = Vec::new();
    for (on, n) in [
        (r.prerule, "prerule"),
        (r.hostrule, "hostrule"),
        (r.portrule, "portrule"),
        (r.postrule, "postrule"),
    ] {
        if on {
            names.push(n);
        }
    }
    format!(
        "ACCEPT:cats={};deps={};rules={};desc={};author={};license={}",
        list(cats),
        list(deps),
        names.join(","),
        esc(desc),
        esc(author),
        esc(license),
    )
}

fn run(cases: &str, golden: &str, verdict: impl Fn(&[u8]) -> String) -> Vec<String> {
    let cases = rows(cases);
    let golden = rows(golden);
    assert_eq!(
        cases.len(),
        golden.len(),
        "corpus and golden disagree in size"
    );
    assert!(cases.len() > 20, "corpus looks truncated");

    let mut divergent = Vec::new();
    for (c, g) in cases.iter().zip(golden.iter()) {
        let (name, hex) = (&c[0], &c[1]);
        assert_eq!(name, &g[0], "corpus and golden are out of order");
        let (oracle, expected) = (&g[1], &g[2]);
        let got = verdict(&unhex(hex));
        assert_eq!(
            &got, expected,
            "{name}: this port disagrees with its own golden verdict"
        );
        let oracle_accepted = oracle.starts_with("LUA_OK:");
        if oracle_accepted != expected.starts_with("ACCEPT:") {
            divergent.push(name.clone());
        }
    }
    divergent
}

#[test]
fn script_db_matches_nmaps_own_lua() {
    let divergent = run(
        "m6_scriptdb_cases.txt",
        "m6_scriptdb_golden.txt",
        db_verdict,
    );
    // Every one of these is nmap's Lua accepting a *program* where the generated
    // format is data. Ledgered as `nse-scriptdb-not-evaluated`.
    assert_eq!(
        divergent,
        vec![
            "not_entry_call".to_owned(),
            "loop_generates_entries".to_owned(),
            "conditional_entry".to_owned(),
            "entry_rebound".to_owned(),
        ],
        "the set of script.db divergences changed"
    );
}

#[test]
fn nse_metadata_matches_nmaps_own_lua() {
    let divergent = run("m6_nse_cases.txt", "m6_nse_golden.txt", nse_verdict);
    // Every one of these is metadata the C obtains by *running the script*.
    // Ledgered as `nse-metadata-not-executed`.
    assert_eq!(
        divergent,
        vec![
            "computed_categories".to_owned(),
            "categories_from_call".to_owned(),
            "categories_via_table_insert".to_owned(),
        ],
        "the set of .nse metadata divergences changed"
    );
}

/// Nothing nmap's Lua refuses may be accepted here. The reverse is allowed and
/// pinned above; this direction never is, because it would mean loading a script
/// index or a script that the reference implementation considers malformed.
#[test]
fn nothing_the_oracle_rejects_is_ever_accepted_here() {
    for (cases, golden, f) in [
        (
            "m6_scriptdb_cases.txt",
            "m6_scriptdb_golden.txt",
            &db_verdict as &dyn Fn(&[u8]) -> String,
        ),
        ("m6_nse_cases.txt", "m6_nse_golden.txt", &nse_verdict),
    ] {
        for (c, g) in rows(cases).iter().zip(rows(golden).iter()) {
            if g[1].starts_with("LUA_ERR:") {
                assert_eq!(
                    f(&unhex(&c[1])),
                    "REJECT",
                    "{}: nmap's Lua refuses this and this port does not",
                    c[0]
                );
            }
        }
    }
}
