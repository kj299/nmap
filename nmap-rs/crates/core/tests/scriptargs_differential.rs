//! M6.3 differential: `--script-args` / `--script-args-file` against nmap's own
//! Lua and LPeg.
//!
//! `core::nse::scriptargs` ports `nse_main.lua:1245-1291` — joining the file
//! and the command line, and the LPeg grammar that turns the result into
//! `nmap.registry.args`. The corpus in `tests/differential/m6/m63_args_*.txt`
//! is that code, sliced verbatim out of `nse_main.lua`, run by nmap's own
//! interpreter and PEG engine over 20,517 inputs; a sample was also checked
//! against the nmap 7.94 binary itself.
//!
//! Every verdict is compared exactly: the parsed table, rendered canonically,
//! or the refusal. One divergence is pinned rather than exempted: nmap's LPeg
//! runs out of backtrack stack ("too many pending calls/choices") on tables
//! nested 11 to 15 deep, and this port parses them
//! (DIVERGENCES.md, `nse-script-args-depth-ceiling`). Those cases are the
//! `depth_*` probes, and any other case the oracle refuses that way fails.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

use nmap_core::nse::scriptargs::{registry_args, ArgTable, ArgValue, ArgsError};
use std::collections::HashMap;
use std::path::{Path, PathBuf};

fn corpus(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

fn rows(file: &str) -> Vec<Vec<String>> {
    let p = corpus(file);
    std::fs::read(&p)
        .unwrap_or_else(|e| panic!("{}: {e}", p.display()))
        .split(|&b| b == b'\n')
        .filter(|l| !l.is_empty() && l[0] != b'#')
        .map(|l| {
            String::from_utf8(l.to_vec())
                .expect("the corpus is hex and ASCII")
                .split('\t')
                .map(str::to_string)
                .collect()
        })
        .collect()
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).expect("ascii"), 16).expect("hex"))
        .collect()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|c| format!("{c:02x}")).collect()
}

/// The driver's `render`: positional values, then keys in byte order.
fn render(t: &ArgTable) -> String {
    fn value(v: &ArgValue) -> String {
        match v {
            ArgValue::Str(s) => format!("s{}", hex(s)),
            ArgValue::Table(t) => render(t),
        }
    }
    let mut keyed: Vec<_> = t.fields.iter().collect();
    keyed.sort_by(|a, b| a.0.cmp(&b.0));
    let parts: Vec<String> = t
        .array
        .iter()
        .map(value)
        .chain(
            keyed
                .iter()
                .map(|(k, v)| format!("{}={}", hex(k), value(v))),
        )
        .collect();
    format!("{{{}}}", parts.join(","))
}

#[test]
fn script_args_match_nmaps_own_lpeg_exactly() {
    let golden: HashMap<String, Vec<String>> = rows("m63_args_golden.txt")
        .into_iter()
        .map(|mut r| (r.remove(0), r))
        .collect();
    let cases = rows("m63_args_cases.txt");
    assert!(cases.len() >= 20_000, "corpus shrank to {}", cases.len());

    let mut mismatches = Vec::new();
    let mut ceiling = 0;
    for c in &cases {
        let (name, file, cli) = (&c[0], &c[1], &c[2]);
        let file = (file != "-").then(|| unhex(file));
        let got = registry_args(file.as_deref(), &unhex(cli));
        let want = golden
            .get(name)
            .unwrap_or_else(|| panic!("{name}: in cases but not in golden"));
        let ok = match (want[0].as_str(), &got) {
            ("ok", Ok(t)) => want.get(1) == Some(&render(t)),
            ("nomatch", Err(ArgsError::NoMatch)) => true,
            // The pinned divergence: LPeg's stack gives out, this port parses.
            ("error:backtrack", Ok(_)) if name.starts_with("depth_") => {
                ceiling += 1;
                true
            }
            _ => false,
        };
        if !ok {
            mismatches.push(format!("  {name}: lua = {want:?}, port = {got:?}"));
        }
    }
    assert!(
        mismatches.is_empty(),
        "{} of {} diverge:\n{}",
        mismatches.len(),
        cases.len(),
        mismatches[..mismatches.len().min(30)].join("\n")
    );
    // The depth probes do reach past the C's ceiling; if they stop doing so the
    // pinned divergence is no longer being exercised.
    assert!(
        ceiling >= 20,
        "only {ceiling} cases reach LPeg's stack ceiling"
    );
}
