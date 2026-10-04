//! M6.4c differential: nmap's own Lua libraries, loaded and unit-tested in the
//! port's NSE state, against nmap itself doing the same.
//!
//! `tests/differential/m6/m64_nselib_golden.txt` records, from nmap 7.94 run
//! over this repository's `nselib/` (`oracle/gen_m64_nselib.py`), whether each
//! of the 133 libraries loads — under `nse_main.lua`'s `strict` globals, as a
//! script would require it — and whether each of the 26 libraries that ships
//! a unit-test suite passes it. Each library is required here in a fresh state
//! built by `core::nse::runtime`, its suite run through `unittest.run_tests`
//! as `scripts/unittest.nse` runs it.
//!
//! Every library and suite must do what it does under nmap, except those that
//! need a C module the port does not have yet — `lpeg`, `openssl`, `nmapdb`
//! (M6.5, M6.6) — which are pinned, in both directions, to fail for exactly
//! that reason. `M64_NSELIB_GOLDEN` names a golden to use instead of the
//! committed one; CI's differential job regenerates it live.
#![cfg(not(miri))] // reads nselib/ from disk; Miri has no filesystem

mod m6_eval;
mod nse_host;

use m6_eval::rows;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Libraries that cannot load until a C module is ported, and the module.
/// Most reach `openssl` through `stdnse.silent_require`, which raises a table
/// rather than a message; the rest name the module they could not find.
const NEEDS_MODULE: &[(&str, &str)] = &[
    ("bitcoin", "openssl"),
    ("bittorrent", "openssl"),
    ("coap", "lpeg"),
    ("datafiles", "nmapdb"),
    ("iax2", "openssl"),
    ("iscsi", "openssl"),
    ("json", "lpeg"),
    ("libssh2-utility", "openssl"),
    ("lpeg-utility", "lpeg"),
    ("mobileme", "lpeg"),
    ("mongodb", "openssl"),
    ("pgsql", "openssl"),
    ("re", "lpeg"),
    ("rpc", "nmapdb"),
    ("rsync", "openssl"),
    ("sip", "openssl"),
    ("ssh1", "openssl"),
    ("ssh2", "openssl"),
    ("tns", "openssl"),
];

fn golden() -> PathBuf {
    std::env::var_os("M64_NSELIB_GOLDEN").map_or_else(
        || nse_host::repo_root().join("nmap-rs/tests/differential/m6/m64_nselib_golden.txt"),
        PathBuf::from,
    )
}

/// The oracle's rows of `kind`: library to outcome.
fn expected(kind: &str) -> BTreeMap<String, String> {
    rows(&golden())
        .into_iter()
        .filter(|(k, _, _)| k == kind)
        .map(|(_, lib, rest)| {
            let outcome = rest.split('\t').next().unwrap_or_default().to_string();
            (lib, outcome)
        })
        .collect()
}

/// Whether `detail` is the failure a missing `module` causes.
fn missing(detail: Option<&str>, module: &str) -> bool {
    match detail {
        Some(d) => d.contains(&format!("module '{module}' not found")) || d.starts_with("table: "),
        None => false,
    }
}

#[test]
fn every_library_loads_as_under_nmap() {
    let dir = nse_host::repo_root();
    let want = expected("require");
    assert!(want.len() >= 133, "golden has {} libraries", want.len());
    let mut wrong = Vec::new();
    let mut pinned = 0;
    for (lib, outcome) in &want {
        let (got, detail) = nse_host::probe(&dir, lib, false);
        match NEEDS_MODULE.iter().find(|(l, _)| l == lib) {
            Some((_, module)) => {
                pinned += 1;
                if got != "error" || !missing(detail.as_deref(), module) {
                    wrong.push(format!(
                        "  {lib}: pinned to fail for want of `{module}`, got {got} {detail:?}"
                    ));
                }
            }
            None if got != *outcome => {
                wrong.push(format!("  {lib}: nmap {outcome}, port {got} {detail:?}"));
            }
            None => {}
        }
    }
    assert_eq!(
        pinned,
        NEEDS_MODULE.len(),
        "a pinned library is not in the golden"
    );
    assert!(
        wrong.is_empty(),
        "{} libraries differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

#[test]
fn every_unit_test_suite_passes_as_under_nmap() {
    let dir = nse_host::repo_root();
    let want = expected("unittest");
    assert!(want.len() >= 26, "golden has {} suites", want.len());
    let mut wrong = Vec::new();
    for (lib, outcome) in &want {
        let (got, detail) = nse_host::probe(&dir, lib, true);
        match NEEDS_MODULE.iter().find(|(l, _)| l == lib) {
            Some((_, module)) => {
                let failed_to_load = got == "fail"
                    && detail
                        .as_deref()
                        .is_some_and(|d| d.starts_with("Failed to load"))
                    && missing(
                        detail
                            .as_deref()
                            .map(|d| d.trim_start_matches("Failed to load: ")),
                        module,
                    );
                if !failed_to_load {
                    wrong.push(format!(
                        "  {lib}: pinned to fail to load, got {got} {detail:?}"
                    ));
                }
            }
            None if got != *outcome => {
                wrong.push(format!("  {lib}: nmap {outcome}, port {got} {detail:?}"));
            }
            None => {}
        }
    }
    assert!(
        wrong.is_empty(),
        "{} suites differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
