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
//! need a C module the port does not have yet — `lpeg`, `openssl`, `libssh2`
//! (M6.5, M6.6) — which are pinned, in both directions, to fail for exactly
//! that reason: the module they failed on, the last one no searcher found
//! while they loaded, must be the one they are pinned to. `datafiles` and
//! `rpc`, pinned to `nmapdb` until M6.6 step a ported it, now load.
//! `M64_NSELIB_GOLDEN` names a golden to use instead of the committed one;
//! CI's differential job regenerates it live.
#![cfg(not(miri))] // reads nselib/ from disk; Miri has no filesystem

mod m6_eval;
mod nse_host;

use m6_eval::rows;
use std::collections::BTreeMap;
use std::path::PathBuf;

/// Libraries that cannot load until a C module is ported, and the module.
/// Most reach `openssl` through `stdnse.silent_require`, which raises a table
/// rather than a message; the rest name the module they could not find.
/// `libssh2-utility` was pinned to `openssl` until M6.6 step a; it fails on
/// `libssh2` (`libssh2-utility.lua:15`, a `silent_require`), and
/// [`missing`] now tells the two apart.
const NEEDS_MODULE: &[(&str, &str)] = &[
    ("bitcoin", "openssl"),
    ("bittorrent", "openssl"),
    ("coap", "lpeg"),
    ("iax2", "openssl"),
    ("iscsi", "openssl"),
    ("json", "lpeg"),
    ("libssh2-utility", "libssh2"),
    ("lpeg-utility", "lpeg"),
    ("mobileme", "lpeg"),
    ("mongodb", "openssl"),
    ("pgsql", "openssl"),
    ("re", "lpeg"),
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

/// Whether a load failed for want of `module`: the last module no searcher
/// found while it ran is `module`, and the failure is what that causes —
/// `require`'s "module 'X' not found" naming it, or the table
/// `stdnse.silent_require` raises, which names nothing.
fn missing(detail: Option<&str>, not_found: &[String], module: &str) -> bool {
    let Some(d) = detail else { return false };
    not_found.last().map(String::as_str) == Some(module)
        && (d.contains(&format!("module '{module}' not found")) || d.starts_with("table: "))
}

/// [`missing`] tells one missing module from another, and a failure from
/// a load that never looked for the module (M6.6 review, sabotage S25: a
/// `missing` that accepted any table or any "not found" let `libssh2-utility`
/// be pinned to the wrong module).
#[test]
fn missing_names_one_module_and_only_that_one() {
    let libssh2 = ["libssh2".to_string()];
    let lpeg = ["lpeg".to_string()];
    // The right module, either way of failing.
    assert!(missing(Some("table: 0x1"), &libssh2, "libssh2"));
    assert!(missing(
        Some("module 'lpeg' not found:\n\tno field"),
        &lpeg,
        "lpeg"
    ));
    // Another module was the one not found.
    assert!(!missing(Some("table: 0x1"), &libssh2, "openssl"));
    assert!(!missing(
        Some("module 'lpeg' not found"),
        &["openssl".to_string()],
        "lpeg"
    ));
    // No module was looked for and not found.
    assert!(!missing(Some("module 'lpeg' not found"), &[], "lpeg"));
    assert!(!missing(Some("table: 0x1"), &[], "openssl"));
    // A failure that is neither the message nor `silent_require`'s table.
    assert!(!missing(
        Some("x.lua:3: attempt to index a nil value"),
        &lpeg,
        "lpeg"
    ));
    assert!(!missing(Some("module 'openssl' not found"), &lpeg, "lpeg"));
    // No failure at all.
    assert!(!missing(None, &lpeg, "lpeg"));
}

#[test]
fn every_library_loads_as_under_nmap() {
    let dir = nse_host::repo_root();
    let want = expected("require");
    assert!(want.len() >= 133, "golden has {} libraries", want.len());
    let mut wrong = Vec::new();
    let mut pinned = 0;
    for (lib, outcome) in &want {
        let (got, detail, not_found) = nse_host::probe_modules(&dir, lib, false);
        match NEEDS_MODULE.iter().find(|(l, _)| l == lib) {
            Some((_, module)) => {
                pinned += 1;
                if got != "error" || !missing(detail.as_deref(), &not_found, module) {
                    wrong.push(format!(
                        "  {lib}: pinned to fail for want of `{module}`, got {got} {detail:?}, \
                         modules not found {not_found:?}"
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
        let (got, detail, not_found) = nse_host::probe_modules(&dir, lib, true);
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
                        &not_found,
                        module,
                    );
                if !failed_to_load {
                    wrong.push(format!(
                        "  {lib}: pinned to fail to load for want of `{module}`, got {got} \
                         {detail:?}, modules not found {not_found:?}"
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
