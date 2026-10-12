//! M6.4c differential: nmap's own Lua libraries, loaded and unit-tested in the
//! port's NSE state, against nmap itself doing the same.
//!
//! `tests/differential/m6/m64_nselib_golden.txt` records, from nmap 7.94 run
//! over this repository's `nselib/` (`oracle/gen_m64_nselib.py`), whether each
//! of the 133 libraries loads — under `nse_main.lua`'s `strict` globals, as a
//! script would require it — and whether each of the 26 libraries that ships
//! a unit-test suite passes it, and with how many tests. Each library is
//! required here in a fresh state built by `core::nse::runtime`, its suite run
//! through `unittest.run_tests` as `scripts/unittest.nse` runs it.
//!
//! Every library and suite must do what it does under nmap, a passing suite
//! running as many tests as it does under nmap, except those that need a C
//! module the port does not have yet — `openssl`, `libssh2` (M6.5) — which are
//! pinned, in both directions, to fail for exactly that reason: the module
//! they failed on, the last one no searcher found while they loaded, must be
//! the one they are pinned to. `datafiles` and `rpc`, pinned to `nmapdb` until
//! M6.6 step a ported it, and `coap`, `json`, `lpeg-utility`, `mobileme` and
//! `re`, pinned to `lpeg` until step e registered it, now load; the `json`
//! and `coap` suites run 69 and 1,060 tests.
//!
//! And `unittest.run_tests()` over every library `unittest.lua` lists must
//! fail on the libraries it fails on under nmap with the port's missing C
//! modules removed (the golden's `unittest-all` rows, from
//! `gen_m66_scriptload.py`'s emulation): 16 since M6.6 step e, 22 before it.
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
    ("iax2", "openssl"),
    ("iscsi", "openssl"),
    ("libssh2-utility", "libssh2"),
    ("mongodb", "openssl"),
    ("pgsql", "openssl"),
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
    expected_with_detail(kind)
        .into_iter()
        .map(|(lib, (outcome, _))| (lib, outcome))
        .collect()
}

/// The oracle's rows of `kind`: library to outcome and the detail after it.
fn expected_with_detail(kind: &str) -> BTreeMap<String, (String, Option<String>)> {
    rows(&golden())
        .into_iter()
        .filter(|(k, _, _)| k == kind)
        .map(|(_, lib, rest)| {
            let mut f = rest.splitn(2, '\t');
            let outcome = f.next().unwrap_or_default().to_string();
            (lib, (outcome, f.next().map(str::to_string)))
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

/// Every suite passes as under nmap, and by its count: as many tests as
/// nmap runs without the port's missing C modules (`unittest-emu`), since a
/// suite adds the tests that need one only when it loads — sasl's, smbauth's
/// and vnc's (none left) and 30 of http's 105 need `openssl`
/// (`nse-c-modules-pending`). Those counts are nmap's own (`unittest`) for
/// every other suite, `json`'s 69 and `coap`'s 1,060 among them.
#[test]
fn every_unit_test_suite_passes_as_under_nmap() {
    let dir = nse_host::repo_root();
    let want = expected_with_detail("unittest");
    let emu = expected_with_detail("unittest-emu");
    assert!(want.len() >= 26, "golden has {} suites", want.len());
    let mut wrong = Vec::new();
    let mut counted = 0;
    for (lib, (outcome, _)) in &want {
        let count = emu
            .get(lib)
            .filter(|(o, _)| o == "pass")
            .and_then(|(_, n)| n.clone());
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
            // A passing suite passes by its count: as many tests as under
            // nmap (`oracle/m64_probe_unittest.nse`'s third field).
            None if got == "pass" => {
                counted += 1;
                if count.is_none() || detail != count {
                    wrong.push(format!(
                        "  {lib}: passed with {detail:?} tests, nmap without the missing \
                         modules ran {count:?}"
                    ));
                }
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
    // Every suite not pinned passed, json's and coap's among them.
    assert_eq!(
        counted,
        want.len()
            - NEEDS_MODULE
                .iter()
                .filter(|(l, _)| want.contains_key(*l))
                .count()
    );
    // json's and coap's suites, which reach lpeg, run every test nmap runs.
    for (lib, n) in [("json", "69"), ("coap", "1060")] {
        for rows in [&want, &emu] {
            assert_eq!(
                rows.get(lib),
                Some(&("pass".to_string(), Some(n.to_string()))),
                "{lib}: the golden's count"
            );
        }
    }
}

/// `unittest.run_tests()` over every library `unittest.lua` lists, as
/// `scripts/unittest.nse` runs it with no `unittest.tests`: the libraries
/// that fail, and on what — the module no searcher found, or the table
/// `stdnse.silent_require` raises — must be those nmap fails on with the
/// port's missing C modules removed (`unittest-all`,
/// `oracle/m64_probe_unittest_all.nse`, the same Lua). 16 since M6.6 step e
/// registered `lpeg` (22 before it: `coap`, `json`, `lpeg`, `lpeg-utility`,
/// `mobileme` and `re` as well), all on `openssl`, `libssh2`, `lfs` or `zlib`.
#[test]
fn every_library_unittest_lists_fails_only_as_under_nmap_without_the_missing_modules() {
    use nmap_core::nse::runtime::{run_chunk, ChunkOutcome};
    let want: Vec<(String, String)> = expected("unittest-all").into_iter().collect();
    assert!(!want.is_empty(), "the golden has no unittest-all rows");
    let mut st = nse_host::state(&nse_host::repo_root()).expect("state");
    let src = "local unittest = require 'unittest'\n\
               local fails = unittest.run_tests()\n\
               local names, out = {}, {}\n\
               for name in pairs(fails) do names[#names + 1] = name end\n\
               table.sort(names)\n\
               for _, name in ipairs(names) do\n\
                 local f = tostring(fails[name])\n\
                 local kind = f:match(\"^Failed to load: .-module '([^']+)' not found\")\n\
                 if not kind and f:match('^Failed to load: table: ') then kind = 'silent_require' end\n\
                 out[#out + 1] = name .. '\\t' .. (kind or ('other: ' .. f:gsub('\\n', '\\\\n')))\n\
               end\n\
               return table.concat(out, '\\n')";
    let got: Vec<(String, String)> =
        match run_chunk(&mut st.lua, "=unittest-all", src.as_bytes(), 50_000_000_000) {
            ChunkOutcome::Returned(v) => v[0]
                .lines()
                .map(|l| {
                    let (a, b) = l.split_once('\t').unwrap_or((l, ""));
                    (a.to_string(), b.to_string())
                })
                .collect(),
            other => panic!("unittest.run_tests(): {other:?}"),
        };
    assert_eq!(
        got, want,
        "unittest.run_tests() fails otherwise than under nmap"
    );
    eprintln!("unittest.run_tests(): {} libraries fail to load", got.len());
}
