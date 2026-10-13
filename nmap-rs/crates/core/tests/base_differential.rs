//! Differential: the base and coroutine libraries (`core::nse::stdlib::base`)
//! against nmap itself, as an NSE script meets them.
//!
//! `tests/differential/m6/m6_base_golden.txt` is what nmap 7.94 wrote running
//! `oracle/m6_base_probe.nse` as a prerule (`oracle/gen_m6_base.py`): one line
//! per row, `row|name|values` — the base library's argument checks and
//! results, the coroutine functions inside a script's own coroutine, the
//! collector as nmap's state starts it, `string.char`, the string
//! metatable's arithmetic, the table functions' checks, table borders — and
//! what `warn` wrote to standard error, `warn|line`.
//!
//! This test runs the same probe through the port's engine, with `warn`'s
//! output captured, and requires the same lines, line for line, but for the
//! rows [`PINS`] lists: each must give the port's own answer there, exactly,
//! and still differ from nmap's, so the list is the divergence and no more.
//!
//! `M6_BASE_GOLDEN` names a different golden file: CI regenerates one against
//! the installed nmap and points this test at it.
#![cfg(all(unix, not(miri)))] // reads the golden from disk; the locator is unix-only

mod nse_host;

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;

use nmap_core::nse::choose::{choose, RuleOptions};
use nmap_core::nse::nmaplib::{NmapEnv, NmapLib, Phase};
use nmap_core::nse::runtime::{new_state, StateConfig};
use nmap_core::nse::script::parse_script_db;
use nmap_core::nse::scriptargs::registry_args;
use nmap_core::nse::stdlib::base::set_warning_sink;
use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};

/// The rows where the port answers otherwise than nmap 7.94: the row, the
/// port's values, exactly, and the ledger entry that records why.
const PINS: [(&str, &str, &str); 7] = [
    // `#t` of a table with holes: a border in both, which one decided by the
    // array size PUC-Lua reaches through its rehashes (stage 2): 8, `7,6`,
    // and `x` appended at 9 there.
    ("border_sparse", "4", "vm-table-border-is-not-luas"),
    ("border_len_twice", "7,3", "vm-table-border-is-not-luas"),
    (
        "border_insert_holes",
        "1,2,nil,4,x,6,nil,8,nil,nil",
        "vm-table-border-is-not-luas",
    ),
    // Called by `pcall`, a C function, PUC-Lua names the function from
    // `package.loaded`, `'string.char'`; the binding names itself.
    (
        "create_table",
        "false,bad argument #1 to 'create' (function expected, got table)",
        "stdlib-bad-argument-naming",
    ),
    (
        "char",
        "false,bad argument #1 to 'char' (value out of range)",
        "stdlib-bad-argument-naming",
    ),
    (
        "insert_pos",
        "false,bad argument #2 to 'insert' (position out of bounds)",
        "stdlib-bad-argument-naming",
    ),
    (
        "remove_pos",
        "false,bad argument #2 to 'remove' (position out of bounds)",
        "stdlib-bad-argument-naming",
    ),
];

/// The fewest `row` lines the golden may hold: the probe is shared by the
/// oracle and the port, so a probe weakened and regenerated in place would
/// pass on what is left.
const MIN_ROWS: usize = 67;

/// The name the probe's output file goes by; the file system below keeps it
/// in memory.
const OUT: &str = "/m6-base-probe.out";

fn golden() -> PathBuf {
    std::env::var_os("M6_BASE_GOLDEN").map_or_else(
        || nse_host::scenarios::m6().join("m6_base_golden.txt"),
        PathBuf::from,
    )
}

/// The probe's output file, in memory.
struct Capture(Rc<RefCell<Vec<u8>>>);

impl ScriptFile for Capture {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, FsError> {
        Ok(0)
    }
    fn write(&mut self, data: &[u8]) -> Result<(), FsError> {
        self.0.borrow_mut().extend_from_slice(data);
        Ok(())
    }
    fn seek(&mut self, _: Whence, _: i64) -> Result<u64, FsError> {
        Ok(0)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}

/// Every file for reading, and [`OUT`] for writing.
struct ProbeFs(Rc<RefCell<Vec<u8>>>);

impl ScriptFs for ProbeFs {
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        if path == OUT.as_bytes() && mode.writes() {
            self.0.borrow_mut().clear();
            return Ok(Box::new(Capture(Rc::clone(&self.0))));
        }
        nse_host::ReadOnlyFs.open(path, mode)
    }
    fn stdout(&self) -> Box<dyn ScriptFile> {
        nse_host::ReadOnlyFs.stdout()
    }
}

/// Run the probe as a prerule, as the generator runs it under nmap: its
/// lines without the final `done`, then `warn`'s output as `warn|` lines.
fn run_probe() -> Vec<String> {
    let dir = nse_host::repo_root();
    let out = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&log);
    let probe = nse_host::scenarios::m6().join("oracle/m6_base_probe.nse");
    let rules = vec![probe.to_string_lossy().into_owned().into_bytes()];
    let db = parse_script_db(&std::fs::read(dir.join("scripts/script.db")).expect("script.db"))
        .expect("script.db parses");
    let chosen = choose(
        &rules,
        RuleOptions::default(),
        &db,
        &nse_host::scenarios::Locator(dir.clone()),
    );
    let mut st = new_state(&StateConfig {
        lib: NmapLib::new(NmapEnv {
            log: Box::new(move |_, b| sink.borrow_mut().extend_from_slice(b)),
            ..nse_host::env(dir.clone())
        }),
        args: registry_args(None, format!("out={OUT}").as_bytes()).expect("arguments parse"),
        source: Rc::new(nse_host::Dir(dir.clone())),
        fs: Rc::new(ProbeFs(Rc::clone(&out))),
        os: Rc::new(nse_host::os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
        net: Rc::new(RefCell::new(nmap_core::nse::net::NoNet)),
    })
    .expect("state");
    let warned = Rc::new(RefCell::new(Vec::new()));
    let w = Rc::clone(&warned);
    st.lua
        .enter(|ctx| set_warning_sink(ctx, move |b| w.borrow_mut().extend_from_slice(b)));
    const BUDGET: Option<u64> = Some(1 << 36);
    st.load_chosen(&chosen, BUDGET).expect("the probe loads");
    let r = st.run_phase(Phase::PreScan, vec![], BUDGET);
    assert_eq!(r.aborted, None, "the probe's phase aborted");
    let text: String = out.borrow().iter().map(|&b| char::from(b)).collect();
    let mut lines: Vec<String> = text.lines().map(str::to_string).collect();
    assert_eq!(
        lines.last().map(String::as_str),
        Some("done"),
        "the probe did not finish; the engine logged:\n{}",
        String::from_utf8_lossy(&log.borrow())
    );
    lines.pop();
    let warned: String = warned.borrow().iter().map(|&b| char::from(b)).collect();
    lines.extend(warned.lines().map(|l| format!("warn|{l}")));
    lines
}

/// The golden's lines (latin-1), its header apart.
fn read_golden() -> (Vec<String>, Vec<String>) {
    let path = golden();
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let text: String = bytes.iter().map(|&b| char::from(b)).collect();
    text.lines()
        .map(str::to_string)
        .partition(|l| l.starts_with('#'))
}

/// A line's row name, for a `row|name|values` line.
fn name(line: &str) -> Option<&str> {
    line.strip_prefix("row|")?.split('|').next()
}

#[test]
fn the_base_library_answers_as_nmap_does() {
    let (header, want) = read_golden();
    assert!(
        header.iter().any(|h| h.contains("Nmap version 7.94")),
        "the golden does not record nmap's version: {header:?}"
    );
    let rows = want.iter().filter(|l| l.starts_with("row|")).count();
    assert!(rows >= MIN_ROWS, "only {rows} rows in the golden");
    assert!(
        want.iter().any(|l| l.starts_with("warn|")),
        "the golden records no warning"
    );
    let got = run_probe();
    assert_eq!(
        got.iter().map(|l| name(l)).collect::<Vec<_>>(),
        want.iter().map(|l| name(l)).collect::<Vec<_>>(),
        "the port wrote other rows, or in another order"
    );
    let mut wrong = Vec::new();
    let mut pinned = 0usize;
    for (w, g) in want.iter().zip(got.iter()) {
        let pin = name(w).and_then(|n| PINS.iter().find(|(row, _, _)| *row == n));
        match pin {
            Some((row, values, ledger)) => {
                pinned += 1;
                let port = format!("row|{row}|{values}");
                if *g != port {
                    wrong.push(format!(
                        "  {row} (pinned, {ledger}):\n    pin  {port}\n    port {g}"
                    ));
                } else if w == g {
                    wrong.push(format!(
                        "  {row}: pinned under {ledger}, but now nmap's answer: take the pin out"
                    ));
                }
            }
            None if w != g => wrong.push(format!("  nmap {w}\n  port {g}")),
            None => {}
        }
    }
    assert_eq!(pinned, PINS.len(), "a pinned row is not in the golden");
    assert!(
        wrong.is_empty() && want.len() == got.len(),
        "{} of {} lines differ (nmap {} lines, port {}):\n{}",
        wrong.len(),
        want.len(),
        want.len(),
        got.len(),
        wrong.join("\n")
    );
}
