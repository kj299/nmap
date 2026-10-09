//! M6.6 gate: every shipped script loads, alone, as it loads under nmap 7.94
//! missing the same C modules.
//!
//! `tests/differential/m6/m66_scriptload_golden.txt` records, for each of the
//! 611 scripts in `scripts/`, how nmap 7.94 ends `--script-help` on it alone
//! (`oracle/gen_m66_scriptload.py`), with the modules in its `missing` header
//! line removed from `package.loaded` before scripts load:
//!
//! - `OK`: the script loaded;
//! - `LOUD`: a hard `require` failed, and nmap quit; with the first
//!   `file:line: module 'X' not found` it printed, the path stripped to the
//!   file's name;
//! - `QUIET`: `stdnse.silent_require` failed, and the script was dropped.
//!
//! The port refuses `--script-help`, so this loads each script through the
//! engine instead, as the command line does: in a fresh state at `-v`, the
//! script chosen by its path with [`nmap_core::nse::choose`] and loaded by
//! `NseState::load_chosen`. What nmap's engine logs is the same text here,
//! and the same rules classify it.
//!
//! There are no pins. The golden's missing set must be the port's, which
//! `the_missing_modules_are_the_ports` checks, so porting a module fails
//! this test until the generator's `PORT_MISSING` drops it and the golden is
//! regenerated.
//! `M66_SCRIPTLOAD_GOLDEN` names a golden to use instead of the committed
//! one; CI's differential job regenerates it live.
#![cfg(all(unix, not(miri)))] // loads scripts from disk; the locator is unix-only

mod nse_host;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::nse::choose::{choose, RuleOptions};
use nmap_core::nse::nmaplib::{NmapEnv, NmapLib};
use nmap_core::nse::runtime::{new_state, run_chunk, ChunkOutcome, NseState, StateConfig};
use nmap_core::nse::script::{parse_script_db, ScriptDb};
use nmap_core::nse::scriptargs::ArgTable;

/// The C modules nmap registers that a missing set may name.
const MODULES: [&str; 6] = ["lfs", "libssh2", "lpeg", "nmapdb", "openssl", "zlib"];

fn golden() -> PathBuf {
    std::env::var_os("M66_SCRIPTLOAD_GOLDEN").map_or_else(
        || nse_host::scenarios::m6().join("m66_scriptload_golden.txt"),
        PathBuf::from,
    )
}

/// One load: `OK`, `LOUD` or `QUIET`, and the detail.
type Outcome = (String, String);

/// The golden: its missing set, and each script's outcome.
fn read_golden(path: &Path) -> (Vec<String>, BTreeMap<String, Outcome>) {
    let text = std::fs::read_to_string(path).expect("golden");
    let mut missing = None;
    let mut rows = BTreeMap::new();
    for line in text.lines() {
        if let Some(set) = line.strip_prefix("# missing: ") {
            missing = Some(set.split(',').map(str::to_string).collect());
        } else if !line.starts_with('#') {
            let f: Vec<&str> = line.split('\t').collect();
            assert_eq!(f.len(), 3, "golden row {line:?}");
            rows.insert(f[0].to_string(), (f[1].to_string(), f[2].to_string()));
        }
    }
    (missing.expect("a `# missing:` header line"), rows)
}

/// A fresh state over this repository at `-v`, its log written to `log`.
fn state(log: &Rc<RefCell<Vec<u8>>>) -> NseState {
    let dir = nse_host::repo_root();
    let sink = Rc::clone(log);
    new_state(&StateConfig {
        lib: NmapLib::new(NmapEnv {
            verbose: 1,
            log: Box::new(move |_, b| sink.borrow_mut().extend_from_slice(b)),
            ..nse_host::env(dir.clone())
        }),
        args: ArgTable::default(),
        source: Rc::new(nse_host::Dir(dir)),
        fs: Rc::new(nse_host::ReadOnlyFs),
        os: Rc::new(nse_host::os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
        net: Rc::new(RefCell::new(nmap_core::nse::net::NoNet)),
    })
    .expect("state")
}

/// Which of [`MODULES`] the port's state lacks: neither in `package.loaded`
/// nor in `package.preload`.
fn port_missing() -> Vec<String> {
    let mut st = state(&Rc::default());
    let list = MODULES.map(|m| format!("{m:?}")).join(",");
    let src = format!(
        "local out = {{}}\n\
         for _, m in ipairs({{{list}}}) do\n\
           if package.loaded[m] == nil and package.preload[m] == nil then\n\
             out[#out + 1] = m\n\
           end\n\
         end\n\
         return table.concat(out, ',')"
    );
    match run_chunk(&mut st.lua, "=missing", src.as_bytes(), 10_000_000) {
        ChunkOutcome::Returned(v) => v[0]
            .split(',')
            .filter(|m| !m.is_empty())
            .map(str::to_string)
            .collect(),
        other => panic!("the missing-module chunk: {other:?}"),
    }
}

/// The file's name, as the generator strips a path.
fn basename(s: &str) -> &str {
    s.rsplit('/').next().unwrap_or(s)
}

/// How a load ended, by the generator's rules, from what the engine logged
/// and the error it ended with.
fn classify(log: &str, result: &Result<(), String>) -> Outcome {
    static NOT_FOUND: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let not_found = NOT_FOUND.get_or_init(|| {
        regex::Regex::new(r"[a-zA-Z0-9_./-]*:[0-9]*: module '[^']*' not found").expect("pattern")
    });
    match result {
        Err(e) => {
            let text = format!("{log}{e}\n");
            let lines: Vec<&str> = text.lines().collect();
            let detail = lines
                .iter()
                .find_map(|l| not_found.find(l))
                .map(|m| basename(m.as_str()).to_string())
                .or_else(|| {
                    let i = lines.iter().position(|l| l.contains("Failed to load"))?;
                    lines
                        .get(i.saturating_add(1))
                        .map(|l| basename(l).to_string())
                })
                .unwrap_or_default();
            ("LOUD".into(), detail)
        }
        Ok(())
            if log.contains("Failed to load '")
                && log.contains("Loaded 0 scripts for scanning.") =>
        {
            ("QUIET".into(), String::new())
        }
        Ok(())
            if !log.contains("Failed to load")
                && log.contains("Loaded 1 scripts for scanning.") =>
        {
            ("OK".into(), String::new())
        }
        Ok(()) => ("UNKNOWN".into(), log.replace('\n', "\\n")),
    }
}

/// Load `scripts/NAME.nse` alone, as the command line loads what `--script`
/// chose, in a fresh state.
fn load(name: &str, db: &ScriptDb) -> Outcome {
    let repo = nse_host::repo_root();
    let path = repo.join("scripts").join(format!("{name}.nse"));
    let rules = vec![path.to_string_lossy().into_owned().into_bytes()];
    let chosen = choose(
        &rules,
        RuleOptions::default(),
        db,
        &nse_host::scenarios::Locator(repo),
    );
    let log = Rc::new(RefCell::new(Vec::new()));
    let mut st = state(&log);
    let result = st.load_chosen(&chosen, Some(1 << 30));
    let text = String::from_utf8_lossy(&log.borrow()).into_owned();
    classify(&text, &result)
}

#[test]
fn the_missing_modules_are_the_ports() {
    let (mut want, _) = read_golden(&golden());
    want.sort();
    assert_eq!(
        port_missing(),
        want,
        "the port lacks the modules on the left, and the golden was generated without those \
         on the right: make PORT_MISSING in oracle/gen_m66_scriptload.py the port's set, \
         and regenerate the golden"
    );
}

#[test]
fn every_script_loads_as_under_nmap() {
    let (_, want) = read_golden(&golden());
    let mut shipped: Vec<String> = std::fs::read_dir(nse_host::repo_root().join("scripts"))
        .expect("scripts/")
        .flatten()
        .filter_map(|e| {
            e.file_name()
                .to_str()
                .and_then(|n| n.strip_suffix(".nse"))
                .map(str::to_string)
        })
        .collect();
    shipped.sort();
    let names: Vec<String> = want.keys().cloned().collect();
    assert_eq!(names, shipped, "the golden's scripts are not scripts/'s");
    assert!(names.len() >= 611, "only {} scripts", names.len());

    let db = std::fs::read(nse_host::repo_root().join("scripts/script.db")).expect("script.db");
    let db = parse_script_db(&db).expect("script.db parses");
    // One state per script, in a few threads: each builds its own.
    let next = std::sync::atomic::AtomicUsize::new(0);
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get().min(8));
    let got: BTreeMap<String, Outcome> = std::thread::scope(|s| {
        let workers: Vec<_> = (0..threads)
            .map(|_| {
                s.spawn(|| {
                    let mut out = Vec::new();
                    loop {
                        let i = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                        let Some(name) = names.get(i) else { break };
                        out.push((name.clone(), load(name, &db)));
                    }
                    out
                })
            })
            .collect();
        workers
            .into_iter()
            .flat_map(|w| w.join().expect("worker"))
            .collect()
    });

    let mut wrong = Vec::new();
    let mut totals: BTreeMap<&str, usize> = BTreeMap::new();
    for (name, w) in &want {
        let g = &got[name];
        let n = totals.entry(g.0.as_str()).or_default();
        *n = n.saturating_add(1);
        if g != w {
            wrong.push(format!(
                "  {name}: nmap {} {:?}, port {} {:?}",
                w.0, w.1, g.0, g.1
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} scripts load differently ({totals:?}):\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
