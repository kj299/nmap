//! Differential: the step 0b LPeg corpus, every row the port can run so far.
//!
//! `tests/differential/m6/m66_lpeg_cases.txt` (62,599 rows) is what the tree's
//! standalone Lua with `lpeg.c` answers (`m66_lpeg_golden.txt`), and
//! `m66_lpeg_steps.txt` names the first step of the plan whose engine can run
//! each row (`oracle/classify_m66_lpeg.py`). This gate runs every row mapped
//! to [`STEP`] or an earlier step through the port, with the test-only
//! registration and the tree's `nselib/re.lua` and `nselib/lpeg-utility.lua`,
//! by the same case runner the oracle used (`oracle/m66_lpeg_core.lua`,
//! `run_row`), and compares status, values and log byte for byte with the
//! golden. Steps c and d extend it by changing [`STEP`].
//!
//! - Quarantined rows (`m66_lpeg_quarantine.txt`: they crash or are undefined
//!   in the C, LESSONS #033) are never run here; each has a pin elsewhere.
//! - The golden is stored with the `hashorder` mask applied (the rule name in
//!   four grammar errors follows the C's salted table order,
//!   `lpeg-grammar-error-rule-name-is-hash-ordered`); the same mask is applied
//!   to the port's output before comparing.
//! - **No exemption without a named class, and no class without its rows.**
//!   A row that differs passes only if it agrees under the one *named*
//!   normalisation class, each ledgered ([`CLASSES`]), that [`SCOPED`] lists
//!   for its id; a listed row that no longer needs its class fails too, so
//!   each class's membership is exact. Every class's members are printed.
//!
//! Since M6.6 step e the module is registered, and
//! [`every_row_through_the_registered_module_matches_the_trees_own_lpeg`]
//! runs the whole corpus again as nmap 7.94 ran it for step 0b's agreement
//! check: `oracle/m66_lpeg_probe.nse`, a prerule, through the port's own
//! engine (`runtime::new_state`, `load_chosen`, `run_phase`), with `lpeg`,
//! `re`, `lpeg-utility` and `stdnse` as scripts get them — `require` finding
//! the module nmap's way, not this file's test-only registration — under
//! the same comparison.
#![cfg(not(miri))] // reads the corpus from disk; minutes of VM time under Miri

mod lpeg_eval;
mod nse_host;

use std::collections::{HashMap, HashSet};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::nse::package::{load_package, LibrarySource};
use nmap_core::nse::stdlib::iolib::{load_io, FsError, OpenMode, ScriptFile, ScriptFs, Whence};
use nmap_core::nse::stdlib::utf8lib::load_utf8;
use piccolo::{Closure, Executor, Function, Lua, Table, Value, Variadic};
use regex::Regex;

/// The plan's step this gate runs up to (`b`, then `c`, then `d`): every row
/// `m66_lpeg_steps.txt` maps to it or to an earlier step.
const STEP: char = 'd';

/// The fewest rows the step must run: the corpus and its step map are
/// generated, and a weakened generator regenerated in place would otherwise
/// pass on what is left. Step 0b mapped 12,641 rows to step b, 24,726 to
/// step c and 25,232 to step d.
const MIN_ROWS: [(char, usize); 3] = [('b', 12_641), ('c', 24_726), ('d', 25_232)];

fn m6(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

/// The repository root, whose `nselib/` holds `re.lua` and `lpeg-utility.lua`.
fn repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../..")
}

/// The non-comment lines of a corpus file, split on tabs. Read as bytes:
/// the files are ASCII with `\xHH` escapes, but nothing here assumes it.
fn lines(file: &str) -> Vec<Vec<String>> {
    let path = m6(file);
    let bytes = std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    String::from_utf8_lossy(&bytes)
        .lines()
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(|l| l.split('\t').map(str::to_string).collect())
        .collect()
}

/// A case chunk as the cases file escapes it (`\\`, `\n`, `\t`).
fn unescape(s: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(s.len());
    let mut it = s.bytes();
    while let Some(b) = it.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next() {
            Some(b'\\') => out.push(b'\\'),
            Some(b'n') => out.push(b'\n'),
            Some(b't') => out.push(b'\t'),
            other => panic!("bad escape in a case chunk: \\{other:?}"),
        }
    }
    out
}

/// `nselib/` from the repository, for `require`.
struct Nselib;

impl LibrarySource for Nselib {
    fn find(&self, file: &[u8]) -> Option<Vec<u8>> {
        let p = repo().join(std::str::from_utf8(file).ok()?);
        p.is_file()
            .then(|| p.to_string_lossy().into_owned().into_bytes())
    }
    fn read(&self, path: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
        std::fs::read(Path::new(
            std::str::from_utf8(path).map_err(|_| Vec::new())?,
        ))
        .map_err(|e| e.to_string().into_bytes())
    }
}

/// `io` as the NSE state has it — `io.stdout` is a `FILE*` the corpus hands
/// to LPeg, and `print` lives in `io`'s library — with no file to open and
/// its output discarded.
struct NoFiles;

struct Discard;

impl ScriptFile for Discard {
    fn read(&mut self, _: &mut [u8]) -> Result<usize, FsError> {
        Ok(0)
    }
    fn write(&mut self, _: &[u8]) -> Result<(), FsError> {
        Ok(())
    }
    fn seek(&mut self, _: Whence, _: i64) -> Result<u64, FsError> {
        Ok(0)
    }
    fn flush(&mut self) -> Result<(), FsError> {
        Ok(())
    }
}

impl ScriptFs for NoFiles {
    fn open(&self, _: &[u8], _: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        Err(FsError::denied())
    }
    fn stdout(&self) -> Box<dyn ScriptFile> {
        Box::new(Discard)
    }
}

/// The hashorder mask (`classify_m66_lpeg.py`'s `FOUR`), which the golden is
/// stored with.
struct Masks {
    four: Vec<(Regex, &'static str)>,
    not_a_pattern: Regex,
    argname: Regex,
}

impl Masks {
    fn new() -> Masks {
        let re = |s: &str| Regex::new(s).expect("a valid regex");
        Masks {
            four: vec![
                (
                    re(r"rule '[^']*' may be left recursive"),
                    "rule '?' may be left recursive",
                ),
                (re(r"empty loop in rule '[^']*'"), "empty loop in rule '?'"),
                (
                    re(r"rule '[^']*' undefined in given grammar"),
                    "rule '?' undefined in given grammar",
                ),
            ],
            not_a_pattern: re(r"(initial )?rule '[^']*' is not a pattern"),
            argname: re(r"bad argument #(\d+) to '[^']*'"),
        }
    }

    fn hashorder(&self, s: &str) -> String {
        let mut s = s.to_string();
        for (rx, rep) in &self.four {
            s = rx.replace_all(&s, *rep).into_owned();
        }
        // Not `initial rule 'X' is not a pattern`, whose name is the
        // grammar's first field and so deterministic (Python's lookbehind).
        self.not_a_pattern
            .replace_all(&s, |c: &regex::Captures| match c.get(1) {
                Some(_) => c[0].to_string(),
                None => "rule '?' is not a pattern".to_string(),
            })
            .into_owned()
    }

    /// One named class's normalisation, of the port's text (`port`) or the
    /// C's.
    fn class(&self, class: &str, s: &str, port: bool) -> String {
        match class {
            // The port numbers a method call's arguments from the receiver,
            // one past the C's (`luaL_argerror` takes one off for a call its
            // `lua_getinfo` names a "method"): `p:match(nil)`.
            "method" if port => self
                .argname
                .replace_all(s, |c: &regex::Captures| {
                    let n: u64 = c[1].parse().unwrap_or(0);
                    c[0].replacen(&format!("#{n}"), &format!("#{}", n.saturating_sub(1)), 1)
                })
                .into_owned(),
            "method" => s.to_string(),
            "argname" => self
                .argname
                .replace_all(s, "bad argument #${1} to '?'")
                .into_owned(),
            _ => unreachable!("{class}"),
        }
    }
}

/// The named classes a differing row may agree under, each with its ledger
/// entry: `argname` is `classify_m66_lpeg.py`'s ("Named classes"), the
/// function name in `bad argument #N to 'NAME'`
/// (`stdlib-bad-argument-naming`); `method` is a method call's argument
/// numbering, which the port starts at the receiver
/// (`lpeg-bad-argument-naming`); `cdepth` is decided by the row, not its
/// text — see [`SCOPED`]. `classify_m66_lpeg.py`'s `position`
/// (`stdlib-errors-have-no-position`) is listed for no row, so a row that
/// differs only in a position prefix fails.
const CLASSES: [(&str, &str); 3] = [
    ("argname", "stdlib-bad-argument-naming"),
    ("method", "lpeg-bad-argument-naming"),
    ("cdepth", "lpeg-capture-ceiling-is-the-embeddings"),
];

/// **Every row that may agree only under a named class, with that class —
/// exactly** (the M6.6 retrospective's H2: a class tried on every differing
/// row reached 5,906 of the golden's rows, and a port numbering an argument
/// one too high passed). A differing row passes only under the class listed
/// for its id, and a listed row must still need it: one that agrees exactly,
/// or under no class, fails the gate, so the table is the membership the
/// ledger states.
///
/// - `argname`: `pcall(string.rep, P'a', …)`, which Lua names
///   `'string.rep'` and the binding `'rep'`.
/// - `method`: `re.compile(nil)`'s `pattern:match(nil)` (`re.lua:269`),
///   `#1` in the C and `#2` here.
/// - `cdepth` (`classify_m66_lpeg.py`): a row the cases file also tags
///   `cdepth`, whose answer is the depth of the embedding it runs in — how
///   many Lua stack slots the frames below the call use, which piccolo lays
///   out otherwise than the C — and nothing about LPeg: the absolute capture
///   ceiling (`H.stackcaps.999950`; the port puts the ceiling where the C
///   puts it relative to `table.unpack`'s in the same frame,
///   `H.stackcaps.rel`, an untagged row held to the golden's -5) and the C
///   levels left to re-entry (`H.reenter.196` to `.200` and `.250`;
///   `H.reenter.rel` is held to the golden's 0). Such a row agrees under
///   this class when its status and log are the golden's, whatever its
///   values. The other ten rows tagged `cdepth` must agree exactly.
const SCOPED: [(&str, &str); 10] = [
    ("A.name.typeerr", "argname"),
    ("X.name.rep", "argname"),
    ("J.compile.nil", "method"),
    ("H.stackcaps.999950", "cdepth"),
    ("H.reenter.196", "cdepth"),
    ("H.reenter.197", "cdepth"),
    ("H.reenter.198", "cdepth"),
    ("H.reenter.199", "cdepth"),
    ("H.reenter.200", "cdepth"),
    ("H.reenter.250", "cdepth"),
];

/// The rows this step runs, in corpus order: (id, tags, chunk).
fn step_rows() -> Vec<(String, String, Vec<u8>)> {
    let steps: HashMap<String, char> = lines("m66_lpeg_steps.txt")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].chars().next().unwrap_or('?')))
        .collect();
    let quarantined: HashSet<String> = lines("m66_lpeg_quarantine.txt")
        .into_iter()
        .map(|r| r[0].clone())
        .collect();
    lines("m66_lpeg_cases.txt")
        .into_iter()
        .filter(|r| !quarantined.contains(&r[0]))
        .filter(|r| {
            let s = steps
                .get(&r[0])
                .unwrap_or_else(|| panic!("{}: in the cases but not the step map", r[0]));
            assert!(matches!(s, 'b' | 'c' | 'd'), "{}: step {s}", r[0]);
            *s <= STEP
        })
        .map(|r| {
            assert_eq!(r.len(), 3, "{}: malformed case row", r[0]);
            (r[0].clone(), r[1].clone(), unescape(&r[2]))
        })
        .collect()
}

/// A state with the test-only `lpeg`, `io`, `utf8`, `package` and
/// `require` finding the tree's `re` and `lpeg-utility`, and the case
/// runner's `run_row` as a global.
fn corpus_lua() -> Lua {
    let mut lua = lpeg_eval::new_lua();
    let core = std::fs::read(m6("oracle/m66_lpeg_core.lua")).expect("the core");
    let ex = lua
        .try_enter(|ctx| {
            // The NSE state's `io` (with `print`) and `utf8`, which
            // `lpeg_eval::new_lua` leaves out; `package` and `require` as NSE
            // sets them up, finding `re` and `lpeg-utility` in `nselib/`.
            load_io(ctx, Rc::new(NoFiles));
            load_utf8(ctx);
            let loaded = load_package(ctx, Rc::new(Nselib));
            let lpeg = ctx.get_global::<Value>("lpeg").expect("lpeg");
            loaded.set_field(ctx, "lpeg", lpeg);
            // lpeg-utility requires stdnse only for its debug printer, which
            // no case reaches; the oracle's driver stubs it the same way.
            let stdnse = Table::new(&ctx);
            stdnse.set_field(
                ctx,
                "debug1",
                piccolo::Callback::from_fn(&ctx, |_, _, _| Ok(piccolo::CallbackReturn::Return)),
            );
            loaded.set_field(ctx, "stdnse", stdnse);
            let c = Closure::load(ctx, Some("=m66_lpeg_core.lua"), &core[..])?;
            Ok(ctx.stash(Executor::start(ctx, c.into(), ())))
        })
        .expect("the core compiles");
    assert!(
        lpeg_eval::step_only(&mut lua, &ex, 1_000_000, 10_000).0,
        "the core loads"
    );
    lua.enter(|ctx| {
        let t: Table = ctx
            .fetch(&ex)
            .take_result(ctx)
            .expect("finished")
            .expect("the core loads re and lpeg-utility");
        ctx.set_global("run_row", t.get_value(ctx, "run_row"));
    });

    lua
}

/// Run one case through `run_row`: its status, values and log, the last two
/// masked for hash order as the golden is.
fn run_case(
    lua: &mut Lua,
    masks: &Masks,
    id: &str,
    tags: &str,
    chunk: &[u8],
) -> (String, String, String) {
    let ex = lua.enter(|ctx| {
        let f: Function = ctx.get_global("run_row").expect("run_row");
        let row = Table::new(&ctx);
        row.set_field(ctx, "id", ctx.intern(id.as_bytes()));
        row.set_field(ctx, "tags", ctx.intern(tags.as_bytes()));
        row.set_field(ctx, "chunk", ctx.intern(chunk));
        ctx.stash(Executor::start(ctx, f, row))
    });
    let (done, _) = lpeg_eval::step_only(lua, &ex, 1_000_000, 100_000);
    let got = if done {
        lua.enter(
            |ctx| match ctx.fetch(&ex).take_result::<Variadic<Vec<Value>>>(ctx) {
                Ok(Ok(vs)) => {
                    let s = |i: usize| match vs.0.get(i) {
                        Some(Value::String(s)) => {
                            String::from_utf8_lossy(s.as_bytes()).into_owned()
                        }
                        Some(v) => v.display().to_string(),
                        None => String::new(),
                    };
                    (s(0), masks.hashorder(&s(1)), masks.hashorder(&s(2)))
                }
                Ok(Err(e)) => ("RAISED".into(), e.to_string(), String::new()),
                Err(e) => ("NO-RESULT".into(), e.to_string(), String::new()),
            },
        )
    } else {
        ("UNFINISHED".into(), String::new(), String::new())
    };
    got
}

#[test]
fn every_step_row_matches_the_trees_own_lpeg() {
    let rows = step_rows();
    for (step, min) in MIN_ROWS {
        if step <= STEP {
            let n = lines("m66_lpeg_steps.txt")
                .iter()
                .filter(|r| r[1].starts_with(step))
                .count();
            assert!(n >= min, "step {step} has {n} rows, fewer than {min}");
        }
    }
    let mut lua = corpus_lua();
    let masks = Masks::new();
    let (by_class, mismatches) = compare(&rows, &golden(), &masks, |id, tags, chunk| {
        run_case(&mut lua, &masks, id, tags, chunk)
    });
    report(&format!("step {STEP}"), rows.len(), &by_class, &mismatches);
}

/// The golden: id to status, values and log.
fn golden() -> HashMap<String, (String, String, String)> {
    lines("m66_lpeg_golden.txt")
        .into_iter()
        .map(|r| {
            assert_eq!(r.len(), 4, "{}: malformed golden row", r[0]);
            (r[0].clone(), (r[1].clone(), r[2].clone(), r[3].clone()))
        })
        .collect()
}

/// Rows that agree only under a named class, by class.
type ByClass = HashMap<String, Vec<String>>;

/// Compare each row's answer (`get`) with the golden's: equal, or equal
/// under the one class [`SCOPED`] lists for its id; anything else is a
/// mismatch, and so is a listed row that no longer needs its class.
fn compare(
    rows: &[(String, String, Vec<u8>)],
    golden: &HashMap<String, (String, String, String)>,
    masks: &Masks,
    mut get: impl FnMut(&str, &str, &[u8]) -> (String, String, String),
) -> (ByClass, Vec<String>) {
    let scoped: HashMap<&str, &str> = SCOPED.into_iter().collect();
    assert_eq!(scoped.len(), SCOPED.len(), "an id listed twice in SCOPED");
    let mut by_class: ByClass = HashMap::new();
    let mut mismatches = Vec::new();
    let mut seen = HashSet::new();
    for (id, tags, chunk) in rows {
        let got = get(id, tags, chunk);
        let want = golden
            .get(id)
            .unwrap_or_else(|| panic!("{id}: in the cases but not the golden"));
        let class = scoped.get(id.as_str()).copied();
        if class.is_some() {
            seen.insert(id.as_str());
        }
        if &got == want {
            if let Some(c) = class {
                mismatches.push(format!(
                    "  {id}: listed for the named class `{c}` but agrees exactly: \
                     take it out of SCOPED and the ledger's count"
                ));
            }
            continue;
        }
        let agrees = match class {
            None => false,
            Some("cdepth") => {
                tags.split(',').any(|t| t == "cdepth") && got.0 == want.0 && got.2 == want.2
            }
            Some(c) => {
                got.0 == want.0
                    && masks.class(c, &got.1, true) == masks.class(c, &want.1, false)
                    && masks.class(c, &got.2, true) == masks.class(c, &want.2, false)
            }
        };
        match (agrees, class) {
            (true, Some(c)) => by_class.entry(c.to_string()).or_default().push(id.clone()),
            _ => mismatches.push(format!(
                "  {id}{}:\n      lua  = {} {} | {}\n      port = {} {} | {}",
                class.map_or(String::new(), |c| format!(" (listed for `{c}`)")),
                want.0,
                want.1,
                want.2,
                got.0,
                got.1,
                got.2
            )),
        }
    }
    // A listed id the run never reached is a stale table: the corpus lost
    // the row, or the gate stopped running it.
    for (id, c) in SCOPED {
        if !seen.contains(id) {
            mismatches.push(format!(
                "  {id}: listed for the named class `{c}` but not run"
            ));
        }
    }
    (by_class, mismatches)
}

/// Print the classes used, and fail on any mismatch.
fn report(what: &str, rows: usize, by_class: &ByClass, mismatches: &[String]) {
    eprintln!(
        "{what}: {rows} rows; agreeing only under the named class listed for them: {by_class:?} ({})",
        CLASSES
            .iter()
            .map(|(c, l)| format!("{c} = {l}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(
        mismatches.is_empty(),
        "{what}: {} of {rows} rows diverge from the tree's LPeg:\n{}",
        mismatches.len(),
        mismatches
            .iter()
            .take(80)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The name the probe's output file goes by; the file system below keeps it
/// in memory.
const PROBE_OUT: &str = "/m66-lpeg-probe.out";

/// The probe's output file, in memory.
struct Capture(Rc<std::cell::RefCell<Vec<u8>>>);

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

/// Every file for reading (the core and the cases), [`PROBE_OUT`] for
/// writing.
struct ProbeFs(Rc<std::cell::RefCell<Vec<u8>>>);

impl ScriptFs for ProbeFs {
    fn open(&self, path: &[u8], mode: OpenMode) -> Result<Box<dyn ScriptFile>, FsError> {
        if path == PROBE_OUT.as_bytes() && mode.writes() {
            self.0.borrow_mut().clear();
            return Ok(Box::new(Capture(Rc::clone(&self.0))));
        }
        nse_host::ReadOnlyFs.open(path, mode)
    }
    fn stdout(&self) -> Box<dyn ScriptFile> {
        nse_host::ReadOnlyFs.stdout()
    }
}

/// Run `oracle/m66_lpeg_probe.nse` over `cases` as nmap 7.94 runs it for
/// step 0b's agreement check (`regen_m66_lpeg.sh --check-794`): a prerule
/// through the port's engine over this repository's `nselib/`, with the
/// module registered as scripts get it, no memory budget (the command
/// line's, `nse-cli-no-memory-budget`). Each row's status, values and log,
/// the last two masked for hash order as the golden is.
fn run_registered(cases: &Path, masks: &Masks) -> HashMap<String, (String, String, String)> {
    use nmap_core::nse::choose::{choose, RuleOptions};
    use nmap_core::nse::nmaplib::{NmapEnv, NmapLib, Phase};
    use nmap_core::nse::runtime::{new_state, StateConfig};
    use nmap_core::nse::script::parse_script_db;
    use nmap_core::nse::scriptargs::registry_args;

    let dir = nse_host::repo_root();
    let out = Rc::new(std::cell::RefCell::new(Vec::new()));
    let log = Rc::new(std::cell::RefCell::new(Vec::new()));
    let sink = Rc::clone(&log);
    let probe = m6("oracle/m66_lpeg_probe.nse");
    let rules = vec![probe.to_string_lossy().into_owned().into_bytes()];
    let db = parse_script_db(&std::fs::read(dir.join("scripts/script.db")).expect("script.db"))
        .expect("script.db parses");
    let chosen = choose(
        &rules,
        RuleOptions::default(),
        &db,
        &nse_host::scenarios::Locator(dir.clone()),
    );
    let args = format!(
        "core={},cases={},out={PROBE_OUT}",
        m6("oracle/m66_lpeg_core.lua").display(),
        cases.display()
    );
    let mut st = new_state(&StateConfig {
        lib: NmapLib::new(NmapEnv {
            log: Box::new(move |_, b| sink.borrow_mut().extend_from_slice(b)),
            ..nse_host::env(dir.clone())
        }),
        args: registry_args(None, args.as_bytes()).expect("arguments parse"),
        source: Rc::new(nse_host::Dir(dir.clone())),
        fs: Rc::new(ProbeFs(Rc::clone(&out))),
        os: Rc::new(nse_host::os_env()),
        memory_limit: None,
        engine: Default::default(),
        net: Rc::new(std::cell::RefCell::new(nmap_core::nse::net::NoNet)),
    })
    .expect("state");
    const BUDGET: Option<u64> = Some(1 << 42);
    st.load_chosen(&chosen, BUDGET).expect("the probe loads");
    let r = st.run_phase(Phase::PreScan, vec![], BUDGET);
    assert_eq!(r.aborted, None, "the probe's phase aborted");
    let text = String::from_utf8_lossy(&out.borrow()).into_owned();
    let mut lines: Vec<&str> = text.lines().collect();
    assert_eq!(
        lines.last().copied(),
        Some("done"),
        "the probe did not finish; the engine logged:\n{}",
        String::from_utf8_lossy(&log.borrow())
    );
    lines.pop();
    let mut got = HashMap::new();
    for line in lines {
        let f: Vec<&str> = line.split('\t').collect();
        assert_eq!(f.len(), 4, "a malformed probe line: {line}");
        let prev = got.insert(
            f[0].to_string(),
            (
                f[1].to_string(),
                masks.hashorder(f[2]),
                masks.hashorder(f[3]),
            ),
        );
        assert!(prev.is_none(), "{}: written twice", f[0]);
    }
    got
}

/// The whole corpus — every row of `m66_lpeg_cases.txt`, all steps — through
/// the registered module (M6.6 step e): the probe nmap 7.94 runs, run by the
/// port's engine, and every row's answer compared with the golden as
/// [`every_step_row_matches_the_trees_own_lpeg`] compares it, through named
/// classes only. Then the quarantined rows, which no golden holds, against
/// their pins, the same way (the probe runs the quarantine file as it runs
/// the cases).
#[test]
fn every_row_through_the_registered_module_matches_the_trees_own_lpeg() {
    let masks = Masks::new();
    let got = run_registered(&m6("m66_lpeg_cases.txt"), &masks);
    let rows: Vec<(String, String, Vec<u8>)> = lines("m66_lpeg_cases.txt")
        .into_iter()
        .map(|r| (r[0].clone(), r[1].clone(), Vec::new()))
        .collect();
    assert_eq!(got.len(), rows.len(), "the probe ran another set of rows");
    assert!(rows.len() >= 62_599, "only {} rows", rows.len());
    let (by_class, mismatches) = compare(&rows, &golden(), &masks, |id, _, _| {
        got.get(id)
            .cloned()
            .unwrap_or_else(|| ("MISSING".into(), String::new(), String::new()))
    });
    report("registered module", rows.len(), &by_class, &mismatches);

    let q = run_registered(&m6("m66_lpeg_quarantine.txt"), &masks);
    let mut wrong = Vec::new();
    let pins = pins();
    for pin in &pins {
        let want = (
            pin[3].clone(),
            masks.hashorder(&pin[4]),
            masks.hashorder(&pin[5]),
        );
        if q.get(&pin[0]) != Some(&want) {
            wrong.push(format!(
                "  {}: pin {want:?}, port {:?}",
                pin[0],
                q.get(&pin[0])
            ));
        }
    }
    assert_eq!(
        q.len(),
        pins.len(),
        "the probe ran another set of quarantined rows"
    );
    assert!(
        wrong.is_empty(),
        "registered module: {} of {} quarantined rows differ from their pins:\n{}",
        wrong.len(),
        pins.len(),
        wrong.join("\n")
    );
}

/// Every pin, from every file in [`PIN_FILES`].
fn pins() -> Vec<Vec<String>> {
    let pins: Vec<Vec<String>> = PIN_FILES.into_iter().flat_map(lines).collect();
    for pin in &pins {
        assert_eq!(pin.len(), 6, "{}: malformed pin", pin[0]);
    }
    pins
}

/// The fewest quarantined rows pinned at or below [`STEP`]: at step c, the
/// peephole's 10, `Cc(nil)`'s 99 and `init`'s 3 that the fixed C answers,
/// and 7 semantic pins; at step d, the 30 more of those ids that run
/// captures calling Lua, and the 8 of `m66d_quarantine_pins.txt`; at step e,
/// the 7 construction rows of `m66e_quarantine_pins.txt` — every
/// quarantined row (M6.6-ANALYSIS §11, row 0b).
const MIN_PINS: usize = 164;

/// The pin files: step c's, step d's for the rows of the three ids whose
/// defects only a match-time capture reaches, and step e's for the last 7,
/// construction rows that steps c and d left to step b's unit tests
/// (`lpeg-tree-size-int-overflow`, `lpeg-pattern-string-size-overflow`,
/// `lpeg-getfirst-unbounded-recursion`).
const PIN_FILES: [&str; 3] = [
    "m66c_quarantine_pins.txt",
    "m66d_quarantine_pins.txt",
    "m66e_quarantine_pins.txt",
];

/// The quarantined rows (`m66_lpeg_quarantine.txt`: they crash or are
/// undefined in the C, so no golden holds them, LESSONS #033) that the step
/// can run, against their pins: `m66c_quarantine_pins.txt`, written by
/// `oracle/gen_m66c_quarantine_pins.py`, what the tree's `lpeg.c` answers
/// with the two defects the port fixes fixed in it
/// (`lpeg-codegen-jump-out-of-code`, `lpeg-cc-nil-without-ktable`), or
/// where that build still fails, a correct LPeg's answer; and
/// `m66d_quarantine_pins.txt` (`oracle/gen_m66d_quarantine_pins.py`), the
/// answers of that build with the three match-time capture defects fixed
/// as well (`lpeg-doublecap-stack-overread`,
/// `lpeg-runtime-capture-index-16bit`, `lpeg-code-freed-during-match`); and
/// `m66e_quarantine_pins.txt`, the last 7, by hand (the tree's answer where
/// it gives one, a correct LPeg's where it crashes). Compared exactly, with
/// no class; every quarantined row has exactly one pin.
#[test]
fn every_quarantined_step_row_matches_its_pin() {
    let chunks: HashMap<String, Vec<u8>> = lines("m66_lpeg_quarantine.txt")
        .into_iter()
        .map(|r| (r[0].clone(), unescape(&r[2])))
        .collect();
    let masks = Masks::new();
    let mut lua = corpus_lua();
    let (mut ran, mut mismatches) = (0usize, Vec::new());
    // Every quarantined row has a pin, and only those (M6.6-ANALYSIS §11,
    // row 0b: "every quarantined id has a port pin by step e").
    let mut pinned: Vec<String> = pins().into_iter().map(|p| p[0].clone()).collect();
    let mut quarantined: Vec<String> = chunks.keys().cloned().collect();
    pinned.sort();
    quarantined.sort();
    assert_eq!(pinned, quarantined, "the pins are not the quarantine");
    for pin in pins() {
        let step = pin[1].chars().next().unwrap_or('?');
        if step > STEP {
            continue;
        }
        let chunk = chunks
            .get(&pin[0])
            .unwrap_or_else(|| panic!("{}: pinned but not quarantined", pin[0]));
        let got = run_case(&mut lua, &masks, &pin[0], "", chunk);
        let want = (
            pin[3].clone(),
            masks.hashorder(&pin[4]),
            masks.hashorder(&pin[5]),
        );
        ran += 1;
        if got != want {
            mismatches.push(format!(
                "  {} ({}):\n      pin  = {} {} | {}\n      port = {} {} | {}",
                pin[0], pin[2], want.0, want.1, want.2, got.0, got.1, got.2
            ));
        }
    }
    eprintln!("step {STEP}: {ran} quarantined rows against their pins");
    assert!(
        ran >= MIN_PINS,
        "{ran} pinned rows at step {STEP}, fewer than {MIN_PINS}"
    );
    assert!(
        mismatches.is_empty(),
        "{} of {ran} quarantined rows differ from their pins:\n{}",
        mismatches.len(),
        mismatches.join("\n")
    );
}
