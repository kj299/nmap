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
//! - **No per-row exemption list.** A row that differs passes only if it
//!   agrees under a *named* normalisation class, each ledgered: [`CLASSES`],
//!   and [`CDEPTH`] for the rows the cases file tags `cdepth`. Every class's
//!   count is printed, and a class may be used only by rows of the kind it
//!   names.
#![cfg(not(miri))] // reads the corpus from disk; minutes of VM time under Miri

mod lpeg_eval;

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
const STEP: char = 'c';

/// The fewest rows the step must run: the corpus and its step map are
/// generated, and a weakened generator regenerated in place would otherwise
/// pass on what is left. Step 0b mapped 12,641 rows to step b and 24,726 to
/// step c.
const MIN_ROWS: [(char, usize); 2] = [('b', 12_641), ('c', 24_726)];

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
    position: Regex,
    argname: Regex,
    vm_base_c: Regex,
    vm_base_port: Regex,
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
            position: re(r#""(?:\.\.\.)?[^"\s:\\]+:\d+: "#),
            argname: re(r"bad argument #(\d+) to '[^']*'"),
            // The base functions whose argument errors the VM words its own
            // way (`vm-base-library-argument-errors`), and that wording.
            vm_base_c: re(
                r"bad argument #\d+ to '(?:setmetatable|next|rawlen|rawget|rawset|ipairs|select)' \([^)]*\)",
            ),
            vm_base_port: re(r"type error, expected \w+, found \w+|Bad argument to 'select'"),
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

    /// One named class's normalisation.
    fn class(&self, class: &str, s: &str) -> String {
        match class {
            "position" => self.position.replace_all(s, "\"").into_owned(),
            "argname" => self
                .argname
                .replace_all(s, "bad argument #${1} to '?'")
                .into_owned(),
            "vmbase" => {
                let s = self.vm_base_c.replace_all(s, "<vm-base-argument-error>");
                self.vm_base_port
                    .replace_all(&s, "<vm-base-argument-error>")
                    .into_owned()
            }
            _ => unreachable!("{class}"),
        }
    }
}

/// The named classes a differing row may agree under, each with its ledger
/// entry: `position` and `argname` are `classify_m66_lpeg.py`'s ("Named
/// classes"); `vmbase` is the VM's own base library, whose argument errors
/// are worded the VM's way (`type error, expected Table, found userdata`
/// where Lua says `bad argument #1 to 'setmetatable' (table expected, got
/// lpeg-pattern)`): the corpus's two rows that hand a pattern to
/// `setmetatable`. Tried alone, then in pairs, then all together; the
/// smallest set under which a row agrees is the one it is counted under.
const CLASSES: [(&str, &str); 3] = [
    ("position", "stdlib-errors-have-no-position"),
    ("argname", "stdlib-bad-argument-naming"),
    ("vmbase", "vm-base-library-argument-errors"),
];

/// `cdepth` (`classify_m66_lpeg.py`): a row the cases file tags `cdepth` has
/// for its answer the depth of the embedding it runs in — how many Lua
/// stack slots the frames below the call use, which piccolo lays out
/// otherwise than the C — and nothing about LPeg. At step c these are the
/// absolute capture ceilings, `H.stackcaps.999000` to `.1000100`: the port
/// puts the ceiling where the C puts it relative to `table.unpack`'s in the
/// same frame (`H.stackcaps.rel`, an untagged row held to the golden's -5),
/// and the absolute ceiling, about 999,934 under the standalone oracle and
/// 999,945 under 7.94, falls elsewhere. Such a row agrees under this class
/// when its status and log are the golden's, whatever its values.
const CDEPTH: (&str, &str) = ("cdepth", "lpeg-capture-ceiling-is-the-embeddings");

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
    let golden: HashMap<String, (String, String, String)> = lines("m66_lpeg_golden.txt")
        .into_iter()
        .map(|r| {
            assert_eq!(r.len(), 4, "{}: malformed golden row", r[0]);
            (r[0].clone(), (r[1].clone(), r[2].clone(), r[3].clone()))
        })
        .collect();

    let mut lua = corpus_lua();
    let masks = Masks::new();
    let mut by_class: HashMap<String, Vec<String>> = HashMap::new();
    let mut mismatches = Vec::new();
    for (id, tags, chunk) in &rows {
        let got = run_case(&mut lua, &masks, id, tags, chunk);
        let want = golden
            .get(id)
            .unwrap_or_else(|| panic!("{id}: in the cases but not the golden"));
        if &got == want {
            continue;
        }
        if tags.split(',').any(|t| t == CDEPTH.0) && got.0 == want.0 && got.2 == want.2 {
            by_class
                .entry(CDEPTH.0.to_string())
                .or_default()
                .push(id.clone());
            continue;
        }
        // The smallest set of named classes under which the row agrees.
        let names: Vec<&str> = CLASSES.iter().map(|(c, _)| *c).collect();
        let mut sets: Vec<Vec<&str>> = (1u32..1 << names.len())
            .map(|m| {
                (0..names.len())
                    .filter(|i| m & (1 << i) != 0)
                    .map(|i| names[i])
                    .collect()
            })
            .collect();
        sets.sort_by_key(Vec::len);
        let agrees = sets.iter().find(|set| {
            let n = |s: &str| set.iter().fold(s.to_string(), |s, c| masks.class(c, &s));
            got.0 == want.0 && n(&got.1) == n(&want.1) && n(&got.2) == n(&want.2)
        });
        match agrees {
            Some(set) => by_class.entry(set.join("+")).or_default().push(id.clone()),
            None => mismatches.push(format!(
                "  {id}:\n      lua  = {} {} | {}\n      port = {} {} | {}",
                want.0, want.1, want.2, got.0, got.1, got.2
            )),
        }
    }
    eprintln!(
        "step {STEP}: {} rows; agreeing only under a named class: {by_class:?} ({})",
        rows.len(),
        CLASSES
            .iter()
            .chain([&CDEPTH])
            .map(|(c, l)| format!("{c} = {l}"))
            .collect::<Vec<_>>()
            .join(", ")
    );
    assert!(
        mismatches.is_empty(),
        "{} of {} step-{STEP} rows diverge from the tree's LPeg:\n{}",
        mismatches.len(),
        rows.len(),
        mismatches
            .iter()
            .take(80)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// The fewest quarantined rows pinned at or below [`STEP`]: at step c, the
/// peephole's 10, `Cc(nil)`'s 99 and `init`'s 3 that the fixed C answers,
/// and 7 semantic pins.
const MIN_PINS: usize = 119;

/// The quarantined rows (`m66_lpeg_quarantine.txt`: they crash or are
/// undefined in the C, so no golden holds them, LESSONS #033) that the step
/// can run, against their pins (`m66c_quarantine_pins.txt`, written by
/// `oracle/gen_m66c_quarantine_pins.py`): what the tree's `lpeg.c` answers
/// with the two defects the port fixes fixed in it
/// (`lpeg-codegen-jump-out-of-code`, `lpeg-cc-nil-without-ktable`), or
/// where that build still fails, a correct LPeg's answer. Compared exactly,
/// with no class.
#[test]
fn every_quarantined_step_row_matches_its_pin() {
    let chunks: HashMap<String, Vec<u8>> = lines("m66_lpeg_quarantine.txt")
        .into_iter()
        .map(|r| (r[0].clone(), unescape(&r[2])))
        .collect();
    let masks = Masks::new();
    let mut lua = corpus_lua();
    let (mut ran, mut mismatches) = (0usize, Vec::new());
    for pin in lines("m66c_quarantine_pins.txt") {
        assert_eq!(pin.len(), 6, "{}: malformed pin", pin[0]);
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
