//! M6.6 differential: the `nmapdb` module against nmap itself.
//!
//! `tests/differential/m6/m66_nmapdb_golden.txt` is what nmap 7.94's
//! `nmapdb` (`nse_db.cc`) answered over this repository's data files
//! (`--datadir`), as `oracle/m66_probe_nmapdb.nse` wrote it, one line per
//! call (`oracle/gen_m66_nmapdb.py`): the module's shape, `getservbyport`
//! over every port of tcp, udp and sctp, `mac2corp` over every prefix in
//! `nmap-mac-prefixes` and 50,000 addresses, `getprotbynum` and
//! `getprotbyname` over `nmap-protocols`, the argument edges of all four, and
//! the two functions as scripts reach them, through `datafiles`.
//!
//! This test runs the same probe, as a prerule through the port's engine,
//! with the same script arguments and the same data files, and requires the
//! same lines, line for line. No line is excused.
//!
//! The calls the probe does not make, because they abort or are undefined in
//! 7.94 (LESSONS #033), are listed in `m66_nmapdb_quarantine.txt` with their
//! ledger ids. Each id here is a pin: the answer the port must give, which
//! every quarantined call is run against, and a DIVERGENCES.md entry.
//!
//! `M66_NMAPDB_GOLDEN` names a different golden file: CI regenerates one
//! against the installed nmap and points this test at it.
#![cfg(all(unix, not(miri)))] // reads the corpus from disk; the locator is unix-only

mod nse_host;

use std::cell::RefCell;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::nse::choose::{choose, RuleOptions};
use nmap_core::nse::nmaplib::{NmapEnv, NmapLib, Phase};
use nmap_core::nse::runtime::{new_state, run_chunk, ChunkOutcome, StateConfig};
use nmap_core::nse::script::parse_script_db;
use nmap_core::nse::scriptargs::registry_args;
use nmap_core::nse::stdlib::iolib::{FsError, OpenMode, ScriptFile, ScriptFs, Whence};
use nmap_core::protocols::ProtocolTable;

/// The name the probe's output file goes by; the file system below keeps it
/// in memory.
const OUT: &str = "/m66-nmapdb-probe.out";

fn m6(file: &str) -> PathBuf {
    nse_host::scenarios::m6().join(file)
}

fn golden() -> PathBuf {
    std::env::var_os("M66_NMAPDB_GOLDEN").map_or_else(|| m6("m66_nmapdb_golden.txt"), PathBuf::from)
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

/// Every file for reading, as the probe reads `nmap-protocols` and
/// `nmap-mac-prefixes` and `datafiles` reads `nmap-services`, and [`OUT`]
/// for writing.
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

/// Run the probe as a prerule over this repository's data files, as the
/// generator runs it under nmap: its lines, without the final `done`, and
/// what the module logged.
fn run_probe() -> (Vec<String>, Vec<u8>) {
    let dir = nse_host::repo_root();
    let out = Rc::new(RefCell::new(Vec::new()));
    let log = Rc::new(RefCell::new(Vec::new()));
    let sink = Rc::clone(&log);
    let probe = m6("oracle/m66_probe_nmapdb.nse");
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
        args: registry_args(None, format!("out={OUT},mode=main").as_bytes())
            .expect("arguments parse"),
        source: Rc::new(nse_host::Dir(dir.clone())),
        fs: Rc::new(ProbeFs(Rc::clone(&out))),
        os: Rc::new(nse_host::os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
        net: Rc::new(RefCell::new(nmap_core::nse::net::NoNet)),
    })
    .expect("state");
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
    // The data files' paths, as the generator writes them: by name.
    for line in &mut lines {
        for (tag, name) in [
            ("macfile|", "nmap-mac-prefixes"),
            ("protofile|", "nmap-protocols"),
        ] {
            if let Some(path) = line.strip_prefix(tag) {
                if same_file(Path::new(path), &dir.join(name)) {
                    *line = format!("{tag}{name}");
                }
            }
        }
    }
    let logged = log.borrow().clone();
    (lines, logged)
}

fn same_file(a: &Path, b: &Path) -> bool {
    match (a.canonicalize(), b.canonicalize()) {
        (Ok(a), Ok(b)) => a == b,
        _ => false,
    }
}

/// The golden's lines, read as the generator wrote them (latin-1), and its
/// header.
fn read_golden(path: &Path, header: &mut Vec<String>) -> Vec<String> {
    let bytes = std::fs::read(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let text: String = bytes.iter().map(|&b| char::from(b)).collect();
    let mut rows = Vec::new();
    for line in text.lines() {
        if line.starts_with('#') {
            header.push(line.to_string());
        } else {
            rows.push(line.to_string());
        }
    }
    rows
}

#[test]
fn nmapdb_matches_nmap_itself() {
    let mut header = Vec::new();
    let want = read_golden(&golden(), &mut header);
    assert!(
        header.iter().any(|h| h.contains("Nmap version 7.94")),
        "the golden does not record nmap's version: {header:?}"
    );
    assert!(
        want.len() > 100_000,
        "only {} lines in the golden",
        want.len()
    );
    let (got, logged) = run_probe();
    // The shipped files read cleanly: nothing to report.
    assert!(
        logged.is_empty(),
        "the module logged: {}",
        String::from_utf8_lossy(&logged)
    );
    let mut wrong = Vec::new();
    for (i, (w, g)) in want.iter().zip(got.iter()).enumerate() {
        if w != g {
            wrong.push(format!("  line {}:\n    nmap {w}\n    port {g}", i + 1));
        }
    }
    let shown: Vec<String> = wrong.iter().take(25).cloned().collect();
    assert!(
        wrong.is_empty() && want.len() == got.len(),
        "{} of {} lines differ (nmap {} lines, port {}):\n{}",
        wrong.len(),
        want.len(),
        want.len(),
        got.len(),
        shown.join("\n")
    );
}

/// The probe's `esc`: bytes outside printable ASCII, and `|`, as `\xNN`.
fn esc(b: &[u8]) -> String {
    b.iter()
        .map(|&c| {
            if (32..=126).contains(&c) && c != b'|' {
                char::from(c).to_string()
            } else {
                format!("\\x{c:02x}")
            }
        })
        .collect()
}

/// One argument as the probe renders it, decoded: its Lua source, and the
/// bytes `luaL_checkstring` would see.
fn argument(r: &str) -> (String, Vec<u8>) {
    if let Some(n) = r.strip_prefix("i:") {
        (n.to_string(), n.as_bytes().to_vec())
    } else if let Some(n) = r.strip_prefix("f:") {
        let f: f64 = n.parse().expect("a float");
        (format!("{f:?}"), format!("{f:?}").into_bytes())
    } else if let Some(s) = r.strip_prefix("s:") {
        assert!(!s.contains('"'), "{r}");
        // `esc` writes `\xNN`, which a Lua string literal reads back.
        let mut bytes = Vec::new();
        let mut rest = s.as_bytes();
        while let Some((&c, tail)) = rest.split_first() {
            if c == b'\\' {
                let hex = std::str::from_utf8(&tail[1..3]).expect("ascii");
                bytes.push(u8::from_str_radix(hex, 16).expect("\\xNN"));
                rest = &tail[3..];
            } else {
                bytes.push(c);
                rest = tail;
            }
        }
        (format!("\"{s}\""), bytes)
    } else {
        panic!("argument {r} is not one the quarantine list holds")
    }
}

/// The ledger ids of the quarantine list, and the answer each pins the port
/// to, given the call's arguments as `luaL_checkstring` sees them.
fn pinned(id: &str, args: &[Vec<u8>]) -> String {
    match id {
        // This tree's table has a slot for 255 (`efa0dc36f`), and its file
        // names no protocol 255.
        "nmapdb-getprotbynum-255-oracle-abort" => {
            let text = std::fs::read(nse_host::repo_root().join("nmap-protocols"))
                .expect("nmap-protocols");
            match ProtocolTable::parse(&text).by_number(255) {
                Some(name) => format!("s:{}", esc(name)),
                None => "nil".into(),
            }
        }
        // A terminated list: `luaL_checkoption`'s own error, the name cut at
        // its first NUL, before the port is looked at.
        "nmapdb-getservbyport-option-overread" => {
            let name = &args[1];
            let name = name
                .iter()
                .position(|&b| b == 0)
                .map_or(&name[..], |i| &name[..i]);
            let mut m = b"bad argument #2 to 'nmapdb.getservbyport' (invalid option '".to_vec();
            m.extend_from_slice(name);
            m.extend_from_slice(b"')");
            format!("E:{}", esc(&m))
        }
        // A byte of 128 or more is not a hex digit.
        "nmapdb-mac2corp-isxdigit-signed-char" => "E:Expected a 6-byte MAC address".into(),
        other => panic!("the quarantined id {other} has no pin in this test"),
    }
}

#[test]
fn each_quarantined_call_gives_its_pinned_answer() {
    let text = std::fs::read_to_string(m6("m66_nmapdb_quarantine.txt")).expect("quarantine list");
    let ledger = std::fs::read_to_string(nse_host::repo_root().join("nmap-rs/DIVERGENCES.md"))
        .expect("ledger");
    let mut calls = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let rest = line.strip_prefix("quarantine|").expect("a quarantine line");
        let (call, id) = rest.rsplit_once('|').expect("call|id");
        assert!(
            ledger.contains(&format!("`{id}`")),
            "{id} is not in DIVERGENCES.md"
        );
        let (f, args) = call.split_once('(').expect("f(args)");
        let args = args.strip_suffix(')').expect("f(args)");
        let args: Vec<(String, Vec<u8>)> = args.split(',').map(argument).collect();
        let lua: Vec<String> = args.iter().map(|(l, _)| l.clone()).collect();
        let bytes: Vec<Vec<u8>> = args.into_iter().map(|(_, b)| b).collect();
        calls.push((call.to_string(), f.to_string(), lua, pinned(id, &bytes)));
    }
    assert!(calls.len() >= 30, "only {} quarantined calls", calls.len());

    // Each call made as the probe makes its calls: through `pcall`, the result
    // rendered as it renders them.
    let mut src = String::from(
        "local function esc(s)\n\
           return (s:gsub('[^\\32-\\126]', function(c) return string.format('\\\\x%02x', c:byte()) end)\n\
                    :gsub('|', '\\\\x7c'))\n\
         end\n\
         local function render(v)\n\
           local t = type(v)\n\
           if t == 'nil' then return 'nil'\n\
           elseif t == 'string' then return 's:' .. esc(v)\n\
           elseif t == 'number' then\n\
             if math.type(v) == 'integer' then return 'i:' .. tostring(v) end\n\
             return 'f:' .. string.format('%.17g', v)\n\
           elseif t == 'boolean' then return 'b:' .. tostring(v)\n\
           else return t end\n\
         end\n\
         local function call(f, ...)\n\
           local r = table.pack(pcall(nmapdb[f], ...))\n\
           if not r[1] then return 'E:' .. esc(tostring(r[2])) end\n\
           return render(r[2])\n\
         end\n\
         local out = {}\n",
    );
    for (_, f, args, _) in &calls {
        src.push_str(&format!(
            "out[#out + 1] = call({f:?}, {})\n",
            args.join(", ")
        ));
    }
    src.push_str("return table.concat(out, '\\n')");
    let mut st = nse_host::state(&nse_host::repo_root()).expect("state");
    let got = match run_chunk(&mut st.lua, "=pins", src.as_bytes(), 100_000_000) {
        ChunkOutcome::Returned(v) => v[0].clone(),
        other => panic!("the pin chunk: {other:?}"),
    };
    let got: Vec<&str> = got.split('\n').collect();
    assert_eq!(got.len(), calls.len());
    let wrong: Vec<String> = calls
        .iter()
        .zip(got)
        .filter(|((_, _, _, want), got)| want != got)
        .map(|((call, _, _, want), got)| format!("  {call}: pinned {want}, port {got}"))
        .collect();
    assert!(
        wrong.is_empty(),
        "{} quarantined calls differ from their pins:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}
