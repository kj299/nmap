//! M6.4c2 gate: the engine runs scripts as nmap 7.94 runs them.
//!
//! `oracle/gen_m64_scripts.py` ran nmap over the fixture scripts in
//! `tests/differential/m6/nse_scripts/` (their own `script.db`), one scenario
//! per `--script` selection, and recorded every result the scripts left — for
//! the run, the host and each port — as normal output and as XML, or the
//! error the engine failed to start with. This test rebuilds each scenario:
//! the same data directory layout, the same rules chosen by
//! [`nmap_core::nse::choose`], the scripts loaded and run through the three
//! phases by the engine, against the host and ports the scan found. Every
//! result must match byte for byte.
//!
//! Results are compared in order of script id, which is the port's order
//! (`nse-results-sorted-by-id`); nmap's is its results' addresses, and the
//! generator sorts them.
//! `M64_SCRIPTS_GOLDEN` names a golden to use instead of the committed one;
//! CI's differential job regenerates it live.
#![cfg(all(unix, not(miri)))] // runs scripts from disk, through symlinks

#[path = "nse_host/mod.rs"]
mod nse_host;

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::model::{PortState, Protocol};
use nmap_core::nse::choose::{choose, Found, RuleOptions, ScriptLocator};
use nmap_core::nse::engine::PhaseResults;
use nmap_core::nse::nmaplib::{NmapLib, Phase, ScriptHost, ScriptPort};
use nmap_core::nse::runtime::{new_state, StateConfig};
use nmap_core::nse::script::parse_script_db;
use nmap_core::nse::scriptargs::registry_args;
use nmap_core::nse::selection::split_arg;

fn m6() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6")
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("ascii"), 16).expect("hex"))
        .collect()
}

/// One result: container, script id, normal-output lines, `<script>` XML.
type Row = (String, Vec<u8>, Option<Vec<u8>>, Vec<u8>);

#[derive(Default)]
struct Scenario {
    name: String,
    args: Vec<String>,
    ports: Vec<ScriptPort>,
    init_error: Option<Vec<u8>>,
    results: Vec<Row>,
}

fn reason(s: &str) -> &'static str {
    match s {
        "syn-ack" => "syn-ack",
        "conn-refused" => "conn-refused",
        "reset" => "reset",
        other => panic!("reason {other} not in the fixtures"),
    }
}

fn scenarios(golden: &Path) -> Vec<Scenario> {
    let text = std::fs::read_to_string(golden).expect("golden");
    let mut out: Vec<Scenario> = Vec::new();
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => out.push(Scenario {
                name: f[1].to_string(),
                ..Scenario::default()
            }),
            _ => {
                let sc = out.last_mut().expect("a scenario first");
                match f[0] {
                    "args" => {
                        sc.args = String::from_utf8(unhex(f[1]))
                            .expect("utf-8")
                            .split('\0')
                            .map(str::to_string)
                            .collect();
                    }
                    "port" => sc.ports.push(ScriptPort {
                        number: f[2].parse().expect("port"),
                        protocol: match f[1] {
                            "tcp" => Protocol::Tcp,
                            "udp" => Protocol::Udp,
                            _ => Protocol::Sctp,
                        },
                        state: match f[3] {
                            "open" => PortState::Open,
                            "closed" => PortState::Closed,
                            other => panic!("state {other}"),
                        },
                        reason: reason(f[4]),
                        reason_ttl: f[5].parse().expect("ttl"),
                        service: None,
                    }),
                    "init_error" => sc.init_error = Some(unhex(f[1])),
                    "result" => sc.results.push((
                        f[1].to_string(),
                        unhex(f[2]),
                        (f[3] != "-").then(|| unhex(f[3])),
                        unhex(f[4]),
                    )),
                    other => panic!("row {other}"),
                }
            }
        }
    }
    out
}

/// Shipped scripts run beside the fixtures (the generator's `SHIPPED`).
const SHIPPED: [&str; 1] = ["unittest.nse"];

/// A data directory laid out as the generator lays it out: the repository's
/// data files and `nselib/`, and in `scripts/` the fixtures and [`SHIPPED`].
fn datadir(tmp: &Path) -> PathBuf {
    let repo = nse_host::repo_root();
    let d = tmp.join("data");
    std::fs::create_dir_all(&d).expect("data dir");
    for e in std::fs::read_dir(&repo).expect("repo").flatten() {
        let name = e.file_name();
        let n = name.to_string_lossy();
        if n == "nselib" || n == "nse_main.lua" || n.starts_with("nmap-") {
            std::os::unix::fs::symlink(e.path(), d.join(&name)).expect("symlink");
        }
    }
    let scripts = d.join("scripts");
    std::fs::create_dir(&scripts).expect("scripts dir");
    for e in std::fs::read_dir(m6().join("nse_scripts"))
        .expect("fixtures")
        .flatten()
    {
        std::os::unix::fs::symlink(e.path(), scripts.join(e.file_name())).expect("symlink");
    }
    for name in SHIPPED {
        std::os::unix::fs::symlink(repo.join("scripts").join(name), scripts.join(name))
            .expect("symlink");
    }
    d
}

/// `nse_fetchscript` over the data directory.
struct Locator(PathBuf);

impl ScriptLocator for Locator {
    fn fetch_script(&self, name: &[u8]) -> Option<Found> {
        let s = std::str::from_utf8(name).ok()?;
        let kind = |p: &Path, shown: String| {
            if p.is_file() {
                Some(Found::File(shown.into_bytes()))
            } else if p.is_dir() {
                Some(if s.ends_with('/') {
                    Found::Directory(shown.into_bytes())
                } else {
                    Found::BareDirectory(shown.into_bytes())
                })
            } else {
                None
            }
        };
        if s.starts_with('/') {
            return kind(Path::new(s), s.to_string());
        }
        let shown = format!("{}/scripts/{s}", self.0.display());
        kind(Path::new(&shown), shown.clone()).or_else(|| kind(Path::new(s), s.to_string()))
    }

    fn list_dir(&self, path: &[u8]) -> Vec<Vec<u8>> {
        let p = std::str::from_utf8(path).unwrap_or("");
        std::fs::read_dir(p)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned().into_bytes())
                    .collect()
            })
            .unwrap_or_default()
    }
}

fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(hay.len());
    let mut i = 0;
    while i < hay.len() {
        if !from.is_empty() && hay[i..].starts_with(from) {
            out.extend_from_slice(to);
            i = i.saturating_add(from.len());
        } else {
            out.push(hay[i]);
            i = i.saturating_add(1);
        }
    }
    out
}

/// An engine error's first line, without the `nse_main...:N: ` position.
fn error_line(e: &str) -> Vec<u8> {
    let first = e.lines().next().unwrap_or("");
    let rest = match first.find("nse_main") {
        Some(i) => {
            let after = &first[i..];
            match after.find(": ") {
                Some(j)
                    if after[..j]
                        .rsplit(':')
                        .next()
                        .is_some_and(|d| d.chars().all(|c| c.is_ascii_digit())) =>
                {
                    after.get(j.saturating_add(2)..).unwrap_or("")
                }
                _ => first,
            }
        }
        None => first,
    };
    rest.as_bytes().to_vec()
}

/// Run one scenario through the port: its init error, or its results.
fn run(sc: &Scenario, tmp: &Path) -> Result<Vec<Row>, Vec<u8>> {
    let data = datadir(tmp);
    let shown = data.display().to_string().into_bytes();
    let norm = |b: &[u8]| replace(b, &shown, b"DATADIR");
    // The command line, as the scenarios use it.
    let (mut rules, mut options, mut script_args) =
        (Vec::new(), RuleOptions::default(), Vec::new());
    let mut debugging = 0;
    let mut it = sc.args.iter();
    while let Some(a) = it.next() {
        match a.as_str() {
            "--script" => rules.extend(
                split_arg(it.next().expect("rule").as_bytes())
                    .into_iter()
                    .map(<[u8]>::to_vec),
            ),
            "--script-args" => script_args = it.next().expect("args").as_bytes().to_vec(),
            "-sC" => options.default = true,
            "-d" => debugging = 1,
            "-d2" => debugging = 2,
            other => panic!("option {other}"),
        }
    }
    let db = parse_script_db(&std::fs::read(data.join("scripts/script.db")).expect("db"))
        .expect("db parses");
    let chosen = choose(&rules, options, &db, &Locator(data.clone()));
    let mut st = new_state(&StateConfig {
        lib: NmapLib::new(nmap_core::nse::nmaplib::NmapEnv {
            debugging,
            ..nse_host::env(data.clone())
        }),
        args: registry_args(None, &script_args).expect("arguments parse"),
        source: Rc::new(nse_host::Dir(data.clone())),
        fs: Rc::new(nse_host::ReadOnlyFs),
        os: Rc::new(nse_host::os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
    })
    .expect("state");
    const BUDGET: Option<u64> = Some(1 << 30);
    if let Err(e) = st.load_chosen(&chosen, BUDGET) {
        return Err(norm(&error_line(&e)));
    }
    let mut host = ScriptHost::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    host.ports = sc.ports.clone();
    let phases: [(Phase, Vec<ScriptHost>); 3] = [
        (Phase::PreScan, vec![]),
        (Phase::Scan, vec![host]),
        (Phase::PostScan, vec![]),
    ];
    let mut out = Vec::new();
    for (phase, hosts) in phases {
        let r: PhaseResults = st.run_phase(phase, hosts, BUDGET);
        assert_eq!(r.aborted, None, "{}: {phase:?} aborted", sc.name);
        let container = if phase == Phase::PreScan {
            "pre"
        } else {
            "post"
        };
        for s in &r.run {
            out.push((
                container.to_string(),
                s.id.clone(),
                s.normal().map(|n| norm(&n)),
                norm(&s.xml()),
            ));
        }
        for h in &r.hosts {
            for s in &h.results {
                out.push((
                    "host".to_string(),
                    s.id.clone(),
                    s.normal().map(|n| norm(&n)),
                    norm(&s.xml()),
                ));
            }
            for (proto, n, list) in &h.ports {
                for s in list {
                    out.push((
                        format!("port:{}/{n}", proto.as_str()),
                        s.id.clone(),
                        s.normal().map(|x| norm(&x)),
                        norm(&s.xml()),
                    ));
                }
            }
        }
    }
    // Containers in the golden's order; within each, the engine's own order,
    // which must be by script id (`nse-results-sorted-by-id`).
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace('\n', "\\n")
}

#[test]
fn scripts_run_as_under_nmap() {
    let golden = std::env::var_os("M64_SCRIPTS_GOLDEN")
        .map_or_else(|| m6().join("m64_scripts_golden.txt"), PathBuf::from);
    let all = scenarios(&golden);
    assert!(all.len() >= 30, "only {} scenarios", all.len());
    let mut failures = Vec::new();
    for (i, sc) in all.iter().enumerate() {
        let tmp = std::env::temp_dir().join(format!("m64-scripts-{}-{i}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let got = run(sc, &tmp);
        let _ = std::fs::remove_dir_all(&tmp);
        match (&sc.init_error, got) {
            (Some(want), Err(e)) if *want == e => {}
            (Some(want), Err(e)) => failures.push(format!(
                "{}: init error\n  nmap: {}\n  port: {}",
                sc.name,
                show(want),
                show(&e)
            )),
            (Some(want), Ok(_)) => failures.push(format!(
                "{}: nmap failed to start ({}), the port ran",
                sc.name,
                show(want)
            )),
            (None, Err(e)) => failures.push(format!(
                "{}: the port failed to start: {}",
                sc.name,
                show(&e)
            )),
            (None, Ok(got)) => {
                if got != sc.results {
                    let mut msg = format!("{}: results differ", sc.name);
                    for r in sc.results.iter().filter(|r| !got.contains(r)) {
                        msg.push_str(&format!(
                            "\n  nmap {} {}: {:?} {}",
                            r.0,
                            show(&r.1),
                            r.2.as_deref().map(show),
                            show(&r.3)
                        ));
                    }
                    for r in got.iter().filter(|r| !sc.results.contains(r)) {
                        msg.push_str(&format!(
                            "\n  port {} {}: {:?} {}",
                            r.0,
                            show(&r.1),
                            r.2.as_deref().map(show),
                            show(&r.3)
                        ));
                    }
                    failures.push(msg);
                }
            }
        }
    }
    assert!(
        failures.is_empty(),
        "{} of {} scenarios differ:\n{}",
        failures.len(),
        all.len(),
        failures.join("\n")
    );
}

/// The VM's own `coroutine.continue` and `yieldto` are not in the state
/// scripts run in (`vm-nonstandard-coroutine-functions`).
#[test]
fn the_vm_coroutine_extensions_are_removed() {
    use nmap_core::nse::runtime::{run_chunk, ChunkOutcome};
    let mut st = nse_host::state(&nse_host::repo_root()).expect("state");
    let got = run_chunk(
        &mut st.lua,
        "=t",
        b"return coroutine.continue == nil, coroutine.yieldto == nil, type(coroutine.wrap)",
        1 << 20,
    );
    assert_eq!(
        got,
        ChunkOutcome::Returned(vec!["true".into(), "true".into(), "function".into()])
    );
}

/// A script that never yields hangs nmap. Under a budget, the phase ends,
/// reported as aborted, and what was stored before is kept
/// (`nse-phase-budget`).
#[test]
fn a_runaway_script_ends_its_phase_under_a_budget() {
    use nmap_core::nse::engine::ChosenScript;
    let tmp = std::env::temp_dir().join(format!("m64-runaway-{}", std::process::id()));
    std::fs::create_dir_all(&tmp).expect("tmp");
    let write = |name: &str, body: &str| {
        let p = tmp.join(name);
        std::fs::write(&p, body).expect("script");
        ChosenScript {
            path: p.display().to_string().into_bytes(),
            selection: "file path",
            verbosity: true,
            forced: false,
        }
    };
    let quick = write(
        "a-quick.nse",
        "categories = {}\nprerule = function() return true end\naction = function() return 'done' end\n",
    );
    let spin = write(
        "b-spin.nse",
        "categories = {}\nprerule = function() return true end\naction = function() while true do end end\n",
    );
    let mut st = nse_host::state(&nse_host::repo_root()).expect("state");
    st.load_scripts(&[quick, spin], Some(1 << 30))
        .expect("load");
    let r = st.run_phase(Phase::PreScan, vec![], Some(1 << 24));
    let _ = std::fs::remove_dir_all(&tmp);
    assert!(
        r.aborted
            .as_deref()
            .is_some_and(|e| e.contains("out of fuel")),
        "{:?}",
        r.aborted
    );
    // The order threads run in is the VM's table order, so the quick script
    // may or may not have finished first; if it did, its result is kept.
    assert!(r
        .run
        .iter()
        .all(|o| o.output.as_deref() == Some(&b"done"[..])));
}
