//! Scenario gates against nmap itself: a golden of what nmap's scripts left,
//! rebuilt and run through the port's engine (`scripts_differential` in this
//! crate, `nse_net_differential` in `nmap-sys`).
#![cfg(unix)] // data directories made of symlinks

use std::net::{IpAddr, Ipv4Addr};
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::nse::engine::EngineOptions;
use nmap_core::nse::net::SharedNet;

use nmap_core::model::{PortState, Protocol};
use nmap_core::nse::choose::{choose, Found, RuleOptions, ScriptLocator};
use nmap_core::nse::engine::PhaseResults;
use nmap_core::nse::nmaplib::{NmapLib, Phase, ScriptHost, ScriptPort};
use nmap_core::nse::runtime::{new_state, StateConfig};
use nmap_core::nse::script::parse_script_db;
use nmap_core::nse::scriptargs::registry_args;
use nmap_core::nse::selection::split_arg;

pub fn m6() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../tests/differential/m6")
}

pub fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).expect("ascii"), 16).expect("hex"))
        .collect()
}

/// One result: container, script id, normal-output lines, `<script>` XML.
pub type Row = (String, Vec<u8>, Option<Vec<u8>>, Vec<u8>);

#[derive(Default)]
pub struct Scenario {
    pub name: String,
    pub args: Vec<String>,
    pub ports: Vec<ScriptPort>,
    pub init_error: Option<Vec<u8>>,
    pub results: Vec<Row>,
}

pub fn reason(s: &str) -> &'static str {
    match s {
        "syn-ack" => "syn-ack",
        "conn-refused" => "conn-refused",
        "reset" => "reset",
        other => panic!("reason {other} not in the fixtures"),
    }
}

pub fn scenarios(golden: &Path) -> Vec<Scenario> {
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

/// Where a gate's scripts come from.
pub struct Fixtures {
    /// The fixture directory under `tests/differential/m6/`.
    pub dir: &'static str,
    /// Shipped scripts linked in beside the fixtures.
    pub shipped: &'static [&'static str],
}

/// A data directory laid out as the generators lay it out: the repository's
/// data files and `nselib/`, and in `scripts/` the fixtures and the shipped
/// scripts named.
pub fn datadir(tmp: &Path, fx: &Fixtures) -> PathBuf {
    let repo = super::repo_root();
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
    for e in std::fs::read_dir(m6().join(fx.dir))
        .expect("fixtures")
        .flatten()
    {
        std::os::unix::fs::symlink(e.path(), scripts.join(e.file_name())).expect("symlink");
    }
    for name in fx.shipped {
        std::os::unix::fs::symlink(repo.join("scripts").join(name), scripts.join(name))
            .expect("symlink");
    }
    d
}

/// `nse_fetchscript` over the data directory.
pub struct Locator(PathBuf);

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

pub fn replace(hay: &[u8], from: &[u8], to: &[u8]) -> Vec<u8> {
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
pub fn error_line(e: &str) -> Vec<u8> {
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
pub fn run(sc: &Scenario, tmp: &Path, fx: &Fixtures, net: SharedNet) -> Result<Vec<Row>, Vec<u8>> {
    let data = datadir(tmp, fx);
    let shown = data.display().to_string().into_bytes();
    let norm = |b: &[u8]| replace(b, &shown, b"DATADIR");
    // The command line, as the scenarios use it.
    let (mut rules, mut options, mut script_args) =
        (Vec::new(), RuleOptions::default(), Vec::new());
    let mut debugging = 0;
    let mut engine = EngineOptions::default();
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
            // The ports scanned; their states come from the golden's facts.
            "-p" => {
                it.next();
            }
            "--script-timeout" => {
                engine.script_timeout = it.next().expect("seconds").parse().expect("number");
            }
            other => panic!("option {other}"),
        }
    }
    let db = parse_script_db(&std::fs::read(data.join("scripts/script.db")).expect("db"))
        .expect("db parses");
    let chosen = choose(&rules, options, &db, &Locator(data.clone()));
    let mut st = new_state(&StateConfig {
        lib: NmapLib::new(nmap_core::nse::nmaplib::NmapEnv {
            debugging,
            ..super::env(data.clone())
        }),
        args: registry_args(None, &script_args).expect("arguments parse"),
        source: Rc::new(super::Dir(data.clone())),
        fs: Rc::new(super::ReadOnlyFs),
        os: Rc::new(super::os_env()),
        memory_limit: Some(256 << 20),
        engine,
        net,
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

pub fn show(b: &[u8]) -> String {
    String::from_utf8_lossy(b).replace('\n', "\\n")
}

/// Run every scenario of `golden` and compare: how many there were, and a
/// description of each that differs.
pub fn check(golden: &Path, fx: &Fixtures, net: impl Fn() -> SharedNet) -> (usize, Vec<String>) {
    let all = scenarios(golden);
    let mut failures = Vec::new();
    for (i, sc) in all.iter().enumerate() {
        let tmp = std::env::temp_dir().join(format!("m64-scripts-{}-{i}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        let got = run(sc, &tmp, fx, net());
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
    (all.len(), failures)
}
