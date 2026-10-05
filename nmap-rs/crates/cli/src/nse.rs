//! NSE from the command line (M6.4e): `open_nse`, then `script_scan` for each
//! phase (`nmap.cc:2084-2356`).
//!
//! The engine runs on a thread of its own. Its Lua state is not `Send`, and
//! the network scripts use (`sys::nsenet`) drives a runtime of its own. The
//! scan talks to it by message: one request per phase, one reply with that
//! phase's results.
//!
//! Between slices of VM work the engine asks a watchdog whether to go on.
//! It stops a phase when the script scheduler has made no pass for the stall
//! limit (`nse-stall-limit`): `--script-timeout` when given, else ten
//! minutes. nmap has no such limit, and a script that never yields hangs it.

use std::cell::RefCell;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::mpsc;
use std::time::{Duration, Instant};

use nmap_core::model::Host;
use nmap_core::nse::choose::{choose, RuleOptions};
use nmap_core::nse::engine::{EngineOptions, PhaseResults};
use nmap_core::nse::fspolicy::named_values;
use nmap_core::nse::nmaplib::{LogTarget, NmapEnv, NmapLib, Phase, ScriptHost, ScriptPort};
use nmap_core::nse::runtime::{new_state, NseState, StateConfig};
use nmap_core::nse::script::parse_script_db;
use nmap_core::nse::scriptargs::registry_args;
use nmap_core::nse::stdlib::oslib::OsEnv;
use nmap_core::ports::PortList;
use nmap_core::ServiceTable;
use nmap_sys::datadir::{self, DataDirs};
use nmap_sys::nsefs::PolicyFs;
use nmap_sys::nsehost::{self, DataLocator, DataSource, ProgressNet};
use nmap_sys::nsenet::TokioNet;

/// The stall limit when `--script-timeout` is not given.
pub const DEFAULT_STALL: Duration = Duration::from_secs(600);

/// What the engine reads of the run: the options `open_nse` and `cnse` take.
pub struct Setup {
    pub data: DataDirs,
    /// `--script` rules; with none, `default` runs (`check_rules`).
    pub rules: Vec<String>,
    pub script_args: String,
    pub script_args_file: Option<String>,
    pub script_timeout: f64,
    pub stall: Duration,
    pub verbose: i64,
    pub debugging: i64,
    pub timing_level: i64,
    pub version_intensity: i64,
    pub ttl: i64,
    pub ipv6: bool,
    pub min_parallelism: i64,
    pub max_parallelism: i64,
    pub services: Option<ServiceTable>,
    pub excluded_ports: Option<PortList>,
}

/// The engine, started and holding the chosen scripts.
pub struct Nse {
    requests: mpsc::Sender<(Phase, Vec<ScriptHost>)>,
    replies: mpsc::Receiver<PhaseResults>,
}

impl Nse {
    /// `open_nse`: build the engine and load the chosen scripts. The error is
    /// what nmap prints after "NSE: failed to initialize the script engine:".
    pub fn start(setup: Setup) -> Result<Nse, String> {
        let (req_tx, req_rx) = mpsc::channel::<(Phase, Vec<ScriptHost>)>();
        let (rep_tx, rep_rx) = mpsc::channel::<PhaseResults>();
        let (init_tx, init_rx) = mpsc::channel::<Result<(), String>>();
        std::thread::Builder::new()
            .name("nse".into())
            .spawn(move || {
                let mut st = match open(setup) {
                    Ok(st) => {
                        let _ = init_tx.send(Ok(()));
                        st
                    }
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                        return;
                    }
                };
                for (phase, hosts) in req_rx {
                    st.mark();
                    let r = st.state.run_phase(phase, hosts, None);
                    if rep_tx.send(r).is_err() {
                        return;
                    }
                }
            })
            .map_err(|e| format!("could not start the script engine: {e}"))?;
        init_rx
            .recv()
            .map_err(|_| "the script engine stopped while starting".to_string())??;
        Ok(Nse {
            requests: req_tx,
            replies: rep_rx,
        })
    }

    /// `script_scan(hosts, phase)`: the phase's results, or `None` if the
    /// engine's thread is gone.
    pub fn run(&self, phase: Phase, hosts: Vec<ScriptHost>) -> Option<PhaseResults> {
        self.requests.send((phase, hosts)).ok()?;
        self.replies.recv().ok()
    }
}

/// The engine's state on its thread, and when the scheduler last made a
/// pass.
struct Running {
    state: NseState,
    last_pass: Rc<std::cell::Cell<Instant>>,
}

impl Running {
    /// A phase starts with a clean slate: time spent between phases (the
    /// port scan) is not the scripts'.
    fn mark(&self) {
        self.last_pass.set(Instant::now());
    }
}

fn bytes(p: &std::path::Path) -> Vec<u8> {
    p.to_string_lossy().into_owned().into_bytes()
}

fn open(setup: Setup) -> Result<Running, String> {
    let data = setup.data;
    // `nmap.registry.args`: the file first, then `--script-args`
    // (`nse_main.lua:1249`). The file is found as `fetchfile_absolute` finds
    // it, and the C's assertion message is kept.
    let file_args = match &setup.script_args_file {
        None => None,
        Some(name) => match data.fetch_absolute(name) {
            Some(p) if p.is_file() => {
                Some(std::fs::read(&p).map_err(|e| format!("{}: {e}", p.display()))?)
            }
            Some(p) => return Err(format!("{} is not a file", p.display())),
            None => return Err("nil is not a file".to_string()),
        },
    };
    let args = registry_args(file_args.as_deref(), setup.script_args.as_bytes())
        .map_err(|e| e.to_string())?;

    // The script database. nmap writes a new one when it is missing; this
    // port does not write into a data directory unasked
    // (`nse-script-db-required`).
    let db_path = data.fetch("scripts/script.db").ok_or_else(|| {
        "the script database (scripts/script.db) was not found in any data directory. \
         Give --datadir, or set NMAPDIR, to a directory holding nmap's scripts/ and nselib/."
            .to_string()
    })?;
    let db_text = std::fs::read(&db_path).map_err(|e| format!("{}: {e}", db_path.display()))?;
    let db = parse_script_db(&db_text).map_err(|e| {
        format!(
            "NSE script database appears to be corrupt or out of date ({e:?}); \
             this port does not rebuild it"
        )
    })?;
    let rules: Vec<Vec<u8>> = setup.rules.iter().map(|r| r.as_bytes().to_vec()).collect();
    let chosen = choose(
        &rules,
        RuleOptions {
            default: true,
            version: false,
        },
        &db,
        &DataLocator(data.clone()),
    );

    // Scripts read beneath the data directories and the files named in
    // their arguments, and write only the latter (Decision 2). Also
    // readable, never writable: the scripts the operator chose, wherever
    // they are (`--script ./mine.nse`), and their SSH client files, for
    // `ssh1.lua`.
    let home = datadir::home();
    let read_only: Vec<PathBuf> = chosen
        .scripts
        .iter()
        .map(|c| PathBuf::from(String::from_utf8_lossy(&c.path).into_owned()))
        .chain(
            home.iter()
                .flat_map(|h| [h.join(".ssh/config"), h.join(".ssh/known_hosts")]),
        )
        .collect();
    let fs = PolicyFs::new(&data.existing(), &[], &named_values(&args)).with_read_files(&read_only);

    let fetch_dirs = data.clone();
    let started = Instant::now();
    let env = NmapEnv {
        verbose: setup.verbose,
        debugging: setup.debugging,
        timing_level: setup.timing_level,
        version_intensity: setup.version_intensity,
        ttl: setup.ttl,
        data_length: -1,
        have_ssl: false,
        privileged: false,
        ipv6: setup.ipv6,
        interface: None,
        dns_servers: vec![],
        excluded_ports: setup.excluded_ports,
        services: setup.services,
        phase: Phase::PreScan,
        interfaces: nsehost::interfaces(),
        fetchfile: Box::new(move |f| {
            let name = std::str::from_utf8(f).ok()?;
            fetch_dirs.fetch_absolute(name).map(|p| bytes(&p))
        }),
        clock: Box::new(|| {
            let d = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default();
            (
                i64::try_from(d.as_secs()).unwrap_or(i64::MAX),
                i64::from(d.subsec_micros()),
            )
        }),
        random: Box::new(nsehost::random_bytes),
        log: Box::new(|to, line| {
            use std::io::Write as _;
            match to {
                LogTarget::Stdout | LogTarget::Plain => {
                    let mut out = std::io::stdout().lock();
                    let _ = out.write_all(line);
                    let _ = out.flush();
                }
                LogTarget::Stderr | LogTarget::Error => {
                    let _ = std::io::stderr().lock().write_all(line);
                }
            }
        }),
    };
    let os = OsEnv {
        now: Box::new(|| {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_or(0, |d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        }),
        cpu_seconds: Box::new(move || started.elapsed().as_secs_f64()),
        home: home.as_deref().map(bytes),
    };
    let net = ProgressNet::new(
        TokioNet::new().ok_or_else(|| "could not start the scripts' network".to_string())?,
    );
    let last_pass = net.last_pass();
    let mut state = new_state(&StateConfig {
        lib: NmapLib::new(env),
        args,
        source: Rc::new(DataSource(data)),
        fs: Rc::new(fs),
        os: Rc::new(os),
        memory_limit: None,
        engine: EngineOptions {
            script_timeout: setup.script_timeout,
            min_parallelism: setup.min_parallelism,
            max_parallelism: setup.max_parallelism,
        },
        net: Rc::new(RefCell::new(net)),
    })?;
    let watched = last_pass.clone();
    let stall = setup.stall;
    state.set_watchdog(Some(Box::new(move || {
        (watched.get().elapsed() > stall).then(|| {
            format!(
                "no script thread yielded for {} seconds (the stall limit; see --script-timeout)",
                stall.as_secs()
            )
        })
    })));
    last_pass.set(Instant::now());
    state.load_chosen(&chosen, None)?;
    Ok(Running { state, last_pass })
}

/// A scanned host as `set_hostinfo` sees it. The port does no reverse DNS,
/// so `HostName()` is empty and the name given on the command line is the
/// target name.
pub fn script_host(h: &Host) -> ScriptHost {
    let mut s = ScriptHost::new(h.address);
    s.targetname = h.hostname.as_ref().map(|n| n.as_bytes().to_vec());
    s.reason = h.reason.map_or("unknown", |r| r.as_str());
    s.ports = h.ports.iter().map(ScriptPort::from_model).collect();
    s
}
