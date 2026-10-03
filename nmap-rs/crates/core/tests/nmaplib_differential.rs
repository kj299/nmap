//! M6.3 differential: the `nmap` module's non-I/O half against nmap itself.
//!
//! `tests/differential/m6/m63_nmap_golden.txt` is written by
//! `oracle/gen_m63_nmap.py`, which runs nmap 7.94 over loopback fixtures in
//! several scenarios — options, `--script-args`, `-sV`, UDP, selection by name
//! and by category — and records, for each, the command line, the scan's facts
//! (taken from a script-free run's `-oX`), the output of `oracle/m63_probe.nse`
//! and the lines it logged.
//!
//! This test rebuilds each scenario for the port: the options from the same
//! command line (through `core::options` where the port parses the flag), the
//! host from the facts, and the script arguments through
//! `core::nse::scriptargs`. It runs the same probe through the port's VM and
//! requires the same output, byte for byte, and the same log lines.
//!
//! `M63_GOLDEN` names a different golden file: CI regenerates one against the
//! installed nmap and points this test at it, so the comparison is also made
//! against a live oracle on every run.
#![cfg(not(miri))] // reads the corpus from disk; Miri has no filesystem

use std::cell::RefCell;
use std::net::IpAddr;
use std::path::{Path, PathBuf};
use std::rc::Rc;

use nmap_core::model::{PortState, Protocol};
use nmap_core::nse::nmaplib::{
    host_table, load_nmap, DetectionType, Interface, Link, LogTarget, NmapEnv, NmapLib, Phase,
    ScriptHost, ScriptPort, ServiceDeductions, Times, Tunnel,
};
use nmap_core::nse::scriptargs::registry_args;
use nmap_core::nse::stdlib::{load_format, load_patterns, load_strpack, load_tail};
use nmap_core::options::parse_args;
use nmap_core::ports::ServiceTable;
use nmap_core::probedb::ProbeDb;
use piccolo::{Closure, Executor, Fuel, Lua, Table, Value};

fn m6(file: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../tests/differential/m6")
        .join(file)
}

fn unhex(s: &str) -> Vec<u8> {
    s.as_bytes()
        .chunks(2)
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).expect("ascii"), 16).expect("hex"))
        .collect()
}

fn text(s: &str) -> String {
    String::from_utf8(unhex(s)).expect("the golden's text fields are UTF-8")
}

#[derive(Default)]
struct Scenario {
    name: String,
    by_name: bool,
    args: Vec<String>,
    ip: String,
    hostname: Vec<u8>,
    targetname: Option<Vec<u8>>,
    reason: String,
    reason_ttl: u8,
    mac: Option<Vec<u8>>,
    ports: Vec<(u16, String, String, String, u8)>,
    svc: Vec<(u16, String, String, Vec<u8>)>,
    svcnames: Vec<(u16, String, String)>,
    output: Vec<u8>,
    stdout: Vec<Vec<u8>>,
    stderr: Vec<Vec<u8>>,
}

fn scenarios(path: &Path) -> Vec<Scenario> {
    let body = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    let mut cur = Scenario::default();
    for line in body
        .lines()
        .filter(|l| !l.starts_with('#') && !l.is_empty())
    {
        let f: Vec<&str> = line.split(' ').collect();
        match f[0] {
            "scenario" => cur.name = f[1].to_string(),
            "by_name" => cur.by_name = f[1] == "1",
            "arg" => cur.args.push(text(f[1])),
            "host" => match f[1] {
                "ip" => cur.ip = text(f[2]),
                "hostname" => cur.hostname = unhex(f[2]),
                "targetname" => cur.targetname = Some(unhex(f[2])),
                "reason" => {
                    cur.reason = text(f[2]);
                    cur.reason_ttl = f[3].parse().expect("ttl");
                }
                "mac" => cur.mac = Some(unhex(f[2])),
                other => panic!("unknown host fact {other}"),
            },
            "port" => cur.ports.push((
                f[1].parse().expect("port"),
                f[2].to_string(),
                f[3].to_string(),
                text(f[4]),
                f[5].parse().expect("ttl"),
            )),
            "svc" => cur.svc.push((
                f[1].parse().expect("port"),
                f[2].to_string(),
                f[3].to_string(),
                unhex(f[4]),
            )),
            "svcname" => {
                cur.svcnames
                    .push((f[1].parse().expect("port"), f[2].to_string(), text(f[3])))
            }
            "output" => cur.output = unhex(f[1]),
            "stdout" => cur.stdout.push(unhex(f[1])),
            "stderr" => cur.stderr.push(unhex(f[1])),
            "end" => out.push(std::mem::take(&mut cur)),
            other => panic!("unknown golden line {other}"),
        }
    }
    out
}

fn protocol(s: &str) -> Protocol {
    match s {
        "tcp" => Protocol::Tcp,
        "udp" => Protocol::Udp,
        "sctp" => Protocol::Sctp,
        other => panic!("protocol {other}"),
    }
}

fn state(s: &str) -> PortState {
    match s {
        "open" => PortState::Open,
        "closed" => PortState::Closed,
        "filtered" => PortState::Filtered,
        "unfiltered" => PortState::Unfiltered,
        "open|filtered" => PortState::OpenFiltered,
        "closed|filtered" => PortState::ClosedFiltered,
        other => panic!("state {other}"),
    }
}

/// The reason tokens are `&'static str` in the module; the golden's are
/// mapped onto the same set.
fn reason(s: &str) -> &'static str {
    match s {
        "user-set" => "user-set",
        "syn-ack" => "syn-ack",
        "conn-refused" => "conn-refused",
        "reset" => "reset",
        "port-unreach" => "port-unreach",
        "udp-response" => "udp-response",
        "no-response" => "no-response",
        "localhost-response" => "localhost-response",
        "echo-reply" => "echo-reply",
        "arp-response" => "arp-response",
        other => panic!("reason {other} is not mapped in this test"),
    }
}

// ---- reading the probe's own rendering, for the passed-through host facts ---

/// A value as the probe's `render` writes it.
#[derive(Debug, Clone)]
enum R {
    Str(Vec<u8>),
    Int(i64),
    Float(f64),
    Bool(bool),
    Table(Vec<(R, R)>),
    Other,
}

fn parse_render(s: &[u8], pos: &mut usize) -> R {
    let rest = &s[*pos..];
    if rest.starts_with(b"{") {
        *pos = pos.saturating_add(1);
        let mut items = Vec::new();
        while s[*pos] != b'}' {
            let k = parse_render(s, pos);
            assert_eq!(s[*pos], b'=');
            *pos = pos.saturating_add(1);
            let v = parse_render(s, pos);
            items.push((k, v));
            if s[*pos] == b',' {
                *pos = pos.saturating_add(1);
            }
        }
        *pos = pos.saturating_add(1);
        return R::Table(items);
    }
    let end = rest
        .iter()
        .position(|&b| b == b',' || b == b'}' || b == b'=' || b == b' ')
        .map_or(s.len(), |i| pos.saturating_add(i));
    let tok = std::str::from_utf8(&s[*pos..end]).expect("ascii");
    *pos = end;
    if let Some(h) = tok.strip_prefix("s:") {
        R::Str(unhex(h))
    } else if let Some(n) = tok.strip_prefix("integer:") {
        R::Int(n.parse().expect("int"))
    } else if let Some(n) = tok.strip_prefix("float:") {
        R::Float(n.parse().expect("float"))
    } else if tok == "true" || tok == "false" {
        R::Bool(tok == "true")
    } else {
        R::Other
    }
}

fn field<'a>(t: &'a [(R, R)], key: &str) -> Option<&'a R> {
    t.iter()
        .find(|(k, _)| matches!(k, R::Str(s) if s == key.as_bytes()))
        .map(|(_, v)| v)
}

fn probe_line<'a>(output: &'a [u8], prefix: &str) -> &'a [u8] {
    output
        .split(|&b| b == b'\n')
        .find_map(|l| l.strip_prefix(prefix.as_bytes()))
        .unwrap_or_else(|| panic!("the probe printed no {prefix:?} line"))
}

fn mac(v: Option<&R>) -> Option<[u8; 6]> {
    match v {
        Some(R::Str(s)) => Some(s.as_slice().try_into().expect("6 bytes")),
        _ => None,
    }
}

/// Seconds as the probe printed them, back to the microseconds they came from.
fn micros(v: Option<&R>) -> i64 {
    match v {
        #[allow(clippy::cast_possible_truncation)]
        Some(R::Float(f)) => (f * 1_000_000.0).round() as i64,
        other => panic!("times field {other:?}"),
    }
}

fn build_host(sc: &Scenario) -> ScriptHost {
    let ip: IpAddr = sc.ip.parse().expect("ip");
    let mut h = ScriptHost::new(ip);
    h.hostname = sc.hostname.clone();
    h.targetname = sc.targetname.clone();
    h.reason = reason(&sc.reason);
    h.reason_ttl = sc.reason_ttl;
    h.mac = sc
        .mac
        .as_ref()
        .map(|m| m.as_slice().try_into().expect("mac"));
    // Facts -oX does not record, passed through from what the probe saw.
    let line = probe_line(&sc.output, "HOST ");
    let R::Table(host) = parse_render(line, &mut 0) else {
        panic!("HOST is not a table")
    };
    h.interface = match field(&host, "interface") {
        Some(R::Str(s)) => Some(s.clone()),
        _ => None,
    };
    h.mtu = match field(&host, "interface_mtu") {
        Some(R::Int(n)) => *n,
        _ => 0,
    };
    h.source = match field(&host, "bin_ip_src") {
        Some(R::Str(b)) if b.len() == 4 => {
            Some(IpAddr::from(<[u8; 4]>::try_from(b.as_slice()).unwrap()))
        }
        Some(R::Str(b)) if b.len() == 16 => {
            Some(IpAddr::from(<[u8; 16]>::try_from(b.as_slice()).unwrap()))
        }
        _ => None,
    };
    h.directly_connected = match field(&host, "directly_connected") {
        Some(R::Bool(b)) => Some(*b),
        _ => None,
    };
    h.src_mac = mac(field(&host, "mac_addr_src"));
    h.next_hop_mac = mac(field(&host, "mac_addr_next_hop"));
    if let Some(R::Table(t)) = field(&host, "times") {
        h.times = Times {
            srtt: micros(field(t, "srtt")),
            rttvar: micros(field(t, "rttvar")),
            timeout: micros(field(t, "timeout")),
        };
    }
    for (num, proto, st, why, ttl) in &sc.ports {
        let rows: Vec<_> = sc
            .svc
            .iter()
            .filter(|(n, p, _, _)| n == num && p == proto)
            .collect();
        let get = |k: &str| {
            rows.iter()
                .find(|(_, _, key, _)| key == k)
                .map(|(_, _, _, v)| v.clone())
        };
        let service = (!rows.is_empty()).then(|| ServiceDeductions {
            // A table-typed record's name is the services lookup's, which
            // the XML prints as "unknown" when there is none.
            name: if get("method").as_deref() == Some(b"table") {
                None
            } else {
                get("name")
            },
            name_confidence: get("conf")
                .map_or(0, |c| std::str::from_utf8(&c).unwrap().parse().unwrap()),
            product: get("product"),
            version: get("version"),
            extrainfo: get("extrainfo"),
            hostname: get("hostname"),
            ostype: get("ostype"),
            devicetype: get("devicetype"),
            tunnel: if get("tunnel").as_deref() == Some(b"ssl") {
                Tunnel::Ssl
            } else {
                Tunnel::None
            },
            service_fp: get("servicefp"),
            dtype: if get("method").as_deref() == Some(b"probed") {
                DetectionType::Probed
            } else {
                DetectionType::Table
            },
            cpe: rows
                .iter()
                .filter(|(_, _, k, _)| k == "cpe")
                .map(|(_, _, _, v)| v.clone())
                .collect(),
        });
        h.ports.push(ScriptPort {
            number: *num,
            protocol: protocol(proto),
            state: state(st),
            reason: reason(why),
            reason_ttl: *ttl,
            service,
        });
    }
    h
}

/// The probe's view of whether nmap is privileged and has SSL.
fn passthrough_bool(output: &[u8], label: &str) -> bool {
    probe_line(output, &format!("{label} ok 1 ")) == b"true"
}

type Logs = Rc<RefCell<Vec<(LogTarget, Vec<u8>)>>>;

fn build_env(sc: &Scenario, logs: &Logs) -> (NmapEnv, Option<Vec<u8>>) {
    // The flags the port's option parser knows; the rest are NSE's or are
    // read here.
    let mut known = Vec::new();
    let mut interface = None;
    let mut data_length = -1;
    let mut allports = false;
    let mut script_args = None;
    let mut it = sc.args.iter();
    while let Some(a) = it.next() {
        let mut value = || it.next().expect("the option's value").clone();
        match a.as_str() {
            "-e" => interface = Some(value().into_bytes()),
            "--data-length" => data_length = value().parse().expect("data length"),
            "--allports" => allports = true,
            "--script-args" => script_args = Some(value().into_bytes()),
            _ => known.push(a.clone()),
        }
    }
    let cfg = parse_args(&known);
    let probes = std::fs::read_to_string(m6("../../../../nmap-service-probes"))
        .expect("nmap-service-probes");
    let db = ProbeDb::parse(&probes);
    let services: String = sc
        .svcnames
        .iter()
        .map(|(n, p, name)| format!("{name}\t{n}/{p}\t0.001\n"))
        .collect();
    let logs = logs.clone();
    let env = NmapEnv {
        verbose: i64::from(cfg.verbose),
        debugging: i64::from(cfg.debugging),
        timing_level: cfg.timing_template.map_or(3, |t| t as i64),
        version_intensity: i64::from(cfg.version_intensity),
        ttl: cfg.ttl.map_or(-1, i64::from),
        data_length,
        have_ssl: passthrough_bool(&sc.output, "have_ssl"),
        privileged: passthrough_bool(&sc.output, "is_privileged"),
        ipv6: cfg.ipv6,
        interface,
        dns_servers: vec![b"127.0.0.53".to_vec()],
        excluded_ports: (cfg.service_version && !allports).then(|| db.exclude.clone()),
        services: Some(ServiceTable::parse(&services)),
        phase: Phase::Scan,
        interfaces: Ok(vec![Interface {
            device: b"lo".to_vec(),
            shortname: b"lo".to_vec(),
            netmask_bits: 8,
            address: "127.0.0.1".parse().unwrap(),
            link: Link::Loopback,
            up: true,
            mtu: 65536,
        }]),
        fetchfile: Box::new(|name| {
            (name == b"nmap-services").then(|| b"/usr/share/nmap/nmap-services".to_vec())
        }),
        clock: Box::new(|| (1_700_000_000, 123_456)),
        random: Box::new(|buf| {
            buf.fill(0x41);
            true
        }),
        log: Box::new(move |to, msg| logs.borrow_mut().push((to, msg.to_vec()))),
    };
    (env, script_args)
}

/// The generator's `LOG_LINE` filter.
fn probe_logged(l: &[u8]) -> bool {
    let s = String::from_utf8_lossy(l);
    s.starts_with("NSE: m63-log")
        || s == "NSE: 63"
        || s.starts_with("finalizing a non-conforming")
        || s.starts_with("ERROR: adding targets")
        || s.starts_with("ERROR: new target")
        || s.starts_with("Warning: Valid values of script arg")
        || s.starts_with("EXCLUDING ")
        || s.starts_with("New Targets: ")
        || (s.starts_with("Discovered ")
            && (s.ends_with(" on 127.0.0.1") || s.ends_with(" on ::1")))
}

fn split_logs(logs: &Logs) -> (Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let (mut out, mut err) = (Vec::new(), Vec::new());
    for (to, msg) in logs.borrow().iter() {
        let dest = match to {
            LogTarget::Stdout | LogTarget::Plain => &mut out,
            LogTarget::Stderr | LogTarget::Error => &mut err,
        };
        for line in msg.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
            dest.push(line.to_vec());
        }
    }
    let begin = out
        .iter()
        .position(|l| l == b"NSE: m63-log begin")
        .unwrap_or(0);
    (
        out[begin..]
            .iter()
            .filter(|l| probe_logged(l))
            .cloned()
            .collect(),
        err.into_iter().filter(|l| probe_logged(l)).collect(),
    )
}

/// Run the probe for one scenario: its output and the lines it logged.
fn run_probe(sc: &Scenario) -> (Vec<u8>, Vec<Vec<u8>>, Vec<Vec<u8>>) {
    let logs: Logs = Rc::default();
    let (env, cli) = build_env(sc, &logs);
    let args = registry_args(None, cli.as_deref().unwrap_or(b"")).expect("script args parse");
    let lib = NmapLib::new(env);
    lib.borrow_mut().set_hosts(vec![build_host(sc)]);
    lib.borrow_mut().selected_by_name = sc.by_name;
    let source = std::fs::read(m6("oracle/m63_probe.nse")).expect("probe");

    let mut lua = Lua::core();
    let (env_t, ex) = lua.enter(|ctx| {
        load_patterns(ctx).unwrap();
        load_strpack(ctx).unwrap();
        load_format(ctx).unwrap();
        load_tail(ctx).unwrap();
        load_nmap(ctx, &lib, &args);
        // NSE gives each script its own environment over the globals.
        let env = Table::new(&ctx);
        let mt = Table::new(&ctx);
        mt.set_field(ctx, "__index", ctx.globals());
        env.set_metatable(&ctx, Some(mt));
        let chunk =
            Closure::load_with_env(ctx, Some("m63_probe"), &source, env).expect("probe compiles");
        (
            ctx.stash(env),
            ctx.stash(Executor::start(ctx, chunk.into(), ())),
        )
    });
    lua.finish(&ex).expect("probe loads");
    let ex = lua.enter(|ctx| {
        let env = ctx.fetch(&env_t);
        let host = host_table(ctx, &lib, 0);
        let Value::Function(action) = env.get_value(ctx, "action") else {
            panic!("no action")
        };
        ctx.stash(Executor::start(ctx, action, host))
    });
    let mut spent = 0u64;
    loop {
        let mut fuel = Fuel::with(1 << 16);
        if lua
            .enter(|ctx| ctx.fetch(&ex).step(ctx, &mut fuel))
            .expect("executor is running")
        {
            break;
        }
        spent = spent.saturating_add(1 << 16);
        assert!(spent < 1 << 32, "{}: the probe does not finish", sc.name);
    }
    let output = lua.enter(|ctx| match ctx.fetch(&ex).take_result::<Value>(ctx) {
        Ok(Ok(Value::String(s))) => s.as_bytes().to_vec(),
        Ok(Ok(v)) => panic!("{}: action returned {v:?}", sc.name),
        Ok(Err(e)) => panic!("{}: action raised {e}", sc.name),
        Err(e) => panic!("{}: {e}", sc.name),
    });
    let (stdout, stderr) = split_logs(&logs);
    (output, stdout, stderr)
}

fn first_difference(a: &[u8], b: &[u8]) -> String {
    let la: Vec<&[u8]> = a.split(|&c| c == b'\n').collect();
    let lb: Vec<&[u8]> = b.split(|&c| c == b'\n').collect();
    for (i, (x, y)) in la.iter().zip(lb.iter()).enumerate() {
        if x != y {
            return format!(
                "line {}:\n      nmap = {}\n      port = {}",
                i.saturating_add(1),
                String::from_utf8_lossy(x),
                String::from_utf8_lossy(y)
            );
        }
    }
    format!(
        "lengths differ: nmap {} lines, port {} lines",
        la.len(),
        lb.len()
    )
}

#[test]
fn the_nmap_module_matches_nmap_itself() {
    let golden =
        std::env::var_os("M63_GOLDEN").map_or_else(|| m6("m63_nmap_golden.txt"), PathBuf::from);
    let all = scenarios(&golden);
    assert!(
        all.len() >= 9,
        "only {} scenarios in {}",
        all.len(),
        golden.display()
    );
    let mut failures = Vec::new();
    for sc in &all {
        let (output, stdout, stderr) = run_probe(sc);
        if output != sc.output {
            failures.push(format!(
                "  {}: output, {}",
                sc.name,
                first_difference(&sc.output, &output)
            ));
        }
        if stdout != sc.stdout {
            failures.push(format!(
                "  {}: stdout lines\n      nmap = {:?}\n      port = {:?}",
                sc.name,
                sc.stdout
                    .iter()
                    .map(|l| String::from_utf8_lossy(l))
                    .collect::<Vec<_>>(),
                stdout
                    .iter()
                    .map(|l| String::from_utf8_lossy(l))
                    .collect::<Vec<_>>()
            ));
        }
        if stderr != sc.stderr {
            failures.push(format!(
                "  {}: stderr lines\n      nmap = {:?}\n      port = {:?}",
                sc.name,
                sc.stderr
                    .iter()
                    .map(|l| String::from_utf8_lossy(l))
                    .collect::<Vec<_>>(),
                stderr
                    .iter()
                    .map(|l| String::from_utf8_lossy(l))
                    .collect::<Vec<_>>()
            ));
        }
    }
    assert!(
        failures.is_empty(),
        "{} differences:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
