//! Run scripts through the three phases of a scan against one loopback host
//! with one open TCP port, and print their results as nmap prints them.
//!
//!     cargo run -p nmap-core --example nse_run -- DATADIR SCRIPT.nse...
#[path = "../tests/nse_host/mod.rs"]
mod nse_host;

use std::net::{IpAddr, Ipv4Addr};
use std::path::PathBuf;

use nmap_core::model::{PortState, Protocol};
use nmap_core::nse::engine::ChosenScript;
use nmap_core::nse::nmaplib::{Phase, ScriptHost, ScriptPort};
use nmap_core::nse::results::{host_normal, host_xml, phase_normal, phase_xml, ScriptPhase};

fn main() {
    let mut argv = std::env::args().skip(1);
    let dir = PathBuf::from(argv.next().expect("DATADIR"));
    let chosen: Vec<ChosenScript> = argv
        .map(|p| ChosenScript {
            path: p.into_bytes(),
            selection: "file path",
            verbosity: true,
            forced: false,
        })
        .collect();
    let mut st = nse_host::state(&dir).expect("state");
    if let Err(e) = st.load_scripts(&chosen, Some(1 << 32)) {
        println!("failed to initialize the script engine:\n{e}");
        return;
    }
    let out = |s: Vec<u8>| print!("{}", String::from_utf8_lossy(&s));
    let pre = st.run_phase(Phase::PreScan, vec![], Some(1 << 32));
    out(phase_normal(ScriptPhase::PreScan, &pre.run));
    out(phase_xml(ScriptPhase::PreScan, &pre.run));
    println!();
    let mut host = ScriptHost::new(IpAddr::V4(Ipv4Addr::LOCALHOST));
    host.ports.push(ScriptPort {
        number: 80,
        protocol: Protocol::Tcp,
        state: PortState::Open,
        reason: "syn-ack",
        reason_ttl: 64,
        service: None,
    });
    let scan = st.run_phase(Phase::Scan, vec![host], Some(1 << 32));
    for h in &scan.hosts {
        for (proto, n, rs) in &h.ports {
            println!("port {n}/{}", proto.as_str());
            for r in rs {
                if let Some(l) = r.normal() {
                    out(l);
                    println!();
                }
                out(r.xml());
                println!();
            }
        }
        out(host_normal(&h.results));
        out(host_xml(&h.results));
        println!();
    }
    let post = st.run_phase(Phase::PostScan, vec![], Some(1 << 32));
    out(phase_normal(ScriptPhase::PostScan, &post.run));
    out(phase_xml(ScriptPhase::PostScan, &post.run));
    println!();
    for (name, r) in [("pre", &pre), ("scan", &scan), ("post", &post)] {
        if let Some(e) = &r.aborted {
            println!("{name} aborted: {e}");
        }
    }
}
