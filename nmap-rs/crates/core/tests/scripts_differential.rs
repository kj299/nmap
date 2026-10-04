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

use std::path::PathBuf;

use nmap_core::nse::nmaplib::Phase;
use nse_host::scenarios::{check, m6, Fixtures};

#[test]
fn scripts_run_as_under_nmap() {
    let golden = std::env::var_os("M64_SCRIPTS_GOLDEN")
        .map_or_else(|| m6().join("m64_scripts_golden.txt"), PathBuf::from);
    let fx = Fixtures {
        dir: "nse_scripts",
        shipped: &["unittest.nse"],
    };
    let (n, failures) = check(&golden, &fx, || {
        std::rc::Rc::new(std::cell::RefCell::new(nmap_core::nse::net::NoNet))
    });
    assert!(n >= 30, "only {n} scenarios");
    assert!(
        failures.is_empty(),
        "{} of {n} scenarios differ:\n{}",
        failures.len(),
        failures.join("\n")
    );
}
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

/// `nmap.get_interface_info` (`dnet.get_interface_info`): the interface of
/// the scan's family named by its full or short name, described as
/// `list_interfaces` describes it, with the C's errors.
#[test]
fn get_interface_info_describes_an_interface() {
    use nmap_core::nse::nmaplib::{Interface, Link, NmapEnv, NmapLib};
    use nmap_core::nse::runtime::{new_state, run_chunk, ChunkOutcome, StateConfig};
    let dir = nse_host::repo_root();
    let eth = Interface {
        device: b"eth0".to_vec(),
        shortname: b"eth0".to_vec(),
        netmask_bits: 24,
        address: "192.0.2.10".parse().expect("ip"),
        link: Link::Ethernet([0, 1, 2, 3, 4, 5]),
        up: true,
        mtu: 1500,
    };
    let lo6 = Interface {
        device: b"lo".to_vec(),
        shortname: b"lo".to_vec(),
        netmask_bits: 128,
        address: "::1".parse().expect("ip"),
        link: Link::Loopback,
        up: true,
        mtu: 65536,
    };
    let mut st = new_state(&StateConfig {
        lib: NmapLib::new(NmapEnv {
            interfaces: Ok(vec![eth, lo6]),
            ..nse_host::env(dir.clone())
        }),
        args: Default::default(),
        source: std::rc::Rc::new(nse_host::Dir(dir)),
        fs: std::rc::Rc::new(nse_host::ReadOnlyFs),
        os: std::rc::Rc::new(nse_host::os_env()),
        memory_limit: Some(256 << 20),
        engine: Default::default(),
        net: std::rc::Rc::new(std::cell::RefCell::new(nmap_core::nse::net::NoNet)),
    })
    .expect("state");
    let got = run_chunk(
        &mut st.lua,
        "=t",
        b"local i = nmap.get_interface_info('eth0')\n\
          local _, lo = pcall(nmap.get_interface_info, 'lo')\n\
          local _, long = pcall(nmap.get_interface_info, string.rep('x', 32))\n\
          local d = nmap.new_dnet()\n\
          local _, send = pcall(d.ip_send, d, 'x')\n\
          return i.device, i.address, i.netmask, i.link, i.broadcast, #i.mac, i.up, i.mtu,\n\
            lo, long, type(d), send",
        1 << 22,
    );
    let want: Vec<String> = [
        "eth0",
        "192.0.2.10",
        "24",
        "ethernet",
        "192.0.2.255",
        "6",
        "up",
        "1500",
        "bad argument #1 to 'get_interface_info' (device %s not found or no address configured)",
        "bad argument #1 to 'get_interface_info' (device name too long)",
        "userdata",
        "raw packet sending (nmap.dnet) is not available yet",
    ]
    .iter()
    .map(|s| s.to_string())
    .collect();
    assert_eq!(got, ChunkOutcome::Returned(want));
}
