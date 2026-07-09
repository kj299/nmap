//! `nmap-cli` — thin entry point: parse args, set verbosity, call `nmap-core`,
//! render. Keep logic OUT of here (it belongs in `nmap-core`, where it is
//! testable and unsafe-free).
//!
//! Milestone 1 builds this out into the real nmap CLI surface (target spec,
//! `-p`, `-sT`, output formats). Verbosity (`-v`/`-d`) is wired early so every
//! module built after it can emit leveled diagnostics for troubleshooting.

use nmap_core::options;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let cfg = options::parse_args(&args);

    // Wire the parsed verbosity/debugging into the leveled logger before doing
    // anything else, so the rest of the run is diagnosable.
    nmap_core::log::init(cfg.verbose, cfg.debugging);
    nmap_core::trace!(
        "nmap-rs started: {} args, verbose={}, debug={}",
        args.len(),
        cfg.verbose,
        cfg.debugging
    );
    nmap_core::debug!(1, "parsed config: {cfg:?}");

    if cfg.show_version {
        println!("nmap-rs {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    if cfg.show_help {
        println!("usage: nmap-rs [-v|-vv|-vN] [-d|-dN] [--version] <target ...>");
        println!("  (Milestone 1 in progress; connect scan + full CLI landing module-by-module)");
        return;
    }

    for flag in &cfg.unrecognized {
        eprintln!("nmap-rs: warning: unrecognized option '{flag}' (not yet implemented)");
    }

    // The real scan pipeline (targets -> ports -> connect_scan -> output) is
    // wired here as each core module clears its gates.
    nmap_core::verbose!(1, "would scan {} target expression(s)", cfg.targets.len());
    println!(
        "nmap-rs {}: Milestone 1 in progress ({} target expr, {} unrecognized flag(s))",
        env!("CARGO_PKG_VERSION"),
        cfg.targets.len(),
        cfg.unrecognized.len()
    );
    println!("  (connect-scan CLI is being ported module-by-module; see nmap-rs/PLAN.md)");
}
