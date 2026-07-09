//! `nmap-cli` — thin entry point: parse args, call `nmap-core`, render. Keep logic
//! OUT of here (it belongs in `nmap-core`, where it is testable and unsafe-free).
//!
//! Milestone 1 builds this out into the real nmap CLI surface (target spec, `-p`,
//! `-sT`, output formats). Until the `cli` module lands at the end of the M1 loop
//! this is a minimal stub so the workspace builds while the `core` modules are
//! ported and gated one at a time.

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    nmap_core::trace!("nmap-rs started, {} args", args.len());

    if args.iter().any(|a| a == "--version") {
        println!("nmap-rs {}", env!("CARGO_PKG_VERSION"));
        return;
    }

    // The real scan pipeline (targets -> ports -> connect_scan -> output) is wired
    // here as each core module clears its gates.
    println!(
        "nmap-rs {}: Milestone 1 in progress",
        env!("CARGO_PKG_VERSION")
    );
    println!("  (connect-scan CLI is being ported module-by-module; see nmap-rs/PLAN.md)");
}
