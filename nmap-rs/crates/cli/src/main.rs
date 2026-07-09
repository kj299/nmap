//! `nmap-cli` — thin entry point: parse args, call `nmap-core`, render. Keep logic
//! OUT of here (it belongs in `nmap-core`, where it is testable and unsafe-free).
//!
//! This is the Milestone-0 placeholder shape (still the skeleton's key=value demo)
//! so the workspace builds and the differential/fuzz harnesses have a target. It is
//! replaced in Milestone 1 by the real nmap CLI surface (target spec, -p, -sT,
//! output formats).

use std::io::Read;

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    nmap_core::trace!("nmap-rs started, {} args", args.len());

    if args.iter().any(|a| a == "--help") {
        println!(
            "usage: nmap-rs [--format text|json] [--version]  (reads key=value lines on stdin)"
        );
        println!("  (Milestone-0 placeholder; the real nmap CLI lands in Milestone 1)");
        return;
    }
    if args.iter().any(|a| a == "--version") {
        println!("nmap-rs {}", env!("CARGO_PKG_VERSION"));
        return;
    }
    let json = matches!(args.iter().position(|a| a == "--format"), Some(i) if args.get(i.saturating_add(1)).map(String::as_str) == Some("json"));

    let mut input = String::new();
    let _ = std::io::stdin().read_to_string(&mut input);

    match nmap_core::parse(&input) {
        Ok(records) if json => {
            println!("[");
            for (i, r) in records.iter().enumerate() {
                let comma = if i.saturating_add(1) < records.len() {
                    ","
                } else {
                    ""
                };
                println!(
                    "  {{\"key\": {:?}, \"value\": {:?}}}{}",
                    r.key, r.value, comma
                );
            }
            println!("]");
        }
        Ok(records) => {
            for r in &records {
                println!("{}\t{}", r.key, r.value);
            }
        }
        Err(e) => {
            eprintln!("parse error: {e:?}");
            std::process::exit(1);
        }
    }
}
