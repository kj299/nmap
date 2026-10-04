//! Require each nselib library in a fresh NSE state and print the outcome, or
//! run each library's unit tests.
//!
//!     cargo run -p nmap-core --example nse_require -- [--unittest] DATADIR [LIB...]
//!
//! With no LIB, every `DATADIR/nselib/*.lua`. Prints `NAME<TAB>ok` or
//! `NAME<TAB>error<TAB>MESSAGE` (with `--unittest`, `pass` or `fail<TAB>...`),
//! as the oracle probes (`tests/differential/m6/oracle/m64_probe_*.nse`) do.
#[path = "../tests/nse_host/mod.rs"]
mod nse_host;

use std::path::PathBuf;

fn main() {
    let mut argv = std::env::args().skip(1).peekable();
    let unittest = argv.peek().is_some_and(|a| a == "--unittest");
    if unittest {
        argv.next();
    }
    let dir = PathBuf::from(
        argv.next()
            .expect("usage: nse_require [--unittest] DATADIR [LIB...]"),
    );
    let mut libs: Vec<String> = argv.collect();
    if libs.is_empty() {
        let mut names: Vec<String> = std::fs::read_dir(dir.join("nselib"))
            .expect("DATADIR/nselib")
            .filter_map(|e| {
                let n = e.ok()?.file_name().to_string_lossy().into_owned();
                n.strip_suffix(".lua").map(str::to_owned)
            })
            .collect();
        names.sort();
        libs = names;
    }
    for name in libs {
        let (status, detail) = nse_host::probe(&dir, &name, unittest);
        match detail {
            Some(d) => println!("{name}\t{status}\t{}", d.replace('\n', "\\n")),
            None => println!("{name}\t{status}"),
        }
    }
}
