//! Run a cases file through the port and print a golden file.
//!
//!     cargo run -p nmap-core --example m6_eval -- CASES.txt > piccolo.txt
//!     ./oracle/lua oracle/m6_pattern_driver.lua CASES.txt > lua.txt
//!     diff lua.txt piccolo.txt
//!
//! The output has the format `oracle/m6_pattern_driver.lua` writes, row for
//! row, so the two diff cleanly. This is how a candidate case is checked
//! against nmap's own Lua before it is added to a corpus.
//!
//! `M6_MEMORY_LIMIT=BYTES` runs every case under that memory budget.
#[path = "../tests/m6_eval/mod.rs"]
mod m6_eval;

use m6_eval::{eval_limited, quietly, rows, unhex};
use std::path::PathBuf;

fn main() {
    let path: PathBuf = std::env::args_os()
        .nth(1)
        .expect("usage: m6_eval CASES.txt")
        .into();
    let limit = std::env::var("M6_MEMORY_LIMIT")
        .ok()
        .map(|v| v.parse().expect("M6_MEMORY_LIMIT is a byte count"));
    println!("# name\toracle_status\toracle_value");
    quietly(|| {
        for (name, chunk_hex, _) in rows(&path) {
            let (status, value) = eval_limited(&unhex(&chunk_hex), limit);
            println!("{name}\t{status}\t{value}");
        }
    });
}
