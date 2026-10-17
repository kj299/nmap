//! x509-parser 0.18 probe for E5.  Usage: x509parser_probe <tsv>...  -> TSV on stdout.
//! `X509Certificate::from_der(bytes)` is a nom parser returning (rest, cert); verdict and rest length
//! are recorded (it does not re-encode).  Panics are caught and recorded as "panic".
use std::io::{BufRead, BufReader, Write};
use std::panic::{self, AssertUnwindSafe};
use x509_parser::prelude::*;

fn hexdec(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    let out = std::io::stdout();
    let mut out = out.lock();
    writeln!(out, "id\tfamily\tlen\tverdict\terr\tconsumed\tremaining\tversion\tsig_alg_oid").unwrap();
    for path in std::env::args().skip(1) {
        let f = BufReader::new(std::fs::File::open(&path).expect("open"));
        for line in f.lines() {
            let line = line.unwrap();
            let mut it = line.splitn(3, '\t');
            let (id, note, hx) = match (it.next(), it.next(), it.next()) {
                (Some(a), Some(b), Some(c)) => (a, b, c),
                _ => continue,
            };
            let fam = note.split(' ').next().unwrap_or("");
            let b = hexdec(hx);
            let r = panic::catch_unwind(AssertUnwindSafe(|| {
                X509Certificate::from_der(&b)
                    .map(|(rem, c)| (rem.len(), c.version().0, c.signature_algorithm.algorithm.to_string()))
                    .map_err(|e| format!("{:?}", e))
            }));
            let row = match r {
                Ok(Ok((rem, ver, oid))) => format!("accept\t-\t{}\t{}\t{}\t{}", b.len() - rem, rem, ver, oid),
                Ok(Err(e)) => format!("reject\t{}\t-\t-\t-\t-", e.replace('\t', " ").replace('\n', " ")),
                Err(p) => format!(
                    "panic\t{}\t-\t-\t-\t-",
                    p.downcast_ref::<String>().cloned().or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string())).unwrap_or_default()
                ),
            };
            writeln!(out, "{}\t{}\t{}\t{}", id, fam, b.len(), row).unwrap();
        }
    }
}
