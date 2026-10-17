//! x509-cert 0.3 probe for E5.  Usage: x509cert_probe <tsv>...  -> TSV on stdout.
//! Three variants per row: strict `Certificate::from_der` (rejects trailing bytes), tolerant DER
//! (`Certificate::decode` on a `SliceReader`, trailing bytes allowed), tolerant BER
//! (`SliceReader::new_with_encoding_rules(.., EncodingRules::Ber)`).  Accepted values are re-encoded
//! with `Encode::to_der`; "=input" means the re-encoding is byte-identical to the input.
use der::{Decode, Encode, EncodingRules, Reader, SliceReader};
use std::io::{BufRead, BufReader, Write};
use std::panic::{self, AssertUnwindSafe};
use x509_cert::Certificate;

fn hexdec(s: &str) -> Vec<u8> {
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or(0)).collect()
}
fn hexenc(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

enum Res {
    Acc { consumed: usize, reenc: Vec<u8> },
    Rej(String),
    Panic(String),
}

fn attempt<F: FnOnce() -> Result<(usize, Vec<u8>), String>>(f: F) -> Res {
    match panic::catch_unwind(AssertUnwindSafe(f)) {
        Ok(Ok((c, r))) => Res::Acc { consumed: c, reenc: r },
        Ok(Err(e)) => Res::Rej(e),
        Err(p) => Res::Panic(
            p.downcast_ref::<String>()
                .cloned()
                .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
                .unwrap_or_default(),
        ),
    }
}

fn cols(r: &Res, input: &[u8]) -> String {
    match r {
        Res::Acc { consumed, reenc } => format!(
            "accept\t-\t{}\t{}\t{}",
            consumed,
            input.len() - consumed,
            if reenc.as_slice() == input { "=input".to_string() } else { hexenc(reenc) }
        ),
        Res::Rej(e) => format!("reject\t{}\t-\t-\t-", e.replace('\t', " ").replace('\n', " ")),
        Res::Panic(e) => format!("panic\t{}\t-\t-\t-", e.replace('\t', " ").replace('\n', " ")),
    }
}

fn main() {
    panic::set_hook(Box::new(|_| {}));
    let out = std::io::stdout();
    let mut out = out.lock();
    writeln!(out, "id\tfamily\tlen\tstrict_verdict\tstrict_err\tstrict_consumed\tstrict_remaining\tstrict_reenc\ttol_verdict\ttol_err\ttol_consumed\ttol_remaining\ttol_reenc\tber_verdict\tber_err\tber_consumed\tber_remaining\tber_reenc").unwrap();
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
            let strict = attempt(|| {
                let c = Certificate::from_der(&b).map_err(|e| e.to_string())?;
                let r = c.to_der().map_err(|e| e.to_string())?;
                Ok((b.len(), r))
            });
            let tol = attempt(|| {
                let mut rd = SliceReader::new(&b).map_err(|e| e.to_string())?;
                let c = Certificate::decode(&mut rd).map_err(|e| e.to_string())?;
                let pos = u32::from(rd.position()) as usize;
                let r = c.to_der().map_err(|e| e.to_string())?;
                Ok((pos, r))
            });
            let ber = attempt(|| {
                let mut rd = SliceReader::new_with_encoding_rules(&b, EncodingRules::Ber).map_err(|e| e.to_string())?;
                let c = Certificate::decode(&mut rd).map_err(|e| e.to_string())?;
                let pos = u32::from(rd.position()) as usize;
                let r = c.to_der().map_err(|e| e.to_string())?;
                Ok((pos, r))
            });
            writeln!(out, "{}\t{}\t{}\t{}\t{}\t{}", id, fam, b.len(), cols(&strict, &b), cols(&tol, &b), cols(&ber, &b)).unwrap();
        }
    }
}
