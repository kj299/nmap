//! Differential gate for `core::fpmodel` against nmap's real IPv6 model and liblinear.
//!
//! The port's central claim here is that **liblinear can be deleted**: nmap hands
//! classification to a bundled third-party C++ library, and this port replaces the only
//! prediction entry point it uses with a dot product. That claim is not something to
//! argue on paper — the oracle links liblinear's own `predict_values`, verbatim, against
//! nmap's own 2.8 MB model tables, and this test requires **bit-exact** agreement.
//!
//! Exactness matters more than usual. A floating-point port that is merely *close* would
//! pass a tolerance-based comparison while silently reordering a classification: the
//! accept rule downstream turns on whether one class is within 90% of the best, so an
//! error in the last few bits can change the reported OS. Both sides therefore exchange
//! values as `%a` hex floats and compare them as exact `f64` bit patterns.
//!
//! Feature vectors are generated from a seed by a PRNG implemented identically on both
//! sides, so a case is one integer rather than 695 numbers.
//!
//! Skipped when the oracle has not been built — run
//! `tests/differential/m5/oracle/build_fp6_oracle.sh` first. Also skipped under Miri
//! (spawns a process).
#![cfg(not(miri))]

use nmap_core::fpmodel::FpModel;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Command, Stdio};

fn oracle_path() -> PathBuf {
    PathBuf::from(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../tests/differential/m5/oracle/fp6_oracle"
    ))
}

/// xorshift64*, matching `next_feature` in the oracle exactly.
struct Rng(u64);

impl Rng {
    fn next_feature(&mut self) -> f64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        let x = self.0.wrapping_mul(2_685_821_657_736_338_717);
        let bucket = x >> 60;
        let frac = ((x >> 11) & ((1u64 << 40) - 1)) as f64 / (1u64 << 40) as f64;
        match bucket {
            0 => -1.0,
            1 => 0.0,
            2 => 1.0,
            3 => frac * 65535.0,
            4 => -frac * 1000.0,
            5 => frac * 1e6,
            _ => frac,
        }
    }
}

fn features_for(seed: u64, n: usize) -> Vec<f64> {
    let mut rng = Rng(if seed == 0 {
        0x9E37_79B9_7F4A_7C15
    } else {
        seed
    });
    (0..n).map(|_| rng.next_feature()).collect()
}

/// Parse a C `%a` hex float. Rust has no `from_str` for this format, so decode the
/// components directly rather than round-tripping through decimal, which would defeat the
/// whole point of comparing exactly.
fn parse_hex_float(s: &str) -> f64 {
    let (neg, s) = match s.strip_prefix('-') {
        Some(rest) => (true, rest),
        None => (false, s),
    };
    let s = s.strip_prefix("0x").unwrap_or(s);
    let (mantissa, exp) = match s.split_once(['p', 'P']) {
        Some((m, e)) => (m, e.parse::<i32>().expect("exponent")),
        None => (s, 0),
    };
    let (int_part, frac_part) = match mantissa.split_once('.') {
        Some((i, f)) => (i, f),
        None => (mantissa, ""),
    };
    let mut value = u64::from_str_radix(int_part, 16).expect("integer part") as f64;
    let mut scale = 1.0f64 / 16.0;
    for c in frac_part.chars() {
        value += f64::from(c.to_digit(16).expect("hex digit")) * scale;
        scale /= 16.0;
    }
    let out = value * 2f64.powi(exp);
    if neg {
        -out
    } else {
        out
    }
}

#[test]
fn hex_float_parser_round_trips() {
    // The comparison is only as trustworthy as this parser, so pin it first.
    for v in [
        0.0f64,
        1.0,
        -1.0,
        0.5,
        -0.0416667,
        1.0e6,
        f64::MIN_POSITIVE,
        std::f64::consts::PI,
        -1.234_567_890_123_456_7e-5,
    ] {
        let s = format!("{:x}", HexFloat(v));
        let parsed = parse_hex_float(&s);
        assert_eq!(
            parsed.to_bits(),
            v.to_bits(),
            "round trip failed for {v} ({s})"
        );
    }
}

/// Formats an `f64` the way C's `%a` does, for the round-trip test above.
struct HexFloat(f64);

impl std::fmt::LowerHex for HexFloat {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let v = self.0;
        if v == 0.0 {
            return write!(f, "0x0p+0");
        }
        let neg = v.is_sign_negative();
        // Normalise to [1, 2) and record the exponent. `f64::exponent`-style bit
        // twiddling would be terser, but this stays readable and is test-only.
        let mut m = v.abs();
        let mut exp = 0i32;
        while m >= 2.0 {
            m /= 2.0;
            exp = exp.saturating_add(1);
        }
        while m < 1.0 {
            m *= 2.0;
            exp = exp.saturating_sub(1);
        }
        let mut frac = String::new();
        let mut rem = m - 1.0;
        for _ in 0..13 {
            rem *= 16.0;
            // `rem` is in [0, 16) here, so the digit is one of 0..=15. Found by search
            // rather than cast, to keep the file free of float-to-int casts entirely.
            let floor = rem.floor();
            let d = (0u32..16).find(|&k| f64::from(k) == floor).unwrap_or(0);
            frac.push(char::from_digit(d, 16).unwrap_or('0'));
            rem -= f64::from(d);
        }
        write!(
            f,
            "{}0x1.{}p{}{}",
            if neg { "-" } else { "" },
            frac,
            if exp < 0 { "-" } else { "+" },
            exp.abs()
        )
    }
}

#[test]
fn matches_liblinear_bit_for_bit_over_the_real_model() {
    let oracle = oracle_path();
    if !oracle.is_file() {
        eprintln!(
            "SKIP: fp6 oracle not built ({}). Run tests/differential/m5/oracle/build_fp6_oracle.sh",
            oracle.display()
        );
        return;
    }
    let model = FpModel::load().expect("embedded model loads");

    // A spread of seeds; each expands to a full 695-feature vector on both sides.
    let seeds: Vec<u64> = (1..=120u64)
        .chain([0, u64::MAX, 1 << 32, 0x9E37_79B9_7F4A_7C15])
        .collect();
    let stdin_text: String = seeds
        .iter()
        .map(|s| format!("{s}\n"))
        .collect::<Vec<_>>()
        .join("");

    let mut child = Command::new(&oracle)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn oracle");
    child
        .stdin
        .as_mut()
        .expect("stdin")
        .write_all(stdin_text.as_bytes())
        .expect("write cases");
    let out = child.wait_with_output().expect("oracle output");
    assert!(out.status.success(), "oracle exited non-zero");
    let text = String::from_utf8(out.stdout).expect("oracle utf-8");

    let mut lines = text.lines();
    let header = lines.next().expect("model header");
    let mut it = header.split_whitespace();
    assert_eq!(it.next(), Some("model"));
    let n_class: usize = it.next().expect("nr_class").parse().expect("nr_class");
    let n_feature: usize = it.next().expect("nr_feature").parse().expect("nr_feature");
    assert_eq!(
        (n_class, n_feature),
        (model.n_class(), model.n_feature()),
        "the embedded blob and the C model disagree on shape"
    );

    let parse_row = |line: &str, tag: &str| -> Vec<f64> {
        let mut parts = line.split_whitespace();
        assert_eq!(
            parts.next(),
            Some(tag),
            "expected a {tag} line, got: {line}"
        );
        parts.map(parse_hex_float).collect()
    };

    let mut checked = 0usize;
    for &seed in &seeds {
        let c_scaled = parse_row(lines.next().expect("scaled line"), "scaled");
        let c_values = parse_row(lines.next().expect("values line"), "values");
        let c_novelty = parse_row(lines.next().expect("novelty line"), "novelty");
        assert_eq!(c_scaled.len(), n_feature);
        assert_eq!(c_values.len(), n_class);
        assert_eq!(c_novelty.len(), n_class);

        let mut features = features_for(seed, n_feature);
        model.apply_scale(&mut features);
        for (i, (&ours, &theirs)) in features.iter().zip(&c_scaled).enumerate() {
            assert_eq!(
                ours.to_bits(),
                theirs.to_bits(),
                "seed {seed}: scaled feature {i} differs ({ours} vs {theirs})"
            );
        }

        let values = model.predict_values(&features);
        for (c, (&ours, &theirs)) in values.iter().zip(&c_values).enumerate() {
            assert_eq!(
                ours.to_bits(),
                theirs.to_bits(),
                "seed {seed}: decision value for class {c} differs ({ours} vs {theirs})"
            );
        }

        for (label, &theirs) in c_novelty.iter().enumerate() {
            let ours = model.novelty_of(&features, label).expect("in-range label");
            assert_eq!(
                ours.to_bits(),
                theirs.to_bits(),
                "seed {seed}: novelty for class {label} differs"
            );
        }
        checked += 1;
    }
    assert_eq!(checked, seeds.len());
    eprintln!(
        "fp6 differential: {checked} vectors x ({n_feature} scaled + {n_class} values + {n_class} novelty) bit-exact"
    );
}
