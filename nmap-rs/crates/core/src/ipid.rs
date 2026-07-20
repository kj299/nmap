//! IP-ID sequence classification. Ports nmap's `get_ipid_sequence_16` /
//! `get_ipid_sequence_32` / `get_diffs` / `identify_sequence` (`osscan2.cc`).
//!
//! Given a run of IP identification fields observed from one host, classify how that
//! host generates them (constant, all-zero, incremental, incremental-by-two,
//! byte-swapped "broken" incremental, random-positive-increment, or fully random).
//! This feeds two consumers: the **idle scan** (`-sI`, which needs a predictable
//! incremental zombie) and **OS detection** (the `TI`/`CI`/`II`/`SS` fingerprint
//! tests). A pure function over the samples — no I/O, no globals.
//!
//! ## Fidelity note
//!
//! The C's 16-bit path computes the diffs as full 32-bit wrapping subtractions and
//! flags a diff `> 20000` as *random* **before** masking to 16 bits — so a single
//! 16-bit counter wrap mid-run is classified `Rd`. That is a heuristic imperfection,
//! not a memory-safety issue, so this port **reproduces it faithfully** (the
//! differential requires bit-exact agreement with nmap; "fixing" it would silently
//! change OS-detection output). Documented, not diverged.

/// How a host generates its IP identification field, as classified from a run of
/// observed IP-IDs. Values mirror nmap's `IPID_SEQ_*` (`osscan2.h`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpidSequence {
    /// Could not be determined (too few samples, or no rule matched).
    Unknown,
    /// Increments by one each packet.
    Incr,
    /// "Broken" incremental — increments but the counter was not byte-swapped
    /// (`htons` forgotten), so diffs are multiples of 256.
    BrokenIncr,
    /// Random positive increments (goes up, but by large varying amounts).
    Rpi,
    /// Random distribution (can go up or down).
    Rd,
    /// One or more sequential duplicates — effectively constant.
    Constant,
    /// Every observed IP-ID is zero.
    Zero,
    /// Increments by two each packet.
    IncrBy2,
}

/// Random-distribution threshold: a raw diff larger than this (with >2 samples) is
/// treated as random. From `get_diffs`.
const RD_THRESHOLD: u32 = 20000;

enum Diffs {
    /// `get_diffs` reached a verdict on its own (too few samples, all-zero, random).
    Verdict(IpidSequence),
    /// The consecutive differences, to be classified by `identify_sequence`.
    Values(Vec<u32>),
}

/// Compute consecutive IP-ID differences, short-circuiting the all-zero and random
/// verdicts. Ports `get_diffs` (`osscan2.cc`).
fn get_diffs(ipids: &[u32]) -> Diffs {
    if ipids.len() < 2 {
        return Diffs::Verdict(IpidSequence::Unknown);
    }
    let mut diffs = Vec::with_capacity(ipids.len().saturating_sub(1));
    let mut all_zero = true;
    for pair in ipids.windows(2) {
        let prev = pair[0];
        let cur = pair[1];
        if prev != 0 || cur != 0 {
            all_zero = false;
        }
        let d = cur.wrapping_sub(prev);
        diffs.push(d);
        // Random: a large raw jump (only meaningful with more than two samples).
        if ipids.len() > 2 && d > RD_THRESHOLD {
            return Diffs::Verdict(IpidSequence::Rd);
        }
    }
    if all_zero {
        Diffs::Verdict(IpidSequence::Zero)
    } else {
        Diffs::Values(diffs)
    }
}

/// Classify the sequence from its differences. Ports `identify_sequence`
/// (`osscan2.cc`). `islocalhost` applies the localhost RST-IPID adjustment.
fn identify_sequence(diffs: &mut [u32], islocalhost: bool) -> IpidSequence {
    // Localhost: the RST we send back also burns an IP-ID, so subtract it out — but
    // only if every diff already exceeds one (else the adjustment would underflow the
    // sequence's meaning). "Stupid MS" byte-swapped counters step by 256.
    if islocalhost && diffs.iter().all(|&d| d >= 2) {
        for d in diffs.iter_mut() {
            if *d % 256 == 0 {
                *d = d.wrapping_sub(256);
            } else {
                *d = d.wrapping_sub(1);
            }
        }
    }

    // Constant: every difference is zero.
    if diffs.iter().all(|&d| d == 0) {
        return IpidSequence::Constant;
    }

    // Random positive increments: a big jump that isn't a clean multiple of 256
    // (or is, but is very large).
    for &d in diffs.iter() {
        if d > 1000 && (d % 256 != 0 || d >= 25600) {
            return IpidSequence::Rpi;
        }
    }

    // Three simultaneous predicates over all diffs.
    let mut all_small = true; // all <= 9
    let mut all_256_step = true; // all multiples of 256 and <= 5120
    let mut all_even = true; // all multiples of 2
    for &d in diffs.iter() {
        if all_256_step && (d > 5120 || d % 256 != 0) {
            all_256_step = false;
        }
        if all_even && d % 2 != 0 {
            all_even = false;
        }
        if all_small && d > 9 {
            all_small = false;
        }
    }

    if all_256_step {
        IpidSequence::BrokenIncr
    } else if all_even {
        IpidSequence::IncrBy2
    } else if all_small {
        IpidSequence::Incr
    } else {
        IpidSequence::Unknown
    }
}

/// Classify a 16-bit IP-ID sequence. Ports `get_ipid_sequence_16`: diffs are masked to
/// 16 bits before classification (so a wrapped 16-bit counter stays continuous),
/// *except* that `get_diffs`'s own random verdict is computed on the raw 32-bit diff.
#[must_use]
pub fn get_ipid_sequence_16(ipids: &[u32], islocalhost: bool) -> IpidSequence {
    match get_diffs(ipids) {
        Diffs::Verdict(v) => v,
        Diffs::Values(mut diffs) => {
            for d in diffs.iter_mut() {
                *d &= 0xffff;
            }
            identify_sequence(&mut diffs, islocalhost)
        }
    }
}

/// Classify a 32-bit IP-ID sequence. Ports `get_ipid_sequence_32` (no 16-bit masking).
#[must_use]
pub fn get_ipid_sequence_32(ipids: &[u32], islocalhost: bool) -> IpidSequence {
    match get_diffs(ipids) {
        Diffs::Verdict(v) => v,
        Diffs::Values(mut diffs) => identify_sequence(&mut diffs, islocalhost),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn too_few_samples_unknown() {
        assert_eq!(get_ipid_sequence_16(&[], false), IpidSequence::Unknown);
        assert_eq!(get_ipid_sequence_16(&[42], false), IpidSequence::Unknown);
    }

    #[test]
    fn all_zero_is_zero() {
        assert_eq!(
            get_ipid_sequence_16(&[0, 0, 0, 0], false),
            IpidSequence::Zero
        );
    }

    #[test]
    fn constant_duplicates() {
        assert_eq!(
            get_ipid_sequence_16(&[5000, 5000, 5000], false),
            IpidSequence::Constant
        );
    }

    #[test]
    fn simple_incremental() {
        assert_eq!(
            get_ipid_sequence_16(&[100, 101, 102, 103], false),
            IpidSequence::Incr
        );
    }

    #[test]
    fn incremental_by_two() {
        assert_eq!(
            get_ipid_sequence_16(&[100, 102, 104, 106], false),
            IpidSequence::IncrBy2
        );
    }

    #[test]
    fn broken_incr_byte_swapped() {
        // Diffs are multiples of 256 within 5120 => broken incremental (forgot htons).
        assert_eq!(
            get_ipid_sequence_16(&[0x0100, 0x0200, 0x0300, 0x0400], false),
            IpidSequence::BrokenIncr
        );
    }

    #[test]
    fn random_positive_increment() {
        // Large, non-256-aligned positive jumps.
        assert_eq!(
            get_ipid_sequence_16(&[1000, 3500, 8001, 15003], false),
            IpidSequence::Rpi
        );
    }

    #[test]
    fn random_distribution_big_jump() {
        // A raw diff > 20000 with >2 samples => random.
        assert_eq!(
            get_ipid_sequence_32(&[10, 40000, 5], false),
            IpidSequence::Rd
        );
    }

    #[test]
    fn sixteen_bit_wrap_is_random_like_c() {
        // 65000 -> 100 wraps; the raw 32-bit diff is huge, so get_diffs returns Rd
        // BEFORE the 16-bit mask — faithfully reproducing the C quirk.
        assert_eq!(
            get_ipid_sequence_16(&[64000, 65000, 100], false),
            IpidSequence::Rd
        );
    }

    #[test]
    fn localhost_adjustment_recovers_incremental() {
        // On localhost each observed diff is inflated by one (our RST's own IP-ID);
        // with all diffs >= 2 the adjustment subtracts it back to a clean increment.
        assert_eq!(
            get_ipid_sequence_16(&[100, 102, 104, 106], true),
            IpidSequence::Incr
        );
    }

    #[test]
    fn total_on_arbitrary_input_never_panics() {
        let samples = [
            0u32,
            u32::MAX,
            1,
            0x8000_0000,
            0xffff,
            256,
            25600,
            5120,
            20001,
        ];
        for a in samples {
            for b in samples {
                for c in samples {
                    let _ = get_ipid_sequence_16(&[a, b, c], false);
                    let _ = get_ipid_sequence_32(&[a, b, c], true);
                }
            }
        }
    }
}
