// cargo-fuzz target for `nmap_core::sigstore::digest`.
//
// This hash decides whether downloaded bytes may be written over a detection
// database, so "does it ever disagree with itself" is a security question, not a
// tidiness one. The 669-case differential against the system sha256sum covers
// correctness on a fixed corpus; this covers the buffering state machine on
// arbitrary chunkings, which is where the implementation actually had a bug (a
// buffer-length reset that made `finish` spin forever).
//
// Enforced: hashing is TOTAL, one-shot and streaming always agree however the input
// is split, and `finish` is idempotent.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::sigstore::digest::{to_hex, Sha256, DIGEST_LEN};

fuzz_target!(|data: &[u8]| {
    let one_shot = Sha256::digest(data);

    // Split on a byte the fuzzer can find, so it explores chunk boundaries rather
    // than spending its budget on framing.
    let mut streamed = Sha256::new();
    for chunk in data.split(|&b| b == 0x1e) {
        streamed.update(chunk);
    }
    // The split removed the separators, so this is a different message unless there
    // were none -- compare against a hash of the same reassembled bytes.
    let rejoined: Vec<u8> = data.iter().copied().filter(|b| *b != 0x1e).collect();
    assert_eq!(
        streamed.finish(),
        Sha256::digest(&rejoined),
        "streaming disagreed with one-shot"
    );

    // Byte-at-a-time is the worst case for the partial-block buffer.
    let mut byte_wise = Sha256::new();
    for b in data {
        byte_wise.update(&[*b]);
    }
    assert_eq!(byte_wise.finish(), one_shot, "byte-at-a-time disagreed");

    // Every prefix/suffix split must agree too, sampled so the target stays fast.
    for step in [1usize, 7, 64, 65] {
        if step <= data.len() {
            let mut h = Sha256::new();
            h.update(&data[..step]);
            h.update(&data[step..]);
            assert_eq!(h.finish(), one_shot, "split at {step} disagreed");
        }
    }

    // finish() does not consume or mutate.
    let mut h = Sha256::new();
    h.update(data);
    assert_eq!(h.finish(), h.finish(), "finish is not idempotent");

    let hex = to_hex(&one_shot);
    assert_eq!(hex.len(), DIGEST_LEN.saturating_mul(2));
    assert!(hex.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
});
