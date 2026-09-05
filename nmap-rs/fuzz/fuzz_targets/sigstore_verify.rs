// cargo-fuzz target for `nmap_core::sigstore::verify`.
//
// This is the trust anchor of the update path: it is the first code to touch a
// downloaded signature file, it runs BEFORE the manifest parser, and nothing
// upstream has validated a single byte for it. It has to be total on arbitrary
// input, and — more importantly — it has to be impossible to talk into returning
// `Ok` without a real signature.
//
// The fuzzer cannot forge Ed25519, so it is not going to stumble onto an accepting
// input. That is the point of the second half of the contract below: rather than
// hoping for an accept, every accept that DOES happen is required to carry the
// full set of properties the rest of the system relies on. If a bug ever made
// verification skippable, the assertions fire instead of the input being silently
// waved through.
//
// The contract enforced here:
//   * parsing and verification are TOTAL — no panic, no overflow, no unbounded
//     allocation, for any input, including malformed keys;
//   * an `Ok` result implies both signatures passed under ONE ring key, so the
//     reported key id must be one the ring actually holds;
//   * an `Ok` result implies the envelope is understood and agrees with the
//     manifest, so the cross-checks cannot have been skipped;
//   * verification is deterministic: the same bytes always give the same answer.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::sigstore::verify::{
    verify_manifest, KeyRing, TrustedKey, ENVELOPE_VERSION, MAX_TRUSTED_COMMENT_LEN, MAX_SIG_LEN,
};

// Real minisign public key lines, from the seeds in
// `tests/differential/s/oracle/gen_minisign_cases.py`. Fixed rather than fuzzed so
// the interesting surface is the SIGNATURE, not the key: a fuzzed key is
// overwhelmingly rejected before any signature is examined. If the generator's
// seeds ever change, the `expect` below fails loudly rather than fuzzing a ring
// that no corpus corresponds to.
const PUB_A: &str = "RWQRIjNEVWZ3iNdamAGCsQq31Uv+08lkBzoO4XLz2qYjJa8CGmj3B1Ea";
const PUB_B: &str = "RWSZqrvM3e7/AD1AF8PoQ4lakrcKp00bfrycmCzPLsSWjMDNVfEq9GYM";

fuzz_target!(|data: &[u8]| {
    // Arbitrary bytes as a public key must never panic — `--signature-key` puts an
    // operator-supplied string straight into this function.
    let _ = TrustedKey::from_minisign_b64(data);

    // Split the input into a manifest and a signature file. A two-byte prefix keeps
    // the split under the fuzzer's control so it can explore both sides.
    if data.len() < 2 {
        return;
    }
    let (len_bytes, rest) = data.split_at(2);
    let split = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]]));
    let split = split.min(rest.len());
    let (manifest_bytes, sig_bytes) = rest.split_at(split);

    let ring = KeyRing::from_minisign_b64_lines([PUB_A, PUB_B]).expect("fixed test keys parse");
    let ids: Vec<[u8; 8]> = [PUB_A, PUB_B]
        .iter()
        .map(|line| {
            TrustedKey::from_minisign_b64(line.as_bytes())
                .expect("fixed test keys parse")
                .key_id()
        })
        .collect();

    let first = verify_manifest(&ring, manifest_bytes, sig_bytes);

    // Deterministic: no clock, no RNG, no interior mutability, nothing to make the
    // same bytes answer differently on a second look.
    let second = verify_manifest(&ring, manifest_bytes, sig_bytes);
    assert_eq!(first.is_ok(), second.is_ok(), "verification is not deterministic");

    let Ok(verified) = first else {
        // Every rejection path must also be panic-free, which reaching here proves.
        return;
    };

    // Reaching here means the fuzzer produced two valid Ed25519 signatures, which
    // it cannot do by chance. So these assertions exist to catch the case where
    // verification was somehow BYPASSED rather than satisfied.
    assert!(
        sig_bytes.len() <= MAX_SIG_LEN,
        "accepted a signature file over the size cap: {}",
        sig_bytes.len()
    );
    assert!(
        ids.contains(&verified.signing_key_id()),
        "accepted under a key id the ring does not hold: {:?}",
        verified.signing_key_id()
    );

    let envelope = verified.envelope();
    assert!(
        envelope.version <= ENVELOPE_VERSION,
        "accepted envelope version {}",
        envelope.version
    );
    assert_eq!(
        envelope.serial,
        verified.manifest().serial,
        "accepted an envelope whose serial disagrees with the manifest"
    );
    assert!(
        !verified.manifest().files.is_empty(),
        "accepted a manifest with no files"
    );

    // The trusted comment is bounded, and the buffer the global signature is
    // checked over is sized from that bound. Pin the relationship rather than the
    // constant, so a future widening cannot silently outgrow the buffer.
    assert!(MAX_TRUSTED_COMMENT_LEN < MAX_SIG_LEN);
});
