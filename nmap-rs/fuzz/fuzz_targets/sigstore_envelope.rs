// cargo-fuzz target for the trusted-comment envelope grammar in
// `nmap_core::sigstore::verify`.
//
// WHY THIS EXISTS SEPARATELY. The `sigstore_verify` target feeds arbitrary bytes
// at `verify_manifest`, which is the right shape for the container parser — but it
// can never reach the envelope grammar, the version gate or the serial cross-check,
// because all three sit BEHIND two Ed25519 signature checks and a fuzzer cannot
// forge a signature. Left at that, the newest and most bespoke parser in the
// trusted path would ship with zero fuzz coverage while the fuzz job reported
// green.
//
// So this target is signer-in-the-loop: it holds a test SECRET key, mints genuine
// signatures over fuzzer-chosen manifest and trusted-comment bytes, and hands the
// result to `verify_manifest`. The signatures always verify, so every input lands
// in the envelope parser. That is a deliberate inversion of the usual posture —
// the crypto is satisfied so the parser can be attacked.
//
// The key here is a fuzzing fixture and nothing else. `nmap-core` contains no
// signing code at all; this dependency lives in the fuzz crate, which is outside
// the workspace and never ships.
//
// The contract enforced here:
//   * the envelope parser is TOTAL on arbitrary comment bytes — no panic, no
//     overflow, no unbounded allocation;
//   * an `Ok` result implies the envelope was understood AND agrees with the
//     manifest, so neither the version gate nor the serial cross-check can have
//     been skipped;
//   * the manifest bound is enforced before verification, not after.
#![no_main]

use ed25519_dalek::{Signer, SigningKey};
use libfuzzer_sys::fuzz_target;
use nmap_core::sigstore::manifest::MAX_MANIFEST_LEN;
use nmap_core::sigstore::verify::{
    verify_manifest, KeyRing, ENVELOPE_VERSION, MAX_TRUSTED_COMMENT_LEN,
};

/// Fixture seed. Not a secret and not used anywhere but here.
const SEED: [u8; 32] = [
    0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60, 0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
    0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19, 0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
];
const KEY_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];

fn b64(data: &[u8]) -> String {
    const ALPHABET: &[u8; 64] =
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for chunk in data.chunks(3) {
        let mut packed = 0u32;
        for (i, &b) in chunk.iter().enumerate() {
            packed |= u32::from(b) << (16 - 8 * i);
        }
        for i in 0..4 {
            if i <= chunk.len() {
                out.push(char::from(ALPHABET[((packed >> (18 - 6 * i)) & 0x3f) as usize]));
            } else {
                out.push('=');
            }
        }
    }
    out
}

fuzz_target!(|data: &[u8]| {
    // Split the input into a manifest and a trusted comment. Both are fuzzer
    // controlled; only the signatures over them are honest.
    if data.len() < 2 {
        return;
    }
    let (len_bytes, rest) = data.split_at(2);
    let split = usize::from(u16::from_be_bytes([len_bytes[0], len_bytes[1]])).min(rest.len());
    let (manifest_bytes, comment) = rest.split_at(split);

    let signing = SigningKey::from_bytes(&SEED);
    let verifying = signing.verifying_key();

    let mut pk_blob = Vec::with_capacity(42);
    pk_blob.extend_from_slice(b"Ed");
    pk_blob.extend_from_slice(&KEY_ID);
    pk_blob.extend_from_slice(verifying.to_bytes().as_slice());
    let ring = KeyRing::from_minisign_b64_lines([b64(&pk_blob)]).expect("fixture key parses");

    let signature = signing.sign(manifest_bytes);
    let mut sig_blob = Vec::with_capacity(74);
    sig_blob.extend_from_slice(b"Ed");
    sig_blob.extend_from_slice(&KEY_ID);
    sig_blob.extend_from_slice(&signature.to_bytes());

    let mut global_msg = Vec::with_capacity(64 + comment.len());
    global_msg.extend_from_slice(&signature.to_bytes());
    global_msg.extend_from_slice(comment);
    let global = signing.sign(&global_msg);

    let mut sig_file = Vec::new();
    sig_file.extend_from_slice(b"untrusted comment: fuzz\n");
    sig_file.extend_from_slice(b64(&sig_blob).as_bytes());
    sig_file.push(b'\n');
    sig_file.extend_from_slice(b"trusted comment: ");
    sig_file.extend_from_slice(comment);
    sig_file.push(b'\n');
    sig_file.extend_from_slice(b64(&global.to_bytes()).as_bytes());
    sig_file.push(b'\n');

    let first = verify_manifest(&ring, manifest_bytes, &sig_file);
    let second = verify_manifest(&ring, manifest_bytes, &sig_file);
    assert_eq!(
        first.is_ok(),
        second.is_ok(),
        "envelope verification is not deterministic"
    );

    let Ok(verified) = first else {
        // Every rejection path must be panic-free, which reaching here proves.
        return;
    };

    // The signatures were always going to pass, so an `Ok` here says the ENVELOPE
    // was accepted. Everything the rest of the system reads off it must hold.
    assert!(
        manifest_bytes.len() <= MAX_MANIFEST_LEN,
        "accepted a manifest over the size cap: {}",
        manifest_bytes.len()
    );
    assert!(
        comment.len() <= MAX_TRUSTED_COMMENT_LEN,
        "accepted a trusted comment over the cap: {}",
        comment.len()
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
    assert_eq!(verified.signing_key_id(), KEY_ID);
    // Only printable ASCII and tab may survive, on every line including this one.
    assert!(
        comment
            .iter()
            .all(|&b| b == b'\t' || (0x20..0x7f).contains(&b)),
        "accepted a non-ASCII trusted comment"
    );
});
