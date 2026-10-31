// cargo-fuzz target for the TLS provider's M6.7 step-a primitives, on a
// peer's bytes: the key agreement of X448 and the five RFC 7919 FFDHE groups
// with any share (TLS 1.2's form and 1.3's), and the TLS 1.2 record
// decryption of AES-CCM, AES-CCM-8 and ARIA-GCM with any record. Checked:
// nothing panics; a share outside 1 < y < p - 1, of the wrong length or of
// low order is refused; a record shorter than nonce and tag is a decrypt
// error. The server-flight target reaches the same code through rustls; this
// one reaches it without a handshake in front.
//
// Input: a selector byte (bit 7: agreement or record; the rest picks the
// group and version, or the AEAD), then the share or the record.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_sys::tls::fuzzing::{agree, open_tls12};

fuzz_target!(|data: &[u8]| {
    let Some((&sel, rest)) = data.split_first() else {
        return;
    };
    if sel & 0x80 == 0 {
        let _ = agree(sel, rest);
    } else {
        let mut body = rest.to_vec();
        let _ = open_tls12(sel, &mut body);
    }
});
