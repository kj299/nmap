// cargo-fuzz target for `nmap_core::ipid`. Classifying an attacker-influenced run of
// IP-ID samples must be total: never panic (no unsigned underflow in the localhost
// adjustment or the diff computation), for any samples and either bit width.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::ipid::{get_ipid_sequence_16, get_ipid_sequence_32};

fuzz_target!(|data: &[u8]| {
    // Carve u32 samples out of the input (up to 31, matching nmap's buffer bound).
    let islocal = data.first().is_some_and(|b| b & 1 == 0);
    let ipids: Vec<u32> = data
        .get(1..)
        .unwrap_or(&[])
        .chunks(4)
        .take(31)
        .map(|c| {
            let mut b = [0u8; 4];
            b[..c.len()].copy_from_slice(c);
            u32::from_le_bytes(b)
        })
        .collect();
    let _ = get_ipid_sequence_16(&ipids, islocal);
    let _ = get_ipid_sequence_32(&ipids, islocal);
});
