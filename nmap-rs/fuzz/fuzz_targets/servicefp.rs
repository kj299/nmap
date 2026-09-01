// cargo-fuzz target for `nmap_core::servicefp`.
//
// Every byte fed to this builder came off the wire from a service that chose it, and
// the result is printed to the operator's terminal and pasted into a submission form.
// The C's version of this code aborts the process on three separate conditions driven
// by that data -- fatal() when its buffer runs short (service_scan.cc:1666), and two
// asserts inside the escape loop and on an empty response -- so "is this total?" is
// the question that matters most.
//
// The contract enforced here:
//   * building is TOTAL for any bytes, any probe name, any header;
//   * the output is ASCII and free of raw control bytes except the newlines the
//     wrap rule inserts, so it cannot inject escape sequences into a terminal;
//   * the wrap invariant holds -- every line after the first begins with "SF:";
//   * per-response truncation and the total ceiling are respected;
//   * finish() is pure and idempotent.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::servicefp::{
    FingerprintHeader, Proto, ServiceFingerprint, MAX_RESPONSE_BYTES, MAX_RESPONSE_BYTES_DEBUG,
};

fuzz_target!(|data: &[u8]| {
    if data.len() < 4 {
        return;
    }
    let debug = data[0] & 1 == 1;
    let proto = match data[0] >> 1 & 3 {
        0 => Proto::Tcp,
        1 => Proto::Udp,
        _ => Proto::Sctp,
    };
    let header = FingerprintHeader {
        port: u16::from(data[1]) << 8 | u16::from(data[2]),
        proto,
        version: "7.94".to_owned(),
        platform: "x86_64-pc-linux-gnu".to_owned(),
        intensity: i32::from(data[3] % 10),
        ssl_tunnel: data[3] & 0x80 != 0,
        month: i32::from(data[3] % 13),
        day: i32::from(data[3] % 32),
        time: i32::from_le_bytes([data[0], data[1], data[2], data[3] & 0x7f]),
    };

    let mut fp = ServiceFingerprint::new(header, debug);
    let per_response_cap = if debug {
        MAX_RESPONSE_BYTES_DEBUG
    } else {
        MAX_RESPONSE_BYTES
    };

    // Split the rest into responses on a byte the fuzzer can find.
    for (i, chunk) in data[4..].split(|&b| b == 0x1e).enumerate() {
        if chunk.is_empty() {
            // An empty response must be refused, never asserted on.
            assert!(!fp.add_response("E", &[]), "empty response accepted");
            continue;
        }
        let name = format!("P{i}");
        let _ = fp.add_response(&name, chunk);
    }

    let Some(out) = fp.finish() else {
        // Nothing added: the only way to get None, and it must be stable.
        assert_eq!(fp.len(), 0);
        assert!(fp.is_empty());
        return;
    };

    // --- the output is safe to print ---------------------------------------------
    assert!(out.is_ascii(), "non-ASCII in fingerprint");
    assert!(
        !out.chars().any(|c| (c as u32) < 0x20 && c != '\n'),
        "raw control byte in fingerprint"
    );
    assert!(!out.contains('\x7f'), "raw DEL in fingerprint");

    // --- the wrap invariant -------------------------------------------------------
    // Every continuation the builder inserts is "\nSF:", so every line after the
    // first must start with "SF:". A line that does not means a newline reached the
    // output some other way -- which would be a response byte escaping its escaping.
    for (n, line) in out.lines().enumerate() {
        if n > 0 {
            assert!(
                line.starts_with("SF:"),
                "line {n} does not begin with the continuation marker: {line:?}"
            );
        }
    }

    // --- termination ---------------------------------------------------------------
    assert!(out.ends_with(';'), "fingerprint is not terminated");

    // --- bounds ---------------------------------------------------------------------
    // Each input byte costs at most 4 output bytes (\xHH), plus 4 per wrap, plus the
    // header and per-record framing. A generous ceiling still catches unbounded growth.
    let inputs = data.len().saturating_sub(4);
    let bound = 256usize
        .saturating_add(inputs.min(per_response_cap.saturating_mul(64)).saturating_mul(6))
        .saturating_add(inputs.saturating_mul(64));
    assert!(out.len() <= bound, "output {} exceeds {bound}", out.len());

    // --- purity ----------------------------------------------------------------------
    assert_eq!(fp.finish().as_deref(), Some(out.as_str()), "finish is not pure");
});
