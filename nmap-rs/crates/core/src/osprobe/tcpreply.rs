//! Attribute extraction from a TCP probe reply — ports `processT1_7Resp`,
//! `processTEcnResp`, `processTOpsResp` and `processTWinResp` from `osscan2.cc`.
//!
//! Each reply to one of the TCP probes becomes one fingerprint test (`T1`–`T7` or
//! `ECN`), built from the fields where stacks disagree: whether Don't-Fragment was
//! reflected, the TTL, the advertised window, how the sequence and acknowledgement
//! numbers relate to what we sent, which flags came back, the option summary, a CRC of
//! any RST payload, and a "quirks" string for two specific protocol violations.
//!
//! The sequence and acknowledgement numbers are recorded **relative to the probe**
//! (`Z`ero, `A`/`S`ame-as-what-we-sent, `A+`/`S+` for one more, `O`ther) rather than as
//! raw values, because the absolute numbers are per-scan noise while the relationship is
//! the stack's behaviour.

use crate::osdb::model::{FingerTest, TestId};
use crate::osprobe::analyze::tcp_option_string;

/// TCP flags, in the order the `F` attribute lists them. Order is fixed by the C and is
/// part of the wire contract with the database, not an implementation detail.
const FLAG_ORDER: [(u8, char); 7] = [
    (0x40, 'E'), // ECN echo
    (0x20, 'U'), // urgent
    (0x10, 'A'), // acknowledgement
    (0x08, 'P'), // push
    (0x04, 'R'), // reset
    (0x02, 'S'), // synchronise
    (0x01, 'F'), // final
];

const TH_URG: u8 = 0x20;
const TH_RST: u8 = 0x04;
const TH_ECE: u8 = 0x40;
const TH_CWR: u8 = 0x80;

/// What we sent, needed to describe the reply's sequence and acknowledgement numbers
/// relative to the probe.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeContext {
    /// The sequence number our probe carried.
    pub sent_seq: u32,
    /// The acknowledgement number our probe carried.
    pub sent_ack: u32,
}

/// The fields of a received TCP reply this analysis needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TcpReply {
    /// Don't-Fragment set on the reply's IP header.
    pub df: bool,
    /// The reply's IP TTL.
    pub ttl: u8,
    /// Advertised window.
    pub window: u16,
    /// Sequence number.
    pub seq: u32,
    /// Acknowledgement number.
    pub ack: u32,
    /// TCP flags byte.
    pub flags: u8,
    /// The 4-bit reserved field. Non-zero is a protocol violation and a strong signal.
    pub reserved: u8,
    /// Urgent pointer.
    pub urgent_ptr: u16,
    /// The whole TCP segment as received — header, options and any payload.
    pub segment: Vec<u8>,
}

impl TcpReply {
    /// The segment's payload, after the header and options.
    fn payload(&self) -> &[u8] {
        let off = self
            .segment
            .get(12)
            .map_or(0usize, |b| usize::from(b >> 4).saturating_mul(4));
        self.segment.get(off..).unwrap_or_default()
    }
}

/// Uppercase hex without leading zeros, matching the C's `cp_hex`.
fn hex(v: u32) -> String {
    format!("{v:X}")
}

/// Set `attr` on `test`, ignoring an attribute the test does not define.
fn set(test: &mut FingerTest, attr: &str, value: String) {
    if let Some(i) = test.id.attr_index(attr) {
        if let Some(slot) = test.values.get_mut(i) {
            *slot = Some(value);
        }
    }
}

/// The `F` attribute: which flags came back, in the C's fixed order.
fn flags_string(flags: u8) -> String {
    FLAG_ORDER
        .iter()
        .filter(|(bit, _)| flags & bit != 0)
        .map(|(_, c)| *c)
        .collect()
}

/// The `Q` attribute: two specific protocol violations, in order.
///
/// `R` — the TCP reserved field is not zero. `U` — a non-zero urgent pointer with the
/// URG flag clear, so the pointer means nothing yet was still populated. Both are
/// behaviour a conforming stack would not produce, which is exactly why they identify one.
fn quirks_string(reserved: u8, flags: u8, urgent_ptr: u16) -> String {
    let mut q = String::new();
    if reserved != 0 {
        q.push('R');
    }
    if flags & TH_URG == 0 && urgent_ptr != 0 {
        q.push('U');
    }
    q
}

/// The `S` attribute: the reply's sequence number relative to the acknowledgement we sent.
fn seq_relation(seq: u32, ctx: &ProbeContext) -> &'static str {
    if seq == 0 {
        "Z"
    } else if seq == ctx.sent_ack {
        "A"
    } else if seq == ctx.sent_ack.wrapping_add(1) {
        "A+"
    } else {
        "O"
    }
}

/// The `A` attribute: the reply's acknowledgement number relative to the sequence we sent.
fn ack_relation(ack: u32, ctx: &ProbeContext) -> &'static str {
    if ack == 0 {
        "Z"
    } else if ack == ctx.sent_seq {
        "S"
    } else if ack == ctx.sent_seq.wrapping_add(1) {
        "S+"
    } else {
        "O"
    }
}

/// The `O` attribute. An unparseable option block records an empty value rather than
/// omitting the attribute, which is what the C's `setAVal("O", "")` does — "we looked and
/// found nothing usable" is different from "we never looked".
fn option_attr(segment: &[u8]) -> String {
    tcp_option_string(segment).unwrap_or_default()
}

/// The `RD` attribute: a CRC-32 of a RST packet's payload.
///
/// Most stacks send an empty RST; the ones that attach an explanatory string are
/// identifying themselves. Non-RST replies, and RSTs with no payload, record `0`.
fn rst_data_crc(reply: &TcpReply) -> String {
    let payload = reply.payload();
    if reply.flags & TH_RST != 0 && !payload.is_empty() {
        hex(crc32(payload))
    } else {
        "0".to_owned()
    }
}

/// IEEE CRC-32 (polynomial `0xEDB88320`, pre- and post-inverted) — the same function as
/// nbase's `nbase_crc32`, computed directly rather than pulling in a dependency for
/// thirty lines of table-free arithmetic.
fn crc32(data: &[u8]) -> u32 {
    let mut crc = 0xFFFF_FFFFu32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            let mask = 0u32.wrapping_sub(crc & 1);
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    !crc
}

/// Guess the initial TTL a packet was sent with, given the TTL we observed.
///
/// Ports `get_initial_ttl_guess`. Stacks start at one of a handful of round values, so
/// rounding up to the next one recovers the initial TTL when the true hop count is
/// unknown. The C's comment notes this assumes the target is fewer than 32 hops away,
/// and that a stack starting at 60 is reported as 64 because the two cannot be told
/// apart from a hop count alone.
#[must_use]
pub fn initial_ttl_guess(ttl: u8) -> u16 {
    if ttl <= 32 {
        32
    } else if ttl <= 64 {
        64
    } else if ttl <= 128 {
        128
    } else {
        255
    }
}

/// Resolve a test's `T`/`TG` pair once the hop distance is known — the post-pass in the
/// C's `makeFP`.
///
/// Per-reply extraction records the **observed** TTL in `T`, which is not what the
/// database stores. This turns it into the initial TTL, exactly one of two ways:
///
/// * **distance known** (the `U1` probe's ICMP quote gave a true hop count) — `T` becomes
///   `observed + distance - 1`, the reconstructed initial TTL, and `TG` stays unset.
/// * **distance unknown** — `TG` gets the rounded guess and `T` is **removed**, because
///   an observed TTL that has not been corrected for distance would match the wrong
///   entries.
///
/// The two are mutually exclusive by construction; a test carrying both would be scored
/// twice for one piece of evidence.
pub fn finalize_ttl(test: &mut FingerTest, distance: Option<u8>) {
    let Some(observed) = test.get("T").and_then(|v| u32::from_str_radix(v, 16).ok()) else {
        return;
    };

    match distance {
        Some(d) => {
            // `distance - 1` is the number of hops between us and the target. A distance
            // of 0 would underflow in the C; saturating keeps the value sane.
            let hops = u32::from(d).saturating_sub(1);
            set(test, "T", hex(observed.saturating_add(hops)));
        }
        None => {
            let guess = initial_ttl_guess(u8::try_from(observed).unwrap_or(u8::MAX));
            set(test, "TG", hex(u32::from(guess)));
            if let Some(i) = test.id.attr_index("T") {
                if let Some(slot) = test.values.get_mut(i) {
                    *slot = None;
                }
            }
        }
    }
}

/// Build the `T1`–`T7` test for a reply. `n` is 1..=7.
///
/// `T1` omits the window and options attributes: it shares its reply with the `SEQ`
/// probes, whose window and options are recorded by the `WIN` and `OPS` tests instead.
#[must_use]
pub fn t_test(n: u8, reply: &TcpReply, ctx: &ProbeContext) -> Option<FingerTest> {
    let id = match n {
        1 => TestId::T1,
        2 => TestId::T2,
        3 => TestId::T3,
        4 => TestId::T4,
        5 => TestId::T5,
        6 => TestId::T6,
        7 => TestId::T7,
        _ => return None,
    };
    let mut test = FingerTest::new(id);

    // `R=Y` first: it records that a packet came back at all, so this test can never
    // match a database entry that expects silence.
    set(&mut test, "R", "Y".to_owned());
    set(&mut test, "DF", if reply.df { "Y" } else { "N" }.to_owned());
    set(&mut test, "T", hex(u32::from(reply.ttl)));
    if n != 1 {
        set(&mut test, "W", hex(u32::from(reply.window)));
    }
    set(&mut test, "S", seq_relation(reply.seq, ctx).to_owned());
    set(&mut test, "A", ack_relation(reply.ack, ctx).to_owned());
    set(&mut test, "F", flags_string(reply.flags));
    if n != 1 {
        set(&mut test, "O", option_attr(&reply.segment));
    }
    set(&mut test, "RD", rst_data_crc(reply));
    set(
        &mut test,
        "Q",
        quirks_string(reply.reserved, reply.flags, reply.urgent_ptr),
    );
    Some(test)
}

/// Build the `ECN` test for a reply.
#[must_use]
pub fn ecn_test(reply: &TcpReply) -> FingerTest {
    let mut test = FingerTest::new(TestId::Ecn);
    set(&mut test, "R", "Y".to_owned());
    set(&mut test, "DF", if reply.df { "Y" } else { "N" }.to_owned());
    set(&mut test, "T", hex(u32::from(reply.ttl)));
    set(&mut test, "W", hex(u32::from(reply.window)));
    set(&mut test, "O", option_attr(&reply.segment));

    // How the target answered our congestion-notification flags. `S` means it echoed
    // both back, which is what a stack that misunderstands the handshake does; `Y` is
    // correct support; `N` is no support; `O` is anything else.
    let ece = reply.flags & TH_ECE != 0;
    let cwr = reply.flags & TH_CWR != 0;
    let cc = match (ece, cwr) {
        (true, true) => "S",
        (true, false) => "Y",
        (false, false) => "N",
        (false, true) => "O",
    };
    set(&mut test, "CC", cc.to_owned());
    set(
        &mut test,
        "Q",
        quirks_string(reply.reserved, reply.flags, reply.urgent_ptr),
    );
    test
}

/// Build the `WIN` test from the six `SEQ`/`OPS` replies' advertised windows.
///
/// The C only emits this test when **all six** arrived: a partial `WIN` would be scored
/// against complete database entries as though the missing slots were deliberate.
#[must_use]
pub fn win_test(windows: &[Option<u16>]) -> Option<FingerTest> {
    if windows.len() < 6 || windows.iter().take(6).any(Option::is_none) {
        return None;
    }
    let mut test = FingerTest::new(TestId::Win);
    for (i, w) in windows.iter().take(6).enumerate() {
        let Some(w) = w else { continue };
        if let Some(slot) = test.values.get_mut(i) {
            *slot = Some(hex(u32::from(*w)));
        }
    }
    Some(test)
}

/// Build the `OPS` test from the six `SEQ`/`OPS` replies' option summaries.
///
/// As with [`win_test`], all six must be present.
#[must_use]
pub fn ops_test(segments: &[Option<Vec<u8>>]) -> Option<FingerTest> {
    if segments.len() < 6 || segments.iter().take(6).any(Option::is_none) {
        return None;
    }
    let mut test = FingerTest::new(TestId::Ops);
    for (i, seg) in segments.iter().take(6).enumerate() {
        let Some(seg) = seg else { continue };
        if let Some(slot) = test.values.get_mut(i) {
            *slot = Some(option_attr(seg));
        }
    }
    Some(test)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> ProbeContext {
        ProbeContext {
            sent_seq: 0x1000_0000,
            sent_ack: 0xAAAA_BBBB,
        }
    }

    /// A TCP segment with the given flags, options and payload.
    fn segment(flags: u8, options: &[u8], payload: &[u8]) -> Vec<u8> {
        let words = 20usize.saturating_add(options.len()).div_ceil(4);
        let mut s = vec![0u8; 20];
        s[12] = u8::try_from(words << 4).unwrap_or(0x50);
        s[13] = flags;
        s.extend_from_slice(options);
        s.extend_from_slice(payload);
        s
    }

    fn reply(flags: u8) -> TcpReply {
        TcpReply {
            df: true,
            ttl: 64,
            window: 8192,
            seq: 0xAAAA_BBBB,
            ack: 0x1000_0001,
            flags,
            reserved: 0,
            urgent_ptr: 0,
            segment: segment(flags, &[], &[]),
        }
    }

    #[test]
    fn a_reply_always_records_that_it_responded() {
        // Without R=Y the test could match a database entry expecting no reply at all.
        for n in 1..=7u8 {
            let t = t_test(n, &reply(0x12), &ctx()).expect("T{n}");
            assert_eq!(t.get("R"), Some("Y"), "T{n}");
        }
        assert_eq!(ecn_test(&reply(0x12)).get("R"), Some("Y"));
    }

    #[test]
    fn sequence_and_ack_are_recorded_relative_to_what_we_sent() {
        let c = ctx();
        let mut r = reply(0x10);

        r.seq = 0;
        assert_eq!(t_test(2, &r, &c).unwrap().get("S"), Some("Z"));
        r.seq = c.sent_ack;
        assert_eq!(t_test(2, &r, &c).unwrap().get("S"), Some("A"));
        r.seq = c.sent_ack.wrapping_add(1);
        assert_eq!(t_test(2, &r, &c).unwrap().get("S"), Some("A+"));
        r.seq = 12345;
        assert_eq!(t_test(2, &r, &c).unwrap().get("S"), Some("O"));

        r.ack = 0;
        assert_eq!(t_test(2, &r, &c).unwrap().get("A"), Some("Z"));
        r.ack = c.sent_seq;
        assert_eq!(t_test(2, &r, &c).unwrap().get("A"), Some("S"));
        r.ack = c.sent_seq.wrapping_add(1);
        assert_eq!(t_test(2, &r, &c).unwrap().get("A"), Some("S+"));
        r.ack = 999;
        assert_eq!(t_test(2, &r, &c).unwrap().get("A"), Some("O"));
    }

    #[test]
    fn the_relative_comparison_wraps_with_the_counter() {
        let c = ProbeContext {
            sent_seq: u32::MAX,
            sent_ack: u32::MAX,
        };
        let mut r = reply(0x10);
        r.seq = 0;
        r.ack = 0;
        // Zero is checked first, so a wrapped "+1" still reads as Z — matching the C's
        // ordering, where the zero test precedes the arithmetic ones.
        assert_eq!(t_test(2, &r, &c).unwrap().get("S"), Some("Z"));
        r.seq = 1;
        assert_eq!(t_test(2, &r, &c).unwrap().get("S"), Some("O"));
    }

    #[test]
    fn flags_are_listed_in_the_c_order_not_bit_order() {
        // All seven set: the order is fixed by the database, so a different order would
        // never match anything.
        assert_eq!(flags_string(0x7F), "EUAPRSF", "every flag but CWR");
        assert_eq!(flags_string(0x12), "AS", "SYN+ACK");
        assert_eq!(flags_string(0x14), "AR", "RST+ACK");
        assert_eq!(flags_string(0x00), "");
        // The CWR bit has no letter, so it must not appear.
        assert_eq!(flags_string(0x80), "");
    }

    #[test]
    fn quirks_catch_the_two_protocol_violations() {
        assert_eq!(quirks_string(0, 0, 0), "");
        assert_eq!(quirks_string(1, 0, 0), "R", "reserved field set");
        assert_eq!(quirks_string(0, 0, 99), "U", "urgent pointer without URG");
        assert_eq!(
            quirks_string(0, TH_URG, 99),
            "",
            "an urgent pointer with URG set is legal"
        );
        assert_eq!(quirks_string(8, 0, 1), "RU", "both, in order");
    }

    #[test]
    fn t1_omits_the_window_and_options_which_other_tests_carry() {
        let r = reply(0x12);
        let t1 = t_test(1, &r, &ctx()).unwrap();
        assert_eq!(t1.get("W"), None, "T1's window belongs to the WIN test");
        assert_eq!(t1.get("O"), None, "T1's options belong to the OPS test");
        // Every other T test records both.
        for n in 2..=7u8 {
            let t = t_test(n, &r, &ctx()).unwrap();
            assert_eq!(t.get("W"), Some("2000"), "T{n} window");
            assert_eq!(t.get("O"), Some(""), "T{n} options");
        }
    }

    #[test]
    fn an_unparseable_option_block_records_an_empty_value_not_an_absent_one() {
        // "We looked and found nothing usable" differs from "we never looked": the
        // scorer skips an absent attribute but matches an empty one against `O=`.
        let mut r = reply(0x12);
        r.segment = segment(0x12, &[2, 1, 0, 0], &[]); // option length below the minimum
        let t = t_test(2, &r, &ctx()).unwrap();
        assert_eq!(t.get("O"), Some(""));
    }

    #[test]
    fn options_are_summarised_the_same_way_the_ops_test_does() {
        let mut r = reply(0x12);
        r.segment = segment(0x12, &[2, 4, 0x05, 0xb4, 4, 2], &[]);
        assert_eq!(t_test(2, &r, &ctx()).unwrap().get("O"), Some("M5B4S"));
        assert_eq!(ecn_test(&r).get("O"), Some("M5B4S"));
    }

    #[test]
    fn rst_payloads_are_fingerprinted_by_crc() {
        let mut r = reply(TH_RST);
        // No payload: the C records 0 rather than the CRC of nothing.
        assert_eq!(t_test(5, &r, &ctx()).unwrap().get("RD"), Some("0"));

        r.segment = segment(TH_RST, &[], b"No flow control");
        let with_data = t_test(5, &r, &ctx()).unwrap();
        assert_ne!(with_data.get("RD"), Some("0"));

        // A payload on a non-RST reply is not fingerprinted.
        let mut not_rst = reply(0x10);
        not_rst.segment = segment(0x10, &[], b"No flow control");
        assert_eq!(t_test(5, &not_rst, &ctx()).unwrap().get("RD"), Some("0"));
    }

    #[test]
    fn crc32_matches_the_standard_vectors() {
        // IEEE CRC-32, the same function as nbase_crc32.
        assert_eq!(crc32(b""), 0);
        assert_eq!(crc32(b"a"), 0xE8B7_BE43);
        assert_eq!(crc32(b"abc"), 0x3524_41C2);
        assert_eq!(crc32(b"123456789"), 0xCBF4_3926);
    }

    #[test]
    fn ecn_reports_how_the_target_answered_the_congestion_flags() {
        let cc = |flags: u8| {
            ecn_test(&reply(flags))
                .get("CC")
                .map(str::to_owned)
                .unwrap_or_default()
        };
        assert_eq!(cc(TH_ECE | TH_CWR), "S", "echoed both back");
        assert_eq!(cc(TH_ECE), "Y", "supports ECN");
        assert_eq!(cc(0), "N", "no support");
        assert_eq!(cc(TH_CWR), "O", "CWR alone is none of the above");
    }

    #[test]
    fn out_of_range_t_numbers_are_rejected() {
        for n in [0u8, 8, 255] {
            assert!(t_test(n, &reply(0x12), &ctx()).is_none(), "T{n}");
        }
    }

    #[test]
    fn the_win_and_ops_tests_need_all_six_replies() {
        let full: Vec<Option<u16>> = (0..6).map(|i| Some(1000 + i)).collect();
        let t = win_test(&full).expect("all six present");
        assert_eq!(t.id, TestId::Win);
        assert_eq!(t.get("W1"), Some("3E8"));
        assert_eq!(t.get("W6"), Some("3ED"));

        // A partial set would be scored against complete database entries as though the
        // gaps were deliberate.
        let mut partial = full.clone();
        partial[3] = None;
        assert!(win_test(&partial).is_none());
        assert!(win_test(&full[..5]).is_none());

        let segs: Vec<Option<Vec<u8>>> =
            (0..6).map(|_| Some(segment(0x12, &[4, 2], &[]))).collect();
        let t = ops_test(&segs).expect("all six present");
        assert_eq!(t.id, TestId::Ops);
        assert_eq!(t.get("O1"), Some("S"));
        let mut partial = segs.clone();
        partial[0] = None;
        assert!(ops_test(&partial).is_none());
    }

    #[test]
    fn every_attribute_the_tests_define_is_populated() {
        // A slot left unset would be silently skipped by the scorer, quietly lowering
        // the accuracy of every comparison. T1 legitimately omits W and O, and TG is
        // resolved later by `finalize_ttl` (which sets exactly one of T and TG).
        let r = reply(0x12);
        for n in 2..=7u8 {
            let t = t_test(n, &r, &ctx()).unwrap();
            for attr in t.id.attrs() {
                if *attr == "TG" {
                    continue;
                }
                assert!(t.get(attr).is_some(), "T{n} attribute {attr} unset");
            }
        }
        let t = ecn_test(&r);
        for attr in t.id.attrs() {
            if *attr == "TG" {
                continue;
            }
            assert!(t.get(attr).is_some(), "ECN attribute {attr} unset");
        }
    }

    #[test]
    fn a_truncated_segment_does_not_panic() {
        let mut r = reply(TH_RST);
        for len in 0..24usize {
            r.segment = vec![0u8; len];
            let t = t_test(4, &r, &ctx()).expect("still builds");
            assert!(t.get("RD").is_some());
            let _ = ecn_test(&r);
        }
    }
    #[test]
    fn the_initial_ttl_guess_rounds_up_to_the_values_stacks_actually_use() {
        assert_eq!(initial_ttl_guess(0), 32);
        assert_eq!(initial_ttl_guess(32), 32);
        assert_eq!(initial_ttl_guess(33), 64);
        assert_eq!(initial_ttl_guess(64), 64);
        assert_eq!(initial_ttl_guess(65), 128);
        assert_eq!(initial_ttl_guess(128), 128);
        assert_eq!(initial_ttl_guess(129), 255);
        assert_eq!(initial_ttl_guess(255), 255);
    }

    #[test]
    fn a_known_distance_reconstructs_the_initial_ttl_and_leaves_tg_unset() {
        let mut r = reply(0x12);
        r.ttl = 57; // seven hops away from an initial 64
        let mut t = t_test(2, &r, &ctx()).unwrap();
        assert_eq!(
            t.get("T"),
            Some("39"),
            "the observed TTL, before finalizing"
        );
        finalize_ttl(&mut t, Some(8));
        assert_eq!(t.get("T"), Some("40"), "57 + 8 - 1 = 64");
        assert_eq!(t.get("TG"), None, "T and TG are mutually exclusive");
    }

    #[test]
    fn an_unknown_distance_guesses_tg_and_removes_the_uncorrected_t() {
        // Leaving the observed TTL in place would match entries for a completely
        // different initial value, so the C deletes it.
        let mut r = reply(0x12);
        r.ttl = 57;
        let mut t = t_test(2, &r, &ctx()).unwrap();
        finalize_ttl(&mut t, None);
        assert_eq!(t.get("T"), None, "the uncorrected TTL must not survive");
        assert_eq!(t.get("TG"), Some("40"), "rounded up to 64");
    }

    #[test]
    fn finalizing_is_safe_at_the_edges() {
        let mut r = reply(0x12);
        r.ttl = 255;
        let mut t = t_test(2, &r, &ctx()).unwrap();
        // A zero distance would underflow `distance - 1` in the C.
        finalize_ttl(&mut t, Some(0));
        assert_eq!(t.get("T"), Some("FF"));

        // Finalizing a test with no T at all is a no-op, not a panic.
        let mut empty = FingerTest::new(TestId::T2);
        finalize_ttl(&mut empty, None);
        assert_eq!(empty.get("T"), None);
        assert_eq!(empty.get("TG"), None);

        // ECN carries the same pair.
        let mut e = ecn_test(&r);
        finalize_ttl(&mut e, None);
        assert_eq!(e.get("TG"), Some("FF"));
        assert_eq!(e.get("T"), None);
    }
}
