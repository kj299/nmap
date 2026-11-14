//! NDP next-hop resolution on the wire — the I/O half of [`nmap_core::ndp`].
//!
//! The IPv6 probe path is layer 2, by choice (`ipv6-send-is-layer-2-only`): the driver
//! frames its own Ethernet header, and to do that it needs the next hop's MAC. (A Linux
//! `IPPROTO_RAW` IPv6 socket would take a caller-built header, which is how 7.94 sends
//! there, `acinclude.m4:90`; the BSDs have no such socket.) This module runs the
//! exchange that finds the MAC — the port of `doND()`'s send/retransmit loop.
//!
//! An advertisement is parsed in `core::ndp` (`parse_neighbor_advertisement`), where
//! it is differential-tested against nmap and fuzzed. What this module decides from
//! the frame is which advertisements answer: hop limit 255, a unicast MAC, and the
//! rule an address is held to (`answer`, unit-tested by
//! `what_answers_a_solicitation`). The rest is scheduling and I/O, generic over
//! [`RawSender`] and [`PacketSource`] exactly like [`crate::fpengine`], so the whole
//! exchange runs against mocks in CI. **No `unsafe`.**

use std::collections::{BTreeMap, HashMap};
use std::io;
use std::time::Duration;

use tokio::time::Instant;

use nmap_core::ndp::{
    build_neighbor_solicitation, na_bpf_filter, parse_neighbor_advertisement, ETHERTYPE_IPV6,
    ETH_HDR_LEN,
};

use crate::capture::{AsyncCapture, CaptureFailed, PacketSource};
use crate::rawio::RawSender;

/// Frames buffered between the capture thread and this task.
const CAPTURE_CAPACITY: usize = 64;

/// `doND`'s retransmit schedule. These are **deadlines measured from the start of the
/// exchange**, not per-attempt waits — the C computes
/// `timeouts[num_sends - 1] - (now - start)` — so the last is also the give-up time.
pub const ND_DEADLINES: [Duration; 3] = [
    Duration::from_millis(100),
    Duration::from_millis(400),
    Duration::from_millis(800),
];

/// The floor `doND` puts under a listen round, so a deadline that has already passed
/// still gets one pass over the capture rather than none.
const ND_MIN_LISTEN: Duration = Duration::from_millis(25);

/// Wrap `payload` in an Ethernet header. The IPv6 send path is layer 2 by choice
/// (`ipv6-send-is-layer-2-only`), so it frames each packet itself.
#[must_use]
pub fn frame_ethernet(dst_mac: [u8; 6], src_mac: [u8; 6], payload: &[u8]) -> Vec<u8> {
    let mut frame = Vec::with_capacity(ETH_HDR_LEN.saturating_add(payload.len()));
    frame.extend_from_slice(&dst_mac);
    frame.extend_from_slice(&src_mac);
    frame.extend_from_slice(&ETHERTYPE_IPV6.to_be_bytes());
    frame.extend_from_slice(payload);
    frame
}

/// The capture filter for the exchange — advertisements addressed to our own MAC.
#[must_use]
pub fn bpf_filter(src_mac: [u8; 6]) -> String {
    na_bpf_filter(src_mac)
}

/// The capture filter of the C's ND ping (`begin_sniffer`, `scan_engine_raw.cc:905`):
/// every advertisement, to any link-layer address. Unlike [`bpf_filter`] it has no
/// `ether dst` term, so an advertisement sent to a multicast group is seen too.
#[must_use]
pub fn nd_ping_filter() -> String {
    format!(
        "icmp6 and ip6[6:1] = {} and ip6[40:1] = {}",
        nmap_core::ndp::NH_ICMPV6,
        nmap_core::ndp::ICMPV6_NEIGHBOR_ADVERTISEMENT
    )
}

/// Which advertisements answer a solicitation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Rule {
    /// `doND`'s: one carrying a target link-layer address
    /// (`ndp-advert-accepted-without-link-layer-address`).
    DoNd,
    /// The ND ping's (`get_ns_result`, `scan_engine_raw.cc:1555`): any advertisement
    /// about the address says it is there. Without a target link-layer address, the
    /// frame's own Ethernet source is where its probes go.
    NdPing,
}

/// The address an advertisement answers for, and the MAC to frame to, under `rule`.
///
/// Whatever the rule, the advertisement must come from the link, hop limit 255 (RFC
/// 4861 §7.1.2), and name a unicast MAC. The C checks neither, but the C also never
/// frames its scan probes to the MAC it learns: the kernel resolves the next hop for
/// them. Here the MAC decides where every probe goes, so a forged or forwarded
/// advertisement must not choose it (`ndp-advert-hop-limit-255`).
fn answer(frame: &[u8], rule: Rule) -> Option<([u8; 16], [u8; 6])> {
    let na = parse_neighbor_advertisement(frame, ETH_HDR_LEN)?;
    if frame.get(ETH_HDR_LEN.checked_add(7)?) != Some(&255) {
        return None;
    }
    let mac = match (na.mac, rule) {
        (Some(mac), _) => mac,
        (None, Rule::DoNd) => return None,
        (None, Rule::NdPing) => frame.get(6..12)?.try_into().ok()?,
    };
    (mac[0] & 1 == 0).then_some((na.target, mac))
}

/// Solicit every address in `hops`, on `doND`'s schedule, and collect the answers.
///
/// At each deadline every address not yet answered is solicited, and the capture is
/// read until that deadline, or, once it has passed, for one floored window
/// (`ND_MIN_LISTEN`) and no longer, as `doND` does (`netutil.cc:3612`). A stream of
/// frames that answer nothing cannot keep an attempt open, so the exchange ends by
/// the last deadline plus that window.
///
/// # Errors
/// The capture's error, when it fails during the exchange: a capture that died is not
/// a link that answered nothing.
async fn exchange<S, P>(
    sender: &mut S,
    source: P,
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    hops: &[([u8; 16], Rule)],
) -> io::Result<HashMap<[u8; 16], [u8; 6]>>
where
    S: RawSender,
    P: PacketSource,
{
    let mut found = HashMap::new();
    // Ordered, so the solicitations go out in a fixed order. Each address keeps the
    // rule its answer is held to.
    let mut pending: BTreeMap<[u8; 16], Rule> = hops.iter().copied().collect();
    if pending.is_empty() {
        return Ok(found);
    }
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();
    let mut ended = false;

    'schedule: for deadline in ND_DEADLINES {
        // A failed send is not fatal: the remaining attempts may still succeed, and the
        // capture may already hold an answer to an earlier one.
        for &hop in pending.keys() {
            let _ = sender.send(&build_neighbor_solicitation(src_mac, src_ip, hop));
        }
        let now = Instant::now();
        let due = start.checked_add(deadline).unwrap_or(now);
        let until = if due > now {
            due
        } else {
            now.checked_add(ND_MIN_LISTEN).unwrap_or(now)
        };
        loop {
            match tokio::time::timeout_at(until, capture.recv()).await {
                Ok(Some(frame)) => {
                    let about = parse_neighbor_advertisement(&frame.data, ETH_HDR_LEN)
                        .and_then(|na| pending.get(&na.target).copied());
                    if let Some((target, mac)) = about.and_then(|rule| answer(&frame.data, rule)) {
                        pending.remove(&target);
                        found.insert(target, mac);
                        if pending.is_empty() {
                            break 'schedule;
                        }
                    }
                }
                // The capture ended; no further frame can arrive.
                Ok(None) => {
                    ended = true;
                    break 'schedule;
                }
                // This attempt's window closed — retransmit.
                Err(_) => break,
            }
        }
    }

    let failed = if ended { capture.error() } else { None };
    capture.stop();
    match failed {
        Some(e) => Err(CaptureFailed(format!("during neighbor discovery: {e}")).into()),
        None => Ok(found),
    }
}

/// Solicit `next_hop`'s link-layer address, retransmitting on `doND`'s schedule.
///
/// Returns the resolved MAC, or `None` if all three solicitations went unanswered.
///
/// Unlike `doND`, which reports success on any advertisement naming the right address
/// and leaves the caller's MAC buffer untouched when the reply carried none, this
/// resolves only when an address was actually advertised. See `DIVERGENCES.md`
/// `ndp-advert-accepted-without-link-layer-address`.
///
/// # Errors
/// The capture's error, when it fails during the exchange.
pub async fn resolve<S, P>(
    sender: &mut S,
    source: P,
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    next_hop: [u8; 16],
) -> io::Result<Option<[u8; 6]>>
where
    S: RawSender,
    P: PacketSource,
{
    let mut found = exchange(sender, source, src_mac, src_ip, &[(next_hop, Rule::DoNd)]).await?;
    Ok(found.remove(&next_hop))
}

/// Solicit every on-link target and gateway at once: one capture, and at each of
/// `doND`'s deadlines a solicitation to every address not yet answered. Returns the
/// MACs found; an address missing from the map went unanswered for the whole schedule.
///
/// The IPv6 scans need a MAC for every on-link target and every gateway. The C finds
/// those of its on-link targets with one ND ping over the whole host batch
/// (`targets.cc`'s `arpping`, `PING_SCAN_ND`), not one exchange after another, so a
/// batch of silent neighbors costs one schedule (800 ms) rather than one each. An
/// on-link target is held to the ND ping's rule, since its verdict decides which
/// on-link hosts are up: any advertisement about the address, with or without a
/// link-layer address, read through [`nd_ping_filter`]. The C never ND-pings a
/// gateway; its kernel resolves one, and under `--send-eth` `doND` does. So a gateway
/// is held to `doND`'s rule here: only an advertised link-layer address resolves it
/// (`ndp-advert-accepted-without-link-layer-address`). An address that is both is a
/// gateway, since other targets' probes are framed to it. A duplicate address is
/// solicited once.
///
/// # Errors
/// The capture's error, when it fails during the exchange.
pub async fn resolve_many<S, P>(
    sender: &mut S,
    source: P,
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    on_link: &[[u8; 16]],
    gateways: &[[u8; 16]],
) -> io::Result<HashMap<[u8; 16], [u8; 6]>>
where
    S: RawSender,
    P: PacketSource,
{
    // Gateways last, so an address that is both takes the gateway's rule.
    let hops: Vec<([u8; 16], Rule)> = on_link
        .iter()
        .map(|&a| (a, Rule::NdPing))
        .chain(gateways.iter().map(|&a| (a, Rule::DoNd)))
        .collect();
    exchange(sender, source, src_mac, src_ip, &hops).await
}

/// Resolve the MAC to address frames to, for a route already chosen.
///
/// A directly-connected target is solicited for itself; otherwise the gateway is. When
/// the next hop's MAC is already known, that is used and no solicitation is sent — the
/// same short-circuit `getNextHopMAC` makes by consulting the system ARP/neighbor cache
/// first.
///
/// # Errors
/// Returns `AddrNotAvailable` when the exchange goes unanswered, since no IPv6 probe can
/// be framed without a destination MAC, and the capture's error when it fails.
pub async fn next_hop_mac<S, P>(
    sender: &mut S,
    source: P,
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    next_hop: [u8; 16],
    known: Option<[u8; 6]>,
) -> io::Result<[u8; 6]>
where
    S: RawSender,
    P: PacketSource,
{
    if let Some(mac) = known {
        return Ok(mac);
    }
    resolve(sender, source, src_mac, src_ip, next_hop)
        .await?
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no neighbor advertisement for the next hop",
            )
        })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rawio::MockSender;

    const SRC_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];
    const SRC_IP: [u8; 16] = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x0c, 0x29, 0xff, 0xfe, 0x1a, 0x2b, 0x3c,
    ];
    const NEXT_HOP: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef,
    ];
    const THEIR_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xf0];
    /// The Ethernet source of every scripted advertisement.
    const ETH_SRC: [u8; 6] = [0x02, 0, 0, 0, 0, 0x77];

    /// A capture that replays scripted frames, then stays open and silent. (A capture
    /// that ends is a failed one, which the exchange reports as an error.)
    struct ScriptedSource(std::vec::IntoIter<Vec<u8>>);

    impl ScriptedSource {
        fn new(frames: Vec<Vec<u8>>) -> ScriptedSource {
            ScriptedSource(frames.into_iter())
        }
    }

    impl PacketSource for ScriptedSource {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            if let Some(f) = self.0.next() {
                return Ok(Some(f));
            }
            std::thread::sleep(Duration::from_millis(2));
            Ok(None)
        }
    }

    /// A capture that never yields anything, so the retransmit schedule runs in full.
    struct SilentSource;

    impl PacketSource for SilentSource {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            std::thread::sleep(Duration::from_millis(2));
            Ok(None)
        }
    }

    /// A capture that yields `frame` every 2 ms, forever.
    struct Flood(Vec<u8>);

    impl PacketSource for Flood {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            std::thread::sleep(Duration::from_millis(2));
            Ok(Some(self.0.clone()))
        }
    }

    /// A capture that fails on its first read, as one whose interface went away.
    struct Failing;

    impl PacketSource for Failing {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            Err(io::Error::other("the interface went away"))
        }
    }

    /// A Neighbor Advertisement about `target`, as an Ethernet frame from `ETH_SRC`,
    /// hop limit 255.
    fn advert(target: [u8; 16], mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + 40];
        f[6..12].copy_from_slice(&ETH_SRC);
        f[12] = 0x86;
        f[13] = 0xdd;
        f[ETH_HDR_LEN + 6] = 58;
        f[ETH_HDR_LEN + 7] = 255;
        f.extend_from_slice(&[136, 0, 0, 0]); // type, code, checksum
        f.extend_from_slice(&[0x60, 0, 0, 0]); // flags
        f.extend_from_slice(&target);
        if let Some(m) = mac {
            f.push(2);
            f.push(1);
            f.extend_from_slice(&m);
        }
        f
    }

    /// `advert`, arrived with `hop_limit`.
    fn advert_hl(target: [u8; 16], mac: Option<[u8; 6]>, hop_limit: u8) -> Vec<u8> {
        let mut f = advert(target, mac);
        f[ETH_HDR_LEN + 7] = hop_limit;
        f
    }

    #[test]
    fn ethernet_framing() {
        let f = frame_ethernet(THEIR_MAC, SRC_MAC, &[0xde, 0xad]);
        assert_eq!(&f[0..6], &THEIR_MAC);
        assert_eq!(&f[6..12], &SRC_MAC);
        assert_eq!(&f[12..14], &[0x86, 0xdd], "IPv6 ethertype");
        assert_eq!(&f[14..], &[0xde, 0xad]);
        assert_eq!(f.len(), ETH_HDR_LEN + 2);
    }

    #[test]
    fn empty_payload_still_frames() {
        assert_eq!(frame_ethernet(THEIR_MAC, SRC_MAC, &[]).len(), ETH_HDR_LEN);
    }

    #[test]
    fn a_known_mac_short_circuits_the_exchange() {
        let mut sender = MockSender::default();
        let got = futures_lite_block(next_hop_mac(
            &mut sender,
            SilentSource,
            SRC_MAC,
            SRC_IP,
            NEXT_HOP,
            Some(THEIR_MAC),
        ));
        assert_eq!(got.unwrap(), THEIR_MAC);
        assert!(
            sender.sent.is_empty(),
            "a known next-hop MAC must not put a solicitation on the wire"
        );
    }

    /// Minimal blocking adapter so the short-circuit test needs no runtime threads.
    fn futures_lite_block<F: std::future::Future>(f: F) -> F::Output {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(f)
    }

    /// Who answers, under each rule: the address and an address of its own (or,
    /// for the ND ping, any advertisement about it); from the link (hop limit 255);
    /// to frame to a unicast MAC.
    #[test]
    fn what_answers_a_solicitation() {
        let full = advert(NEXT_HOP, Some(THEIR_MAC));
        assert_eq!(answer(&full, Rule::DoNd), Some((NEXT_HOP, THEIR_MAC)));
        assert_eq!(answer(&full, Rule::NdPing), Some((NEXT_HOP, THEIR_MAC)));
        // No target link-layer address: doND's rule says nothing; the ND ping's says
        // the address is there, and its frame's source is where probes go.
        let bare = advert(NEXT_HOP, None);
        assert_eq!(answer(&bare, Rule::DoNd), None);
        assert_eq!(answer(&bare, Rule::NdPing), Some((NEXT_HOP, ETH_SRC)));
        // Forwarded from off the link: neither rule.
        for hl in [0, 64, 254] {
            let f = advert_hl(NEXT_HOP, Some(THEIR_MAC), hl);
            assert_eq!(answer(&f, Rule::DoNd), None, "hop limit {hl}");
            assert_eq!(answer(&f, Rule::NdPing), None, "hop limit {hl}");
        }
        // A group address frames nothing to one host.
        let multicast = advert(NEXT_HOP, Some([0x33, 0x33, 0, 0, 0, 1]));
        assert_eq!(answer(&multicast, Rule::DoNd), None);
        let mut from_group = advert(NEXT_HOP, None);
        from_group[6] = 0x01;
        assert_eq!(answer(&from_group, Rule::NdPing), None);
        // Not an advertisement at all.
        assert_eq!(answer(&full[..ETH_HDR_LEN + 30], Rule::NdPing), None);
    }

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_advertisement_resolves_the_next_hop() {
        let mut sender = MockSender::default();
        let source = ScriptedSource::new(vec![advert(NEXT_HOP, Some(THEIR_MAC))]);
        let got = resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP)
            .await
            .unwrap();
        assert_eq!(got, Some(THEIR_MAC));
        assert_eq!(sender.sent.len(), 1, "resolved on the first solicitation");
        // What went out is the solicitation core::ndp builds, unchanged.
        assert_eq!(
            sender.sent[0],
            build_neighbor_solicitation(SRC_MAC, SRC_IP, NEXT_HOP).to_vec()
        );
    }

    // The divergence, observed through the driver: nmap accepts an advertisement with
    // no target link-layer address option and then uses an uninitialised MAC. Here the
    // exchange simply goes unresolved.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_advertisement_without_an_address_does_not_resolve() {
        let mut sender = MockSender::default();
        let source = ScriptedSource::new(vec![advert(NEXT_HOP, None)]);
        let got = resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP)
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_advertisement_about_another_address_is_ignored() {
        let mut sender = MockSender::default();
        let mut other = NEXT_HOP;
        other[15] ^= 0xff;
        let source = ScriptedSource::new(vec![advert(other, Some(THEIR_MAC))]);
        let got = resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP)
            .await
            .unwrap();
        assert_eq!(got, None);
    }

    // An advertisement for the wrong address, one without an address, and a forwarded
    // one must not consume the attempt: the right one, arriving behind them, resolves.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_later_advertisement_still_resolves() {
        let mut sender = MockSender::default();
        let mut other = NEXT_HOP;
        other[15] ^= 0xff;
        let source = ScriptedSource::new(vec![
            advert(other, Some([2; 6])),
            advert(NEXT_HOP, None),
            advert_hl(NEXT_HOP, Some([4; 6]), 254),
            advert(NEXT_HOP, Some(THEIR_MAC)),
        ]);
        let got = resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP)
            .await
            .unwrap();
        assert_eq!(got, Some(THEIR_MAC));
    }

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silence_retransmits_then_gives_up() {
        let mut sender = MockSender::default();
        let started = std::time::Instant::now();
        let got = resolve(&mut sender, SilentSource, SRC_MAC, SRC_IP, NEXT_HOP)
            .await
            .unwrap();
        assert_eq!(got, None);
        assert_eq!(
            sender.sent.len(),
            ND_DEADLINES.len(),
            "one solicitation per scheduled attempt"
        );
        // The schedule's deadlines run from the start of the exchange, so the whole
        // thing is bounded by the last one rather than by their sum.
        assert!(
            started.elapsed() < Duration::from_secs(3),
            "the exchange must be bounded by its schedule"
        );
    }

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_unanswered_exchange_is_an_error_not_a_guess() {
        let mut sender = MockSender::default();
        let err = next_hop_mac(&mut sender, SilentSource, SRC_MAC, SRC_IP, NEXT_HOP, None)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
    }

    /// A stream of advertisements that answer nothing cannot hold an attempt open:
    /// each listens to its deadline, or one floored window past it, as doND does.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_flood_of_wrong_answers_does_not_hold_the_exchange_open() {
        let mut other = NEXT_HOP;
        other[15] ^= 0xff;
        // A regression must fail here, not hang the suite: each exchange gets well
        // over its 825 ms, and no more.
        let bound = Duration::from_millis(1500);
        let started = std::time::Instant::now();
        let mut sender = MockSender::default();
        let got = tokio::time::timeout(
            bound,
            resolve(
                &mut sender,
                Flood(advert(other, Some([2; 6]))),
                SRC_MAC,
                SRC_IP,
                NEXT_HOP,
            ),
        )
        .await
        .expect("the exchange ended by its last deadline")
        .unwrap();
        assert_eq!(got, None);
        assert_eq!(
            sender.sent.len(),
            ND_DEADLINES.len(),
            "every attempt was made"
        );
        let mut sender = MockSender::default();
        let got = tokio::time::timeout(
            bound,
            resolve_many(
                &mut sender,
                Flood(advert(other, None)),
                SRC_MAC,
                SRC_IP,
                &[NEXT_HOP, hop(1)],
                &[],
            ),
        )
        .await
        .expect("the batch ended by its last deadline")
        .unwrap();
        assert!(got.is_empty());
        assert!(started.elapsed() < bound * 2, "{:?}", started.elapsed());
    }

    /// A capture that fails is an error, never a link where nobody answered.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_failed_capture_is_an_error_not_silence() {
        let mut sender = MockSender::default();
        let err = resolve_many(&mut sender, Failing, SRC_MAC, SRC_IP, &[NEXT_HOP], &[])
            .await
            .unwrap_err();
        assert!(err.to_string().contains("the interface went away"), "{err}");
        let err = resolve(&mut sender, Failing, SRC_MAC, SRC_IP, NEXT_HOP)
            .await
            .unwrap_err();
        assert!(err.to_string().contains("neighbor discovery"), "{err}");
        assert!(
            crate::capture::is_capture_failure(&err),
            "a capture failure, which the CLI does not fall back from"
        );
    }

    /// A unicast MAC ending in `n`.
    fn uni(n: u8) -> [u8; 6] {
        [0x02, 0, 0, 0, 0, n]
    }

    /// A second next hop, for the batch tests.
    fn hop(last: u8) -> [u8; 16] {
        let mut h = NEXT_HOP;
        h[15] = last;
        h
    }

    // Each address resolves by its own advertisement, in whatever order they come;
    // under the ND ping's rule one without an address answers too, framed to its
    // source; strangers, forwarded ones and repeats change nothing; and a duplicate
    // request is solicited once.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_resolves_each_address_by_its_own_advertisement() {
        let mut sender = MockSender::default();
        let (a, b, c, d) = (hop(1), hop(2), hop(3), hop(4));
        let source = ScriptedSource::new(vec![
            advert_hl(d, Some([4; 6]), 254),
            advert(b, None),
            advert(hop(9), Some(uni(9))),
            advert(b, Some([2; 6])),
            advert(a, Some(uni(1))),
            advert(b, Some(uni(7))),
        ]);
        let got = resolve_many(&mut sender, source, SRC_MAC, SRC_IP, &[a, b, a, c, d], &[])
            .await
            .unwrap();
        assert_eq!(got.len(), 2);
        assert_eq!(got[&a], uni(1));
        assert_eq!(got[&b], ETH_SRC, "the first answer wins");
        assert!(!got.contains_key(&c) && !got.contains_key(&d));
        // The first round solicits each distinct address once, as core::ndp builds it.
        let first: Vec<Vec<u8>> = [a, b, c, d]
            .iter()
            .map(|h| build_neighbor_solicitation(SRC_MAC, SRC_IP, *h).to_vec())
            .collect();
        assert_eq!(sender.sent[..4], first[..]);
    }

    /// A gateway is held to doND's rule: an advertisement without a link-layer
    /// address does not resolve it, and it stays pending for one that has one. An
    /// on-link target in the same batch takes the ND ping's rule. An address that is
    /// both is a gateway.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_gateway_needs_its_link_layer_address() {
        let mut sender = MockSender::default();
        let (target, gw, both, mute_gw) = (hop(1), hop(2), hop(3), hop(4));
        let source = ScriptedSource::new(vec![
            advert(target, None),
            advert(gw, None),
            advert(both, None),
            advert(mute_gw, None),
            advert(gw, Some(uni(2))),
            advert(both, Some(uni(3))),
        ]);
        let got = resolve_many(
            &mut sender,
            source,
            SRC_MAC,
            SRC_IP,
            &[target, both],
            &[gw, both, mute_gw],
        )
        .await
        .unwrap();
        assert_eq!(got.get(&target), Some(&ETH_SRC), "the ND ping's rule");
        assert_eq!(
            got.get(&gw),
            Some(&uni(2)),
            "the advertised address, not the frame's"
        );
        assert_eq!(got.get(&both), Some(&uni(3)));
        assert_eq!(
            got.get(&mute_gw),
            None,
            "no link-layer address, no next hop"
        );
    }

    // Silence: every address is solicited at each of the three deadlines, and the
    // whole batch is bounded by the schedule, not by its size.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_batch_retransmits_on_one_schedule() {
        let mut sender = MockSender::default();
        let hops: Vec<[u8; 16]> = (1..=20).map(hop).collect();
        let started = std::time::Instant::now();
        let got = resolve_many(&mut sender, SilentSource, SRC_MAC, SRC_IP, &hops, &[])
            .await
            .unwrap();
        assert!(got.is_empty());
        assert_eq!(sender.sent.len(), hops.len() * ND_DEADLINES.len());
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    // Resolved addresses are not solicited again; nothing at all is sent for none.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_resolved_address_is_not_solicited_again() {
        let mut sender = MockSender::default();
        let (a, b) = (hop(1), hop(2));
        let source = ScriptedSource::new(vec![advert(a, Some(uni(1)))]);
        let got = resolve_many(&mut sender, source, SRC_MAC, SRC_IP, &[a], &[b])
            .await
            .unwrap();
        assert_eq!(got.len(), 1);
        let count = |h| {
            let sol = build_neighbor_solicitation(SRC_MAC, SRC_IP, h).to_vec();
            sender.sent.iter().filter(|f| **f == sol).count()
        };
        assert_eq!(count(a), 1, "a is solicited only in the first round");
        assert_eq!(count(b), ND_DEADLINES.len(), "b in every round");
        let mut none = MockSender::default();
        let empty = resolve_many(&mut none, SilentSource, SRC_MAC, SRC_IP, &[], &[])
            .await
            .unwrap();
        assert!(empty.is_empty() && none.sent.is_empty());
    }

    #[test]
    fn filter_targets_our_own_mac() {
        let f = bpf_filter(SRC_MAC);
        // The C formats the MAC with %02X, so the filter carries it uppercase.
        assert!(f.contains("000C291A2B3C"), "filter must name our MAC: {f}");
        assert!(f.contains("ip6[40:1] = 136"), "and select advertisements");
    }

    /// The ND ping's filter is the C's, byte for byte (`scan_engine_raw.cc:905`):
    /// every advertisement, to any link-layer address.
    #[test]
    fn the_nd_ping_filter_is_the_cs() {
        assert_eq!(
            nd_ping_filter(),
            "icmp6 and ip6[6:1] = 58 and ip6[40:1] = 136"
        );
    }
}
