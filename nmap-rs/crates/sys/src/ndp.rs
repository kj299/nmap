//! NDP next-hop resolution on the wire — the I/O half of [`nmap_core::ndp`].
//!
//! The IPv6 probe path is layer 2. Linux has no `IPV6_HDRINCL`, so unlike IPv4 there is
//! no raw socket that will accept a caller-built IPv6 header and route it: the driver
//! frames its own Ethernet header, and to do that it needs the next hop's MAC. This
//! module runs the exchange that finds it — the port of `doND()`'s send/retransmit loop.
//!
//! Every decision made from bytes lives in `core::ndp`, where it is differential-tested
//! against nmap and fuzzed. What is left here is scheduling and I/O, and it is generic
//! over [`RawSender`] and [`PacketSource`] exactly like [`crate::fpengine`], so the whole
//! exchange runs against mocks in CI. **No `unsafe`.**

use std::collections::{BTreeSet, HashMap};
use std::io;
use std::time::Duration;

use tokio::time::Instant;

use nmap_core::ndp::{
    build_neighbor_solicitation, na_bpf_filter, parse_neighbor_advertisement, resolve_from_frame,
    ETHERTYPE_IPV6, ETH_HDR_LEN,
};

use crate::capture::{AsyncCapture, PacketSource};
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

/// Wrap `payload` in an Ethernet header. The IPv6 send path builds this itself, since
/// the kernel will not do it for a caller-supplied IPv6 header.
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

/// Solicit `next_hop`'s link-layer address, retransmitting on `doND`'s schedule.
///
/// Returns the resolved MAC, or `None` if all three solicitations went unanswered.
///
/// Unlike `doND`, which reports success on any advertisement naming the right address
/// and leaves the caller's MAC buffer untouched when the reply carried none, this
/// resolves only when an address was actually advertised — `core::ndp::resolve_from_frame`
/// makes the other outcome unrepresentable. See `DIVERGENCES.md`
/// `ndp-advert-accepted-without-link-layer-address`.
pub async fn resolve<S, P>(
    sender: &mut S,
    source: P,
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    next_hop: [u8; 16],
) -> Option<[u8; 6]>
where
    S: RawSender,
    P: PacketSource,
{
    let solicitation = build_neighbor_solicitation(src_mac, src_ip, next_hop);
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();

    for deadline in ND_DEADLINES {
        // A failed send is not fatal: the remaining attempts may still succeed, and the
        // capture may already hold an answer to an earlier one.
        let _ = sender.send(&solicitation);

        let until = start.checked_add(deadline).unwrap_or_else(Instant::now);
        loop {
            // The C floors an expired deadline at 25 ms so each attempt still gets one
            // look at the capture before moving on.
            let remaining = until.saturating_duration_since(Instant::now());
            let window = if remaining.is_zero() {
                ND_MIN_LISTEN
            } else {
                remaining
            };
            match tokio::time::timeout(window, capture.recv()).await {
                // A frame: does it resolve the address we asked about?
                Ok(Some(frame)) => {
                    if let Some(mac) = resolve_from_frame(&frame.data, ETH_HDR_LEN, next_hop) {
                        capture.stop();
                        return Some(mac);
                    }
                }
                // The capture ended; no further frame can arrive.
                Ok(None) => {
                    capture.stop();
                    return None;
                }
                // This attempt's window closed — retransmit.
                Err(_) => break,
            }
        }
    }

    capture.stop();
    None
}

/// Solicit every address in `next_hops` at once: one capture, and at each of `doND`'s
/// deadlines a solicitation to every address not yet advertised. Returns the MACs
/// found; an address missing from the map went unanswered for the whole schedule.
///
/// The IPv6 scans need a MAC for every on-link target and every gateway. The C finds
/// those of its on-link targets with one ND ping over the whole host batch
/// (`targets.cc`'s `arpping`, `PING_SCAN_ND`), not one exchange after another, so a
/// batch of silent neighbors costs one schedule (800 ms) rather than one each. Each
/// address gets [`resolve`]'s schedule and acceptance rule (an advertisement about it,
/// carrying a link-layer address); a duplicate address is solicited once.
pub async fn resolve_many<S, P>(
    sender: &mut S,
    source: P,
    src_mac: [u8; 6],
    src_ip: [u8; 16],
    next_hops: &[[u8; 16]],
) -> HashMap<[u8; 16], [u8; 6]>
where
    S: RawSender,
    P: PacketSource,
{
    let mut found = HashMap::new();
    // Ordered, so the solicitations go out in a fixed order.
    let mut pending: BTreeSet<[u8; 16]> = next_hops.iter().copied().collect();
    if pending.is_empty() {
        return found;
    }
    let mut capture = AsyncCapture::spawn(source, CAPTURE_CAPACITY);
    let start = Instant::now();

    'schedule: for deadline in ND_DEADLINES {
        for &hop in &pending {
            let _ = sender.send(&build_neighbor_solicitation(src_mac, src_ip, hop));
        }
        let until = start.checked_add(deadline).unwrap_or_else(Instant::now);
        loop {
            let remaining = until.saturating_duration_since(Instant::now());
            let window = if remaining.is_zero() {
                ND_MIN_LISTEN
            } else {
                remaining
            };
            match tokio::time::timeout(window, capture.recv()).await {
                Ok(Some(frame)) => {
                    let Some(na) = parse_neighbor_advertisement(&frame.data, ETH_HDR_LEN) else {
                        continue;
                    };
                    if let (Some(mac), true) = (na.mac, pending.contains(&na.target)) {
                        pending.remove(&na.target);
                        found.insert(na.target, mac);
                        if pending.is_empty() {
                            break 'schedule;
                        }
                    }
                }
                Ok(None) => break 'schedule,
                Err(_) => break,
            }
        }
    }

    capture.stop();
    found
}

/// Resolve the MAC to address frames to, for a route already chosen.
///
/// A directly-connected target is solicited for itself; otherwise the gateway is. When
/// the OS already knows the next hop's MAC (a gateway entry from the route table), that
/// is used and no solicitation is sent — the same short-circuit `getNextHopMAC` makes by
/// consulting the system ARP/neighbor cache first.
///
/// # Errors
/// Returns `AddrNotAvailable` when the exchange goes unanswered, since no IPv6 probe can
/// be framed without a destination MAC.
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
        .await
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
    use std::sync::{Arc, Mutex};

    const SRC_MAC: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];
    const SRC_IP: [u8; 16] = [
        0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0x02, 0x0c, 0x29, 0xff, 0xfe, 0x1a, 0x2b, 0x3c,
    ];
    const NEXT_HOP: [u8; 16] = [
        0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0xde, 0xad, 0xbe, 0xef,
    ];
    const THEIR_MAC: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];

    /// A capture that replays scripted frames, then ends so the channel closes promptly.
    struct ScriptedSource {
        frames: Arc<Mutex<std::vec::IntoIter<Vec<u8>>>>,
    }

    impl ScriptedSource {
        fn new(frames: Vec<Vec<u8>>) -> ScriptedSource {
            ScriptedSource {
                frames: Arc::new(Mutex::new(frames.into_iter())),
            }
        }
    }

    impl PacketSource for ScriptedSource {
        fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
            let next = self.frames.lock().unwrap().next();
            match next {
                Some(f) => Ok(Some(f)),
                None => Err(io::Error::other("end of script")),
            }
        }
    }

    /// A capture that replays scripted frames and then stays silent (open), so a
    /// schedule runs on after the script.
    struct ThenSilent(std::vec::IntoIter<Vec<u8>>);

    impl PacketSource for ThenSilent {
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

    /// A Neighbor Advertisement about `target`, as an Ethernet frame.
    fn advert(target: [u8; 16], mac: Option<[u8; 6]>) -> Vec<u8> {
        let mut f = vec![0u8; ETH_HDR_LEN + 40];
        f[12] = 0x86;
        f[13] = 0xdd;
        f[ETH_HDR_LEN + 6] = 58;
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

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_advertisement_resolves_the_next_hop() {
        let mut sender = MockSender::default();
        let source = ScriptedSource::new(vec![advert(NEXT_HOP, Some(THEIR_MAC))]);
        let got = resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP).await;
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
        assert_eq!(
            resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP).await,
            None
        );
    }

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn an_advertisement_about_another_address_is_ignored() {
        let mut sender = MockSender::default();
        let mut other = NEXT_HOP;
        other[15] ^= 0xff;
        let source = ScriptedSource::new(vec![advert(other, Some(THEIR_MAC))]);
        assert_eq!(
            resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP).await,
            None
        );
    }

    // An advertisement for the wrong address must not consume the attempt: the right
    // one, arriving behind it, still resolves.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_later_advertisement_still_resolves() {
        let mut sender = MockSender::default();
        let mut other = NEXT_HOP;
        other[15] ^= 0xff;
        let source = ScriptedSource::new(vec![
            advert(other, Some([1; 6])),
            advert(NEXT_HOP, None),
            advert(NEXT_HOP, Some(THEIR_MAC)),
        ]);
        assert_eq!(
            resolve(&mut sender, source, SRC_MAC, SRC_IP, NEXT_HOP).await,
            Some(THEIR_MAC)
        );
    }

    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn silence_retransmits_then_gives_up() {
        let mut sender = MockSender::default();
        let started = std::time::Instant::now();
        let got = resolve(&mut sender, SilentSource, SRC_MAC, SRC_IP, NEXT_HOP).await;
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

    /// A second next hop, for the batch tests.
    fn hop(last: u8) -> [u8; 16] {
        let mut h = NEXT_HOP;
        h[15] = last;
        h
    }

    // Each address resolves by its own advertisement, in whatever order they come;
    // advertisements without an address, about strangers or repeated, change nothing;
    // and a duplicate request is solicited once.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_batch_resolves_each_address_by_its_own_advertisement() {
        let mut sender = MockSender::default();
        let (a, b, c) = (hop(1), hop(2), hop(3));
        let source = ScriptedSource::new(vec![
            advert(b, None),
            advert(hop(9), Some([9; 6])),
            advert(b, Some([2; 6])),
            advert(a, Some([1; 6])),
            advert(b, Some([7; 6])),
        ]);
        let got = resolve_many(&mut sender, source, SRC_MAC, SRC_IP, &[a, b, a, c]).await;
        assert_eq!(got.len(), 2);
        assert_eq!(got[&a], [1; 6]);
        assert_eq!(
            got[&b], [2; 6],
            "the first advertisement with an address wins"
        );
        assert!(!got.contains_key(&c));
        // The first round solicits each distinct address once, as core::ndp builds it.
        let first: Vec<Vec<u8>> = [a, b, c]
            .iter()
            .map(|h| build_neighbor_solicitation(SRC_MAC, SRC_IP, *h).to_vec())
            .collect();
        assert_eq!(sender.sent[..3], first[..]);
    }

    // Silence: every address is solicited at each of the three deadlines, and the
    // whole batch is bounded by the schedule, not by its size.
    #[cfg_attr(miri, ignore = "spawns a capture thread and uses the clock")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_silent_batch_retransmits_on_one_schedule() {
        let mut sender = MockSender::default();
        let hops: Vec<[u8; 16]> = (1..=20).map(hop).collect();
        let started = std::time::Instant::now();
        let got = resolve_many(&mut sender, SilentSource, SRC_MAC, SRC_IP, &hops).await;
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
        let source = ThenSilent(vec![advert(a, Some([1; 6]))].into_iter());
        let got = resolve_many(&mut sender, source, SRC_MAC, SRC_IP, &[a, b]).await;
        assert_eq!(got.len(), 1);
        let count = |h| {
            let sol = build_neighbor_solicitation(SRC_MAC, SRC_IP, h).to_vec();
            sender.sent.iter().filter(|f| **f == sol).count()
        };
        assert_eq!(count(a), 1, "a is solicited only in the first round");
        assert_eq!(count(b), ND_DEADLINES.len(), "b in every round");
        let mut none = MockSender::default();
        let empty = resolve_many(&mut none, SilentSource, SRC_MAC, SRC_IP, &[]).await;
        assert!(empty.is_empty() && none.sent.is_empty());
    }

    #[test]
    fn filter_targets_our_own_mac() {
        let f = bpf_filter(SRC_MAC);
        // The C formats the MAC with %02X, so the filter carries it uppercase.
        assert!(f.contains("000C291A2B3C"), "filter must name our MAC: {f}");
        assert!(f.contains("ip6[40:1] = 136"), "and select advertisements");
    }
}
