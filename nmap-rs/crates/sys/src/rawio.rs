//! Raw packet send / injection — the send half of the raw scan path. Replaces the
//! `send_ip_packet*` / `send_eth_packet` chokepoint in nmap's `tcpip.cc`.
//!
//! [`RawSender`] is the OS-agnostic seam: hand it a fully-formed packet, it puts it on
//! the wire. Two real backends mirror nmap's L3-vs-L2 choice
//! (`send_ip_packet_eth_or_sd`):
//!   * **[`RawIpv4Sender`]** — an L3 raw IPv4 socket (`IP_HDRINCL`) via the safe
//!     `socket2` crate; the kernel adds the link header. Default on Unix, **0
//!     first-party `unsafe`**. Needs `CAP_NET_RAW`/root.
//!   * **[`pcap_sender::PcapSender`]** (feature `pcap`) — L2 injection through
//!     libpcap/Npcap `sendpacket`, for when nmap frames its own Ethernet header (and
//!     the only raw-send path available on Windows). Its FFI is audited upstream, so
//!     still no first-party `unsafe`.
//!
//! [`EthFramingSender`] adapts an L2 backend for the IPv6 probe path, which must frame
//! its own Ethernet header because Linux has no `IPV6_HDRINCL`.
//!
//! A [`MockSender`] records frames for driver tests without touching the network.

use std::collections::HashMap;
use std::io;
use std::net::{Ipv4Addr, SocketAddrV4};

/// IPv4 fixed header length; a raw IPv4 packet must be at least this long.
const IP_HEADER_LEN: usize = 20;
/// `IPPROTO_RAW` — the protocol for an `IP_HDRINCL` raw socket.
const IPPROTO_RAW: i32 = 255;

/// Something that can put a fully-formed packet on the wire.
pub trait RawSender: Send {
    /// Send one packet. Returns the number of bytes written.
    ///
    /// # Errors
    /// Propagates the OS send error (e.g. `EPERM` without raw-socket privilege,
    /// `EMSGSIZE` past the MTU, or an unreachable destination).
    fn send(&mut self, packet: &[u8]) -> io::Result<usize>;
}

/// A test sender that records every frame instead of transmitting it.
#[derive(Debug, Default)]
pub struct MockSender {
    /// Frames handed to [`RawSender::send`], in order.
    pub sent: Vec<Vec<u8>>,
}

impl RawSender for MockSender {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.sent.push(packet.to_vec());
        Ok(packet.len())
    }
}

/// L3 raw IPv4 sender: an `IP_HDRINCL` raw socket that transmits a caller-supplied IP
/// packet, letting the kernel route it and add the link-layer header.
pub struct RawIpv4Sender {
    sock: socket2::Socket,
}

impl RawIpv4Sender {
    /// Open a raw IPv4 socket with `IP_HDRINCL`.
    ///
    /// # Errors
    /// Returns `PermissionDenied` without `CAP_NET_RAW`/Administrator, or another OS
    /// error if the socket cannot be created/configured.
    pub fn new() -> io::Result<RawIpv4Sender> {
        use socket2::{Domain, Protocol, Socket, Type};
        let sock = Socket::new(Domain::IPV4, Type::RAW, Some(Protocol::from(IPPROTO_RAW)))?;
        // We supply the full IP header ourselves (built by `core::build`).
        sock.set_header_included_v4(true)?;
        Ok(RawIpv4Sender { sock })
    }
}

impl RawSender for RawIpv4Sender {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        if packet.len() < IP_HEADER_LEN {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet shorter than an IPv4 header",
            ));
        }
        // The kernel routes by the destination sockaddr; take it from the IP header's
        // destination field (bytes 16..20) so the caller need only pass the packet.
        let dst = Ipv4Addr::new(packet[16], packet[17], packet[18], packet[19]);
        let addr = socket2::SockAddr::from(SocketAddrV4::new(dst, 0));
        self.sock.send_to(packet, &addr)
    }
}

/// How an IPv6 packet is framed for the link it is injected on: by the send
/// handle's datalink, as `send_ip_packet_eth` (`netutil.cc`) frames by
/// `ethsd->datalink`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkFraming {
    /// `DLT_EN10MB`: a 14-byte Ethernet header, from `src` to `dst`.
    Ethernet {
        /// The interface's own MAC.
        src: [u8; 6],
        /// The next hop's MAC, resolved by neighbor discovery.
        dst: [u8; 6],
    },
    /// `DLT_NULL` (the BSD loopback): the address family, 4 bytes in host
    /// order ([`NULL_AF_INET6`]).
    Null,
    /// `DLT_RAW`: the packet as it is.
    Raw,
}

/// `AF_INET6` as a `DLT_NULL` header carries it, which is libpcap's number for
/// the OS, not the OS's own `AF_INET6`: 30 on Darwin, 28 on FreeBSD, and 24
/// elsewhere (NetBSD, OpenBSD, Npcap). These are the values
/// `send_ip_packet_eth` writes ("per libpcap/gencode.c").
pub const NULL_AF_INET6: u32 = if cfg!(target_vendor = "apple") {
    30
} else if cfg!(target_os = "freebsd") {
    28
} else {
    24
};

impl LinkFraming {
    /// The framing for a send handle whose datalink is `dlt`; `ethernet` gives the
    /// MACs, and is asked only for Ethernet. `None` for a datalink nmap cannot send
    /// on either (it `netutil_fatal`s there).
    ///
    /// # Errors
    /// Whatever `ethernet` returns.
    pub fn for_datalink(
        dlt: i32,
        ethernet: impl FnOnce() -> io::Result<([u8; 6], [u8; 6])>,
    ) -> io::Result<Option<LinkFraming>> {
        Ok(match dlt {
            1 => {
                let (src, dst) = ethernet()?;
                Some(LinkFraming::Ethernet { src, dst })
            }
            0 => Some(LinkFraming::Null),
            12 | 14 | 101 => Some(LinkFraming::Raw),
            _ => None,
        })
    }

    /// The framing for a loopback whose datalink is `dlt`, where there is no
    /// neighbor to discover: Linux's `lo` is Ethernet and takes any frame, so it
    /// gets the interface's own MAC (zero there) and a zero destination;
    /// FreeBSD's `lo0` is `DLT_NULL`. `None` for a datalink nmap does not send on.
    /// Shared by the IPv6 port scans and IPv6 OS detection.
    #[must_use]
    pub fn for_loopback(dlt: i32, src_mac: Option<[u8; 6]>) -> Option<LinkFraming> {
        LinkFraming::for_datalink(dlt, || Ok((src_mac.unwrap_or_default(), [0; 6])))
            .ok()
            .flatten()
    }

    /// `packet` (an IPv6 packet) in this framing.
    #[must_use]
    pub fn frame(&self, packet: &[u8]) -> Vec<u8> {
        match self {
            LinkFraming::Ethernet { src, dst } => crate::ndp::frame_ethernet(*dst, *src, packet),
            LinkFraming::Null => {
                let mut f = Vec::with_capacity(packet.len().saturating_add(4));
                f.extend_from_slice(&NULL_AF_INET6.to_ne_bytes());
                f.extend_from_slice(packet);
                f
            }
            LinkFraming::Raw => packet.to_vec(),
        }
    }
}

/// Wraps an L2 sender so each IPv6 packet handed to it goes out framed for its link
/// ([`LinkFraming`]).
///
/// This is what the IPv6 probe path needs and the IPv4 path does not. Linux has no
/// `IPV6_HDRINCL`: an `AF_INET6` raw socket does **not** treat a caller-supplied IPv6
/// header the way `IP_HDRINCL` treats an IPv4 one, so a full IPv6 packet — which is what
/// `core::build6` produces — cannot be handed to the kernel to route. It has to be
/// framed and injected at layer 2, which on Ethernet is why the driver first resolves
/// the next hop's MAC by neighbor discovery.
///
/// Generic over the inner sender, so the framing is exercised against a
/// [`MockSender`] in CI and only the injection underneath it needs privilege.
pub struct FramingSender<S> {
    inner: S,
    framing: LinkFraming,
}

impl<S: RawSender> FramingSender<S> {
    /// Frame everything sent through `inner` as `framing` says.
    pub fn new(inner: S, framing: LinkFraming) -> FramingSender<S> {
        FramingSender { inner, framing }
    }

    /// The framing every packet gets.
    #[must_use]
    pub fn framing(&self) -> LinkFraming {
        self.framing
    }
}

impl<S: RawSender> RawSender for FramingSender<S> {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        let frame = self.framing.frame(packet);
        self.inner.send(&frame)
    }
}

/// Frames each IPv6 packet for an Ethernet link to **its own destination's** next hop:
/// the target's MAC when it is on-link, the gateway's otherwise, as neighbor discovery
/// found them ([`crate::ndp::resolve_many`]). An IPv6 scan sends to many targets
/// through one handle, and they need not share a next hop, which a single
/// [`LinkFraming`] cannot express.
///
/// The destination is read from the packet's own header (bytes 24..40), as
/// [`RawIpv4Sender`] reads its routing destination. A packet to an address with no
/// MAC is refused (`AddrNotAvailable`), never framed to a guess.
pub struct NeighborSender<S> {
    inner: S,
    src_mac: [u8; 6],
    next_hop_macs: HashMap<[u8; 16], [u8; 6]>,
}

impl<S: RawSender> NeighborSender<S> {
    /// Frame from `src_mac`, to the next-hop MAC `next_hop_macs` gives each destination.
    pub fn new(inner: S, src_mac: [u8; 6], next_hop_macs: HashMap<[u8; 16], [u8; 6]>) -> Self {
        NeighborSender {
            inner,
            src_mac,
            next_hop_macs,
        }
    }
}

impl<S: RawSender> RawSender for NeighborSender<S> {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        let dst: [u8; 16] = packet
            .get(24..40)
            .and_then(|d| d.try_into().ok())
            .filter(|_| packet.first().is_some_and(|b| b >> 4 == 6))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "not an IPv6 packet"))?;
        let mac = self.next_hop_macs.get(&dst).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AddrNotAvailable,
                "no next-hop MAC for the destination",
            )
        })?;
        let frame = crate::ndp::frame_ethernet(*mac, self.src_mac, packet);
        self.inner.send(&frame)
    }
}

/// L2 injection via libpcap/Npcap (feature `pcap`).
#[cfg(feature = "pcap")]
pub mod pcap_sender;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_sender_records_frames() {
        let mut s = MockSender::default();
        assert_eq!(s.send(&[1, 2, 3]).unwrap(), 3);
        assert_eq!(s.send(&[9, 9]).unwrap(), 2);
        assert_eq!(s.sent, vec![vec![1, 2, 3], vec![9, 9]]);
    }

    #[test]
    fn eth_framing_wraps_every_packet() {
        const SRC: [u8; 6] = [0x00, 0x0c, 0x29, 0x1a, 0x2b, 0x3c];
        const DST: [u8; 6] = [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff];
        let framing = LinkFraming::Ethernet { src: SRC, dst: DST };
        let mut s = FramingSender::new(MockSender::default(), framing);
        assert_eq!(s.framing(), framing);
        // The reported length is the framed length, as the wire sees it.
        assert_eq!(s.send(&[0x60, 0x00]).unwrap(), 16);
        s.send(&[0xff]).unwrap();
        let sent = &s.inner.sent;
        assert_eq!(sent.len(), 2);
        for frame in sent {
            assert_eq!(&frame[0..6], &DST);
            assert_eq!(&frame[6..12], &SRC);
            assert_eq!(&frame[12..14], &[0x86, 0xdd]);
        }
        assert_eq!(&sent[0][14..], &[0x60, 0x00]);
    }

    // DLT_NULL: the family in host order, as send_ip_packet_eth writes it,
    // with libpcap's number for AF_INET6 (28 on FreeBSD).
    #[test]
    fn null_framing_prefixes_the_family_in_host_order() {
        let mut s = FramingSender::new(MockSender::default(), LinkFraming::Null);
        assert_eq!(s.send(&[0x60, 0x01, 0x02]).unwrap(), 7);
        let frame = &s.inner.sent[0];
        assert_eq!(&frame[..4], &NULL_AF_INET6.to_ne_bytes());
        assert_eq!(&frame[4..], &[0x60, 0x01, 0x02]);
        if cfg!(target_os = "freebsd") {
            assert_eq!(NULL_AF_INET6, 28);
        } else if cfg!(target_vendor = "apple") {
            assert_eq!(NULL_AF_INET6, 30);
        } else {
            assert_eq!(NULL_AF_INET6, 24);
        }
    }

    #[test]
    fn raw_framing_sends_the_packet_as_it_is() {
        let mut s = FramingSender::new(MockSender::default(), LinkFraming::Raw);
        assert_eq!(s.send(&[0x60, 9]).unwrap(), 2);
        assert_eq!(s.inner.sent, vec![vec![0x60, 9]]);
    }

    // The datalinks send_ip_packet_eth frames; anything else is refused, and
    // only Ethernet asks for MACs.
    #[test]
    fn framing_by_datalink() {
        let macs = || Ok(([1; 6], [2; 6]));
        let no_macs =
            || -> io::Result<([u8; 6], [u8; 6])> { panic!("asked for MACs off Ethernet") };
        assert_eq!(
            LinkFraming::for_datalink(1, macs).unwrap(),
            Some(LinkFraming::Ethernet {
                src: [1; 6],
                dst: [2; 6]
            })
        );
        assert_eq!(
            LinkFraming::for_datalink(0, no_macs).unwrap(),
            Some(LinkFraming::Null)
        );
        for raw in [12, 14, 101] {
            assert_eq!(
                LinkFraming::for_datalink(raw, no_macs).unwrap(),
                Some(LinkFraming::Raw)
            );
        }
        // DLT_LOOP (108) carries the family in network order; nmap does not
        // send on it, and neither does the port.
        assert_eq!(LinkFraming::for_datalink(108, no_macs).unwrap(), None);
        // An Ethernet link whose MACs cannot be had is an error, not a guess.
        let err = LinkFraming::for_datalink(1, || Err(io::Error::other("no ND reply")));
        assert!(err.is_err());
    }

    // A loopback has no neighbor: Linux's `lo` (Ethernet) gets its own MAC and a
    // zero destination, FreeBSD's `lo0` its DLT_NULL family; nothing else is sent on.
    #[test]
    fn loopback_framing_by_datalink() {
        let mac = Some([0, 0, 0, 0, 0, 7]);
        assert_eq!(
            LinkFraming::for_loopback(1, mac),
            Some(LinkFraming::Ethernet {
                src: [0, 0, 0, 0, 0, 7],
                dst: [0; 6]
            })
        );
        assert_eq!(
            LinkFraming::for_loopback(1, None),
            Some(LinkFraming::Ethernet {
                src: [0; 6],
                dst: [0; 6]
            })
        );
        assert_eq!(LinkFraming::for_loopback(0, mac), Some(LinkFraming::Null));
        assert_eq!(LinkFraming::for_loopback(12, None), Some(LinkFraming::Raw));
        assert_eq!(LinkFraming::for_loopback(108, mac), None);
    }

    // Each packet goes to its own destination's next hop, from our MAC; a destination
    // with none, or a packet that is not IPv6, is refused and nothing is sent.
    #[test]
    fn neighbor_sender_frames_each_packet_for_its_destination() {
        const US: [u8; 6] = [2, 0, 0, 0, 0, 1];
        let a = [0x20, 1, 0xd, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        let mut b = a;
        b[15] = 3;
        let mut c = a;
        c[15] = 4;
        let ip6 = |dst: [u8; 16]| {
            let mut p = vec![0x60, 0, 0, 0, 0, 0, 59, 64];
            p.extend_from_slice(&[0; 16]);
            p.extend_from_slice(&dst);
            p
        };
        // b is off-link: its next hop is the gateway's MAC, shared with c.
        let macs = HashMap::from([(a, [0xa; 6]), (b, [0xf; 6]), (c, [0xf; 6])]);
        let mut s = NeighborSender::new(MockSender::default(), US, macs);
        assert_eq!(s.send(&ip6(a)).unwrap(), 14 + 40);
        s.send(&ip6(b)).unwrap();
        s.send(&ip6(c)).unwrap();
        let sent = &s.inner.sent;
        for (frame, (dst, mac)) in sent
            .iter()
            .zip([(a, [0xa; 6]), (b, [0xf; 6]), (c, [0xf; 6])])
        {
            assert_eq!(&frame[0..6], &mac);
            assert_eq!(&frame[6..12], &US);
            assert_eq!(&frame[12..14], &[0x86, 0xdd]);
            assert_eq!(&frame[14..], &ip6(dst)[..]);
        }
        let mut stranger = a;
        stranger[15] = 9;
        let err = s.send(&ip6(stranger)).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::AddrNotAvailable);
        let mut v4 = ip6(a);
        v4[0] = 0x45;
        assert_eq!(s.send(&v4).unwrap_err().kind(), io::ErrorKind::InvalidInput);
        assert_eq!(
            s.send(&[0x60; 30]).unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        assert_eq!(s.inner.sent.len(), 3, "nothing sent for a refused packet");
    }

    // Privileged loopback send: build a real UDP/IPv4 packet and transmit it to
    // 127.0.0.1. Requires CAP_NET_RAW, so it self-skips when unprivileged (CI).
    #[test]
    #[cfg_attr(
        miri,
        ignore = "creates a real raw socket; miri isolation blocks socket()"
    )]
    fn raw_send_to_loopback_when_privileged() {
        let mut sender = match RawIpv4Sender::new() {
            Ok(s) => s,
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                eprintln!("skipping privileged send test: no CAP_NET_RAW");
                return;
            }
            Err(e) => panic!("unexpected error: {e}"),
        };
        let spec = nmap_core::build::Ipv4Spec::new([127, 0, 0, 1], [127, 0, 0, 1], 64, 0x1234);
        let pkt = nmap_core::build::build_udp_raw(&spec, 40000, 53, b"ping").unwrap();
        let n = sender
            .send(&pkt)
            .expect("send to loopback should succeed as root");
        assert_eq!(n, pkt.len());
    }
}
