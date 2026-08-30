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

/// Wraps an L2 sender so each packet handed to it goes out inside an Ethernet frame.
///
/// This is what the IPv6 probe path needs and the IPv4 path does not. Linux has no
/// `IPV6_HDRINCL`: an `AF_INET6` raw socket does **not** treat a caller-supplied IPv6
/// header the way `IP_HDRINCL` treats an IPv4 one, so a full IPv6 packet — which is what
/// `core::build6` produces — cannot be handed to the kernel to route. It has to be
/// framed and injected at layer 2, which is why the driver first resolves the next hop's
/// MAC by neighbor discovery.
///
/// Generic over the inner sender, so the framing is exercised against a
/// [`MockSender`] in CI and only the injection underneath it needs privilege.
pub struct EthFramingSender<S> {
    inner: S,
    dst_mac: [u8; 6],
    src_mac: [u8; 6],
}

impl<S: RawSender> EthFramingSender<S> {
    /// Frame everything sent through `inner` from `src_mac` to `dst_mac`.
    pub fn new(inner: S, src_mac: [u8; 6], dst_mac: [u8; 6]) -> EthFramingSender<S> {
        EthFramingSender {
            inner,
            dst_mac,
            src_mac,
        }
    }

    /// The destination MAC every frame is addressed to — the resolved next hop.
    #[must_use]
    pub fn dst_mac(&self) -> [u8; 6] {
        self.dst_mac
    }
}

impl<S: RawSender> RawSender for EthFramingSender<S> {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        let frame = crate::ndp::frame_ethernet(self.dst_mac, self.src_mac, packet);
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
        let mut s = EthFramingSender::new(MockSender::default(), SRC, DST);
        assert_eq!(s.dst_mac(), DST);
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
        assert_eq!(&sent[1][14..], &[0xff]);
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "creates a real raw socket; miri isolation blocks socket()"
    )]
    fn raw_sender_rejects_short_packet() {
        // The length guard lives in `send`, which needs a real socket, so this only
        // runs when privileged; unprivileged hosts (CI) skip it.
        match RawIpv4Sender::new() {
            Ok(mut s) => {
                let err = s.send(&[0u8; 10]).unwrap_err();
                assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
            }
            Err(e) if e.kind() == io::ErrorKind::PermissionDenied => {
                // Unprivileged (e.g. CI): the raw socket can't be opened. Skip.
                eprintln!("skipping raw-socket test: no CAP_NET_RAW");
            }
            Err(e) => panic!("unexpected error opening raw socket: {e}"),
        }
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
