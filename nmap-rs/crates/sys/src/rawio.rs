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
