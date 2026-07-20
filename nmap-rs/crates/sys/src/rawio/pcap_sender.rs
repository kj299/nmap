//! L2 packet injection via libpcap/Npcap (feature `pcap`).
//!
//! Wraps the `pcap` crate's `sendpacket` — the same L2 injection nmap uses when it
//! frames its own Ethernet header, and the only raw-send path available on Windows
//! (Npcap). The crate's FFI is audited upstream, so this backend adds **no
//! first-party `unsafe`**. Feature-gated (needs libpcap/Npcap at build time) and
//! validated on a privileged host.

use super::RawSender;
use std::io;

/// An open capture handle used purely for sending frames on a named interface.
pub struct PcapSender {
    cap: pcap::Capture<pcap::Active>,
}

impl PcapSender {
    /// Open `iface` for L2 injection.
    ///
    /// # Errors
    /// Returns an error if the device cannot be opened (e.g. insufficient privilege).
    pub fn open(iface: &str) -> io::Result<PcapSender> {
        let cap = pcap::Capture::from_device(iface)
            .map_err(to_io)?
            .open()
            .map_err(to_io)?;
        Ok(PcapSender { cap })
    }
}

impl RawSender for PcapSender {
    fn send(&mut self, packet: &[u8]) -> io::Result<usize> {
        self.cap.sendpacket(packet).map_err(to_io)?;
        Ok(packet.len())
    }
}

fn to_io(e: pcap::Error) -> io::Error {
    io::Error::other(e.to_string())
}
