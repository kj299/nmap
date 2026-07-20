//! Live libpcap/Npcap capture source (feature `pcap`).
//!
//! A thin [`super::PacketSource`] over the `pcap` crate, which wraps libpcap on Unix
//! and Npcap on Windows — the same capture library nmap uses. The crate's FFI is
//! audited upstream, so this backend adds **no first-party `unsafe`**. It is
//! feature-gated because it needs libpcap/Npcap headers at build time, and is
//! validated on a privileged host (capture requires elevated rights).
//!
//! The handle is opened in **timeout mode**: `next_frame` returns `Ok(None)` when the
//! read timeout elapses, keeping the capture thread responsive to shutdown (the
//! [`super::PacketSource`] contract).

use super::PacketSource;
use std::io;

/// A live capture on a named interface, optionally filtered by a BPF program.
pub struct PcapSource {
    cap: pcap::Capture<pcap::Active>,
}

impl PcapSource {
    /// Open a live capture on `iface` with the given snap length and read timeout.
    ///
    /// `bpf` is an optional BPF filter (e.g. `"tcp and src host 10.0.0.2"`) applied in
    /// the kernel so only matching frames reach userspace.
    ///
    /// # Errors
    /// Returns an error if the device cannot be opened (e.g. insufficient privilege) or
    /// the filter fails to compile.
    pub fn open(
        iface: &str,
        snaplen: i32,
        read_timeout_ms: i32,
        bpf: Option<&str>,
    ) -> io::Result<PcapSource> {
        let dev = pcap::Capture::from_device(iface)
            .map_err(to_io)?
            .snaplen(snaplen)
            .timeout(read_timeout_ms)
            .immediate_mode(true);
        let mut cap = dev.open().map_err(to_io)?;
        if let Some(filter) = bpf {
            cap.filter(filter, true).map_err(to_io)?;
        }
        Ok(PcapSource { cap })
    }
}

impl PacketSource for PcapSource {
    fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.cap.next_packet() {
            Ok(pkt) => Ok(Some(pkt.data.to_vec())),
            // A read timeout is the expected idle signal, not an error.
            Err(pcap::Error::TimeoutExpired) => Ok(None),
            Err(e) => Err(to_io(e)),
        }
    }
}

fn to_io(e: pcap::Error) -> io::Error {
    io::Error::other(e.to_string())
}
