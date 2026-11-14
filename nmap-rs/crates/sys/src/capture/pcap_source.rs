//! Live libpcap/Npcap capture source (feature `pcap`).
//!
//! A thin [`super::PacketSource`] over the `pcap` crate, which wraps libpcap on Unix
//! and Npcap on Windows — the same capture library nmap uses. The crate's FFI is
//! audited upstream, so this backend adds **no first-party `unsafe`**. It is
//! feature-gated because it needs libpcap/Npcap headers at build time, and is
//! validated on a privileged host (capture requires elevated rights).
//!
//! The handle is opened in **non-blocking mode**: `next_frame` returns `Ok(None)`
//! immediately when no packet is ready, keeping the capture thread responsive to
//! shutdown (the [`super::PacketSource`] contract). This matters because libpcap on
//! Linux does **not** reliably honour a blocking read timeout when the link is idle —
//! a blocking read there can hang until a packet arrives, which would deadlock the
//! capture thread's `Drop`-time join. nmap sets the handle non-blocking and polls for
//! the same reason; the small idle sleep below bounds CPU without adding latency on
//! the hot (packet-present) path.

use super::PacketSource;
use std::io;
use std::time::Duration;

/// How long to sleep after a non-blocking read finds no packet, before looping. Small
/// enough that shutdown is prompt, large enough that an idle link doesn't busy-spin.
const IDLE_POLL_SLEEP: Duration = Duration::from_micros(200);

/// A live capture on a named interface, optionally filtered by a BPF program.
pub struct PcapSource {
    cap: pcap::Capture<pcap::Active>,
    /// Link-header bytes removed from the front of each frame.
    strip: usize,
    /// Whether what is left starts with an Ethernet header.
    eth: bool,
}

/// What a datalink puts before the network header, as nmap's
/// `datalink_offset` (`libnetutil/netutil.cc:3200`) reads it: Ethernet is kept
/// whole for the parsers (`Some((0, true))`); BSD loopback's 4-byte address
/// family (`DLT_NULL`, and OpenBSD's `DLT_LOOP`) is stripped; a raw-IP link
/// has nothing to strip. FreeBSD's `lo0` is `DLT_NULL`, where Linux's `lo`
/// is Ethernet with zeroed addresses (docs/FREEBSD-ANALYSIS.md, F1/F2).
/// `None` for any other datalink, which the scans do not parse.
#[must_use]
pub fn link_layer(dlt: i32) -> Option<(usize, bool)> {
    match dlt {
        1 => Some((0, true)),        // DLT_EN10MB
        0 | 108 => Some((4, false)), // DLT_NULL, DLT_LOOP
        // DLT_RAW is 12 on most systems and 14 on OpenBSD; libpcap may also
        // report LINKTYPE_RAW, 101.
        12 | 14 | 101 => Some((0, false)),
        _ => None,
    }
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
        PcapSource::open_with(iface, snaplen, read_timeout_ms, bpf, false)
    }

    /// [`PcapSource::open`], promiscuous when `promisc` is set: a scan under `-S`
    /// listens for replies to an address that may not be this host's, as C opens its
    /// capture then (`scan_engine_raw.cc:869`).
    ///
    /// # Errors
    /// As [`PcapSource::open`].
    pub fn open_with(
        iface: &str,
        snaplen: i32,
        read_timeout_ms: i32,
        bpf: Option<&str>,
        promisc: bool,
    ) -> io::Result<PcapSource> {
        let dev = pcap::Capture::from_device(iface)
            .map_err(to_io)?
            .snaplen(snaplen)
            .timeout(read_timeout_ms)
            .promisc(promisc)
            .immediate_mode(true);
        let mut cap = dev.open().map_err(to_io)?;
        if let Some(filter) = bpf {
            cap.filter(filter, true).map_err(to_io)?;
        }
        let dlt = cap.get_datalink().0;
        let (strip, eth) = link_layer(dlt).ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::Unsupported,
                format!("{iface}: unsupported datalink {dlt}"),
            )
        })?;
        // Non-blocking so `next_packet` never hangs an idle link (see module docs).
        let cap = cap.setnonblock().map_err(to_io)?;
        Ok(PcapSource { cap, strip, eth })
    }
}

impl PacketSource for PcapSource {
    fn next_frame(&mut self) -> io::Result<Option<Vec<u8>>> {
        match self.cap.next_packet() {
            // A frame shorter than its link header carries nothing: an empty
            // frame, which every parser refuses.
            Ok(pkt) => Ok(Some(
                pkt.data.get(self.strip..).unwrap_or_default().to_vec(),
            )),
            // No packet ready (non-blocking): sleep briefly so an idle link neither
            // busy-spins nor hangs, then report "no frame this round".
            Err(pcap::Error::TimeoutExpired) => {
                std::thread::sleep(IDLE_POLL_SLEEP);
                Ok(None)
            }
            Err(e) => Err(to_io(e)),
        }
    }

    fn eth_included(&self) -> bool {
        self.eth
    }
}

fn to_io(e: pcap::Error) -> io::Error {
    io::Error::other(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::link_layer;

    /// nmap's `datalink_offset` for the links the scans meet: Ethernet kept
    /// whole, BSD loopback's 4-byte family stripped (FreeBSD's `lo0`), a raw-IP
    /// link (tun, WireGuard) passed as it is; anything else refused rather than
    /// misparsed.
    #[test]
    fn datalinks_strip_what_nmap_strips() {
        assert_eq!(link_layer(1), Some((0, true)), "DLT_EN10MB");
        assert_eq!(link_layer(0), Some((4, false)), "DLT_NULL");
        assert_eq!(link_layer(108), Some((4, false)), "DLT_LOOP");
        for raw in [12, 14, 101] {
            assert_eq!(link_layer(raw), Some((0, false)), "DLT_RAW {raw}");
        }
        for other in [6, 9, 105, 113, 127, 228] {
            assert_eq!(link_layer(other), None, "datalink {other}");
        }
    }
}
