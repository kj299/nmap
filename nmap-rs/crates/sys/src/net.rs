//! Async network I/O for the unprivileged connect scan — the `sys`-side
//! primitives the (pure) scan engine drives. Built on tokio's safe socket API,
//! so this module holds **no `unsafe`**.
//!
//! Two primitives:
//!   - [`tcp_connect`] — one TCP connect probe, mapped to a port state/reason
//!     the way nmap's connect scan (`scan_engine_connect.cc`) interprets it:
//!     handshake completes → **open**; RST/refused → **closed**; timeout or
//!     unreachable → **filtered**.
//!   - [`resolve_host`] — forward DNS via the system resolver (tokio's
//!     `getaddrinfo` pool), the MVP's resolution path.

use std::io;
use std::net::{IpAddr, SocketAddr};
use std::time::{Duration, Instant};

use nmap_core::model::{PortState, Reason};

/// Outcome of a single TCP connect probe against one `addr`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConnectResult {
    pub state: PortState,
    pub reason: Reason,
    /// Measured round-trip time when the probe resolved to open or closed
    /// (`None` for a filtered/timed-out probe, which has no meaningful RTT).
    pub rtt: Option<Duration>,
}

/// Interpret a connect attempt's raw outcome into a [`ConnectResult`] — the
/// pure decision logic, split out from the I/O so every branch is unit-testable
/// without real network timing.
///
/// `connect` is `None` if the timeout fired, else `Some(Ok(()))` for a completed
/// handshake or `Some(Err(kind))` for a connect error. Only `ConnectionRefused`
/// is a definite **closed**; a timeout or any other error is **filtered**.
/// (Kept to `std`-stable error kinds so it holds on the declared MSRV.)
fn verdict(connect: Option<Result<(), io::ErrorKind>>, elapsed: Duration) -> ConnectResult {
    match connect {
        // Handshake completed → open; the connect itself is a real round-trip.
        Some(Ok(())) => ConnectResult {
            state: PortState::Open,
            reason: Reason::ConnAccept,
            rtt: Some(elapsed),
        },
        // Explicit refusal (RST) → closed; also a real round-trip.
        Some(Err(io::ErrorKind::ConnectionRefused)) => ConnectResult {
            state: PortState::Closed,
            reason: Reason::ConnRefused,
            rtt: Some(elapsed),
        },
        // Timeout (None) or any other error → no useful answer → filtered.
        _ => ConnectResult {
            state: PortState::Filtered,
            reason: Reason::NoResponse,
            rtt: None,
        },
    }
}

/// Probe one TCP port by attempting a full connect, bounded by `timeout`.
///
/// - Handshake completes → **open** (`syn-ack`); the socket is dropped
///   immediately (we only needed to confirm the handshake).
/// - `ConnectionRefused` → **closed** (`conn-refused`).
/// - `timeout` elapsed, or any other error → **filtered** (`no-response`).
///
/// Never panics; all outcomes map to a [`ConnectResult`].
pub async fn tcp_connect(addr: SocketAddr, timeout: Duration) -> ConnectResult {
    let start = Instant::now();
    let connect = match tokio::time::timeout(timeout, tokio::net::TcpStream::connect(addr)).await {
        Ok(Ok(_stream)) => Some(Ok(())),
        Ok(Err(e)) => Some(Err(e.kind())),
        Err(_elapsed) => None,
    };
    verdict(connect, start.elapsed())
}

/// Resolve `host` to its IP addresses via the system resolver, preserving order
/// and dropping duplicates. `host` may itself be an IP literal (resolves to
/// itself). The port is irrelevant here (we only want addresses).
pub async fn resolve_host(host: &str) -> io::Result<Vec<IpAddr>> {
    let mut out = Vec::new();
    for sockaddr in tokio::net::lookup_host((host, 0u16)).await? {
        let ip = sockaddr.ip();
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    Ok(out)
}

/// Outcome of a service-detection probe: connect, optionally send bytes, then
/// read whatever the port volunteers within a window.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BannerResult {
    /// The TCP handshake completed.
    pub connected: bool,
    /// Bytes read from the port (capped at the caller's `max_bytes`).
    pub data: Vec<u8>,
    /// The peer closed the connection (EOF) during the read window.
    pub closed: bool,
    /// Wall-clock time from connect start to end of the read window.
    pub elapsed: Duration,
}

/// Connect to `addr`, optionally send `send`, then read up to `max_bytes` of
/// banner within `read_timeout`. Keeps the stream for the read (unlike
/// [`tcp_connect`], which drops it). Total, non-panicking: connect failure yields
/// `connected == false`; any read error or the timeout simply ends the window.
///
/// This is the I/O primitive `nmap-core::servicescan` drives — one probe send +
/// response read. Built on tokio's safe socket API — **no `unsafe`**.
pub async fn grab_banner(
    addr: SocketAddr,
    send: &[u8],
    connect_timeout: Duration,
    read_timeout: Duration,
    max_bytes: usize,
) -> BannerResult {
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    let start = Instant::now();
    let mut stream =
        match tokio::time::timeout(connect_timeout, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(s)) => s,
            _ => {
                return BannerResult {
                    connected: false,
                    data: Vec::new(),
                    closed: false,
                    elapsed: start.elapsed(),
                }
            }
        };

    // Send the probe payload (if any), bounded by the read window.
    if !send.is_empty()
        && tokio::time::timeout(read_timeout, stream.write_all(send))
            .await
            .map(|r| r.is_ok())
            != Ok(true)
    {
        // Write failed or timed out — still try to read whatever's there.
    }

    // Read until the window closes, the peer closes, or we hit the byte cap.
    let deadline = tokio::time::Instant::now()
        .checked_add(read_timeout)
        .unwrap_or_else(tokio::time::Instant::now);
    let mut data: Vec<u8> = Vec::new();
    let mut closed = false;
    let mut buf = [0u8; 4096];
    while data.len() < max_bytes {
        match tokio::time::timeout_at(deadline, stream.read(&mut buf)).await {
            Ok(Ok(0)) => {
                closed = true;
                break;
            }
            Ok(Ok(n)) => {
                let room = max_bytes.saturating_sub(data.len());
                data.extend_from_slice(&buf[..n.min(room)]);
            }
            // Read error or window elapsed — stop with whatever we have.
            Ok(Err(_)) | Err(_) => break,
        }
    }

    BannerResult {
        connected: true,
        data,
        closed,
        elapsed: start.elapsed(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn verdict_covers_every_branch() {
        let rtt = Duration::from_millis(5);
        // Handshake completed → open, with an RTT.
        let open = verdict(Some(Ok(())), rtt);
        assert_eq!(
            (open.state, open.reason),
            (PortState::Open, Reason::ConnAccept)
        );
        assert_eq!(open.rtt, Some(rtt));
        // Refused → closed, with an RTT.
        let closed = verdict(Some(Err(io::ErrorKind::ConnectionRefused)), rtt);
        assert_eq!(
            (closed.state, closed.reason),
            (PortState::Closed, Reason::ConnRefused)
        );
        assert_eq!(closed.rtt, Some(rtt));
        // Timeout → filtered, no RTT.
        let timed_out = verdict(None, rtt);
        assert_eq!(
            (timed_out.state, timed_out.reason),
            (PortState::Filtered, Reason::NoResponse)
        );
        assert!(timed_out.rtt.is_none());
        // Any other error → filtered, no RTT.
        for kind in [
            io::ErrorKind::PermissionDenied,
            io::ErrorKind::ConnectionReset,
        ] {
            let r = verdict(Some(Err(kind)), rtt);
            assert_eq!(r.state, PortState::Filtered);
            assert!(r.rtt.is_none());
        }
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn open_port_is_detected() {
        // A bound listener accepts the handshake from the backlog even without
        // calling accept(), so connect() succeeds → open.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        let r = tcp_connect(addr, Duration::from_secs(2)).await;
        assert_eq!(r.state, PortState::Open);
        assert_eq!(r.reason, Reason::ConnAccept);
        assert!(r.rtt.is_some());
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn closed_port_is_refused() {
        // Bind then drop to obtain a port that is (almost certainly) now free;
        // connecting to it on loopback yields an immediate ECONNREFUSED.
        let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0))
            .await
            .unwrap();
        let addr = listener.local_addr().unwrap();
        drop(listener);
        let r = tcp_connect(addr, Duration::from_secs(2)).await;
        assert_eq!(r.state, PortState::Closed);
        assert_eq!(r.reason, Reason::ConnRefused);
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn resolve_ip_literal_is_identity() {
        let ips = resolve_host("127.0.0.1").await.unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::LOCALHOST)]);
    }

    #[cfg_attr(miri, ignore = "miri cannot execute real network syscalls")]
    #[tokio::test]
    async fn resolve_localhost_yields_loopback() {
        let ips = resolve_host("localhost").await.unwrap();
        assert!(
            ips.iter().any(|ip| ip.is_loopback()),
            "expected a loopback address, got {ips:?}"
        );
    }

    // The timeout → filtered branch is covered deterministically by
    // `verdict_covers_every_branch` (the `None` case); a real-network timeout
    // test is intentionally omitted — connect timing is environment-dependent
    // and this sandbox even completes connects to non-routable addresses.
}
