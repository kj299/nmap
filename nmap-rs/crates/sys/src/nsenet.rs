//! The network NSE scripts' sockets use: [`ScriptNet`] over tokio, in the
//! role nsock plays for nmap.
//!
//! Operations are tokio tasks on a current-thread runtime, which runs only
//! while the engine waits in [`ScriptNet::poll`] — the scheduler's
//! `loop(50)`, nsock's `nsock_loop`. Each task reports its operation's end
//! on a channel, and `poll` hands the endings back. What the operations do
//! follows nsock:
//!
//! - a read returns whatever arrives; `Lines(n)` and `Bytes(n)` read until
//!   that many newlines or bytes have come, and a time-out or end of file
//!   after some data succeeds with what came;
//! - a UDP receive waits through the errors an ICMP unreachable raises on a
//!   connected socket, as nsock does, so a silent peer times out;
//! - closing a socket drops its pending operations, which never complete;
//! - one read returns at most [`MAX_READ`] bytes, where nsock has no bound.
//!
//! An SSL socket ([`crate::tls`]) reads as 7.94's nsock reads it over
//! OpenSSL, measured on the `io-*` fixtures (`m65_tls_golden.txt`): a read
//! that meets the end of the connection succeeds with what it has, or else
//! is `EOF`; every later read is `ERROR` at once if the peer closed TCP
//! without a `close_notify`, and waits out its time-out if it sent one
//! (nsock's edge-triggered poll never sees the socket readable again). A
//! TLS error is `ERROR`, losing what the read had collected, as `SSL_read`'s
//! failure does. Closing an SSL socket sends a `close_notify` if the socket
//! takes it at once (`SSL_shutdown` in `nsock_iod_delete`).
//!
//! There is no `unsafe` here: tokio's socket API is safe.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nmap_core::nse::net::{
    Completion, Family, NetProto, NetStatus, OpId, ReadMode, ScriptNet, SockId,
};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};

use crate::tls::{client_config, server_name, ReadEvent, TlsStream};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

#[derive(Clone)]
enum Sock {
    Tcp(Arc<TcpStream>),
    Udp(Arc<UdpSocket>),
    /// A TLS connection.
    Tls(Arc<TlsSock>),
    /// A TCP connection whose handshake failed or is under way: an SSL
    /// socket to `get_ssl_certificate` (nsock created its `SSL` once TCP
    /// connected), unusable for I/O.
    TlsDown(Arc<TcpStream>),
}

/// How a TLS connection's end was seen by a read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TlsEnd {
    /// The peer sent `close_notify`.
    Notify,
    /// The peer closed TCP without one.
    Abrupt,
}

struct TlsSock {
    stream: TlsStream,
    /// Set by the read that met the end.
    ended: Mutex<Option<TlsEnd>>,
}

type Socks = Arc<Mutex<HashMap<SockId, Sock>>>;

/// The network over tokio.
pub struct TokioNet {
    rt: tokio::runtime::Runtime,
    tx: mpsc::UnboundedSender<(OpId, Completion)>,
    rx: mpsc::UnboundedReceiver<(OpId, Completion)>,
    socks: Socks,
    /// Each pending operation's task, and the socket it is on.
    tasks: HashMap<OpId, (Option<SockId>, AbortHandle)>,
}

impl TokioNet {
    /// A network with no sockets yet; `None` if the runtime cannot start.
    pub fn new() -> Option<Self> {
        let rt = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .ok()?;
        let (tx, rx) = mpsc::unbounded_channel();
        Some(Self {
            rt,
            tx,
            rx,
            socks: Arc::new(Mutex::new(HashMap::new())),
            tasks: HashMap::new(),
        })
    }

    fn sock(&self, id: SockId) -> Option<Sock> {
        self.socks.lock().ok()?.get(&id).cloned()
    }

    fn spawn<F>(&mut self, op: OpId, on: Option<SockId>, f: F)
    where
        F: std::future::Future<Output = Completion> + Send + 'static,
    {
        let tx = self.tx.clone();
        let handle = self.rt.spawn(async move {
            let c = f.await;
            let _ = tx.send((op, c));
        });
        self.tasks.insert(op, (on, handle.abort_handle()));
    }
}

/// `timeout` as nsock applies it: `None` waits for ever.
async fn within<T>(t: Option<Duration>, f: impl std::future::Future<Output = T>) -> Option<T> {
    match t {
        Some(d) => tokio::time::timeout(d, f).await.ok(),
        None => Some(f.await),
    }
}

fn unspecified(v6: bool) -> SocketAddr {
    if v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    }
}

async fn tcp_connect(local: Option<SocketAddr>, remote: SocketAddr) -> io::Result<TcpStream> {
    let s = if remote.is_ipv6() {
        TcpSocket::new_v6()?
    } else {
        TcpSocket::new_v4()?
    };
    if let Some(l) = local {
        s.bind(l)?;
    }
    s.connect(remote).await
}

/// The most one read collects before it returns what it has, satisfied or
/// not (`nse-read-size-cap`): nsock buffers a `receive_lines` or
/// `receive_bytes` without bound, so a service streaming without a newline
/// grows nmap's memory for as long as the time-out allows.
pub const MAX_READ: usize = 4 << 20;

/// Whether `buf` holds what `mode` waits for, or as much as one read may.
fn satisfied(mode: ReadMode, buf: &[u8]) -> bool {
    if buf.len() >= MAX_READ {
        return true;
    }
    match mode {
        ReadMode::Any => !buf.is_empty(),
        // A count of zero is met by any data.
        ReadMode::Lines(n) => {
            let lines = buf.iter().filter(|&&b| b == b'\n').count();
            !buf.is_empty() && u64::try_from(lines).unwrap_or(u64::MAX) >= n
        }
        ReadMode::Bytes(n) => !buf.is_empty() && u64::try_from(buf.len()).unwrap_or(u64::MAX) >= n,
    }
}

async fn read_tcp(s: Arc<TcpStream>, mode: ReadMode, t: Option<Duration>) -> Completion {
    let mut buf: Vec<u8> = Vec::new();
    let reading = async {
        let mut chunk = vec![0u8; 8192];
        loop {
            if s.readable().await.is_err() {
                return Some(NetStatus::Error);
            }
            match s.try_read(&mut chunk) {
                Ok(0) => return Some(NetStatus::Eof),
                Ok(n) => {
                    buf.extend_from_slice(&chunk[..n]);
                    if satisfied(mode, &buf) {
                        return None;
                    }
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(_) => return Some(NetStatus::Error),
            }
        }
    };
    let ended = within(t, reading).await;
    match ended {
        // Satisfied.
        Some(None) => Completion::Data(buf),
        // End of file, an error, or a time-out: what came, if anything did.
        Some(Some(st)) if buf.is_empty() => Completion::Failed(st),
        None if buf.is_empty() => Completion::Failed(NetStatus::Timeout),
        _ => Completion::Data(buf),
    }
}

async fn read_udp(s: Arc<UdpSocket>, t: Option<Duration>) -> Completion {
    let receiving = async {
        let mut d = vec![0u8; 65536];
        loop {
            match s.recv(&mut d).await {
                Ok(n) => {
                    d.truncate(n);
                    return d;
                }
                // An ICMP unreachable reported on a connected socket: nsock
                // keeps waiting.
                Err(_) => continue,
            }
        }
    };
    match within(t, receiving).await {
        Some(d) => Completion::Data(d),
        None => Completion::Failed(NetStatus::Timeout),
    }
}

async fn read_tls(s: Arc<TlsSock>, mode: ReadMode, t: Option<Duration>) -> Completion {
    let ended = s.ended.lock().ok().and_then(|e| *e);
    match ended {
        Some(TlsEnd::Abrupt) => return Completion::Failed(NetStatus::Error),
        Some(TlsEnd::Notify) => {
            // Nothing will make the socket readable to nsock again.
            within(t, std::future::pending::<()>()).await;
            return Completion::Failed(NetStatus::Timeout);
        }
        None => {}
    }
    let mut buf: Vec<u8> = Vec::new();
    let reading = async {
        loop {
            match s.stream.read().await {
                ReadEvent::Data(d) => {
                    buf.extend_from_slice(&d);
                    if satisfied(mode, &buf) {
                        return None;
                    }
                }
                ReadEvent::Closed { notify } => {
                    if let Ok(mut e) = s.ended.lock() {
                        *e = Some(if notify {
                            TlsEnd::Notify
                        } else {
                            TlsEnd::Abrupt
                        });
                    }
                    return Some(NetStatus::Eof);
                }
                ReadEvent::Error => return Some(NetStatus::Error),
            }
        }
    };
    match within(t, reading).await {
        Some(None) => Completion::Data(buf),
        // `SSL_read` failed: what the read had is lost.
        Some(Some(NetStatus::Error)) => Completion::Failed(NetStatus::Error),
        Some(Some(st)) if buf.is_empty() => Completion::Failed(st),
        None if buf.is_empty() => Completion::Failed(NetStatus::Timeout),
        _ => Completion::Data(buf),
    }
}

/// The handshake over a connected `tcp`, recording the socket as an SSL
/// socket first; the completion it ends with.
async fn handshake(
    socks: Socks,
    sock: SockId,
    tcp: Arc<TcpStream>,
    sni: Option<Vec<u8>>,
) -> Completion {
    if let Ok(mut m) = socks.lock() {
        m.insert(sock, Sock::TlsDown(tcp.clone()));
    }
    let peer = match tcp.peer_addr() {
        Ok(a) => a.ip(),
        Err(_) => return Completion::Failed(NetStatus::Error),
    };
    let name = server_name(sni.as_deref(), peer);
    match TlsStream::handshake(tcp, client_config(), name).await {
        Ok(stream) => {
            if let Ok(mut m) = socks.lock() {
                m.insert(
                    sock,
                    Sock::Tls(Arc::new(TlsSock {
                        stream,
                        ended: Mutex::new(None),
                    })),
                );
            }
            Completion::Done
        }
        Err(()) => Completion::Failed(NetStatus::Error),
    }
}

impl ScriptNet for TokioNet {
    fn connect(
        &mut self,
        op: OpId,
        sock: SockId,
        proto: NetProto,
        local: Option<SocketAddr>,
        remote: SocketAddr,
        timeout: Option<Duration>,
    ) {
        self.close(sock);
        let socks = self.socks.clone();
        self.spawn(op, Some(sock), async move {
            let made = match proto {
                NetProto::Tcp => match within(timeout, tcp_connect(local, remote)).await {
                    None => return Completion::Failed(NetStatus::Timeout),
                    Some(Err(_)) => return Completion::Failed(NetStatus::Error),
                    Some(Ok(s)) => Sock::Tcp(Arc::new(s)),
                },
                NetProto::Udp => {
                    let bind = local.unwrap_or_else(|| unspecified(remote.is_ipv6()));
                    let u = match UdpSocket::bind(bind).await {
                        Ok(u) => u,
                        Err(_) => return Completion::Failed(NetStatus::Error),
                    };
                    if u.connect(remote).await.is_err() {
                        return Completion::Failed(NetStatus::Error);
                    }
                    Sock::Udp(Arc::new(u))
                }
            };
            if let Ok(mut m) = socks.lock() {
                m.insert(sock, made);
            }
            Completion::Done
        });
    }

    fn connect_ssl(
        &mut self,
        op: OpId,
        sock: SockId,
        local: Option<SocketAddr>,
        remote: SocketAddr,
        timeout: Option<Duration>,
        sni: Option<Vec<u8>>,
    ) {
        self.close(sock);
        let socks = self.socks.clone();
        self.spawn(op, Some(sock), async move {
            // One time-out for the TCP connect and the handshake together
            // (`nse_nsock.cc:586`, one nsock event).
            let both = async {
                let tcp = match tcp_connect(local, remote).await {
                    Ok(s) => Arc::new(s),
                    Err(_) => return Completion::Failed(NetStatus::Error),
                };
                handshake(socks, sock, tcp, sni).await
            };
            within(timeout, both)
                .await
                .unwrap_or(Completion::Failed(NetStatus::Timeout))
        });
    }

    fn reconnect_ssl(
        &mut self,
        op: OpId,
        sock: SockId,
        timeout: Option<Duration>,
        sni: Option<Vec<u8>>,
    ) {
        let s = self.sock(sock);
        let socks = self.socks.clone();
        self.spawn(op, Some(sock), async move {
            let tcp = match s {
                Some(Sock::Tcp(t)) => t,
                // An established connection: OpenSSL's `SSL_connect` on it
                // returns at once.
                Some(Sock::Tls(_)) => return Completion::Done,
                _ => return Completion::Failed(NetStatus::Error),
            };
            within(timeout, handshake(socks, sock, tcp, sni))
                .await
                .unwrap_or(Completion::Failed(NetStatus::Timeout))
        });
    }

    fn is_ssl(&self, sock: SockId) -> bool {
        matches!(self.sock(sock), Some(Sock::Tls(_) | Sock::TlsDown(_)))
    }

    fn peer_certificate(&self, sock: SockId) -> Option<Vec<u8>> {
        match self.sock(sock)? {
            Sock::Tls(t) => t.stream.leaf(),
            _ => None,
        }
    }

    fn setup_udp(
        &mut self,
        sock: SockId,
        v6: bool,
        local: Option<SocketAddr>,
    ) -> Result<(), String> {
        let bind = local.unwrap_or_else(|| unspecified(v6));
        let u = self
            .rt
            .block_on(UdpSocket::bind(bind))
            .map_err(|e| e.to_string())?;
        if let Ok(mut m) = self.socks.lock() {
            m.insert(sock, Sock::Udp(Arc::new(u)));
        }
        Ok(())
    }

    fn write(&mut self, op: OpId, sock: SockId, data: Vec<u8>, timeout: Option<Duration>) {
        let s = self.sock(sock);
        self.spawn(op, Some(sock), async move {
            let sent = match s {
                Some(Sock::Tcp(t)) => {
                    within(timeout, async {
                        let mut off = 0;
                        while off < data.len() {
                            if t.writable().await.is_err() {
                                return false;
                            }
                            match t.try_write(&data[off..]) {
                                Ok(n) => off = off.saturating_add(n),
                                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                                Err(_) => return false,
                            }
                        }
                        true
                    })
                    .await
                }
                Some(Sock::Udp(u)) => within(timeout, async { u.send(&data).await.is_ok() }).await,
                Some(Sock::Tls(t)) => {
                    within(timeout, async { t.stream.write(&data).await.is_ok() }).await
                }
                Some(Sock::TlsDown(_)) | None => Some(false),
            };
            match sent {
                Some(true) => Completion::Done,
                Some(false) => Completion::Failed(NetStatus::Error),
                None => Completion::Failed(NetStatus::Timeout),
            }
        });
    }

    fn sendto(
        &mut self,
        op: OpId,
        sock: SockId,
        to: SocketAddr,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) {
        let s = self.sock(sock);
        self.spawn(op, Some(sock), async move {
            let sent = match s {
                Some(Sock::Udp(u)) => {
                    within(timeout, async { u.send_to(&data, to).await.is_ok() }).await
                }
                _ => Some(false),
            };
            match sent {
                Some(true) => Completion::Done,
                Some(false) => Completion::Failed(NetStatus::Error),
                None => Completion::Failed(NetStatus::Timeout),
            }
        });
    }

    fn read(&mut self, op: OpId, sock: SockId, mode: ReadMode, timeout: Option<Duration>) {
        let s = self.sock(sock);
        self.spawn(op, Some(sock), async move {
            match s {
                Some(Sock::Tcp(t)) => read_tcp(t, mode, timeout).await,
                Some(Sock::Udp(u)) => read_udp(u, timeout).await,
                Some(Sock::Tls(t)) => read_tls(t, mode, timeout).await,
                Some(Sock::TlsDown(_)) | None => Completion::Failed(NetStatus::Error),
            }
        });
    }

    fn close(&mut self, sock: SockId) {
        let gone = self.socks.lock().ok().and_then(|mut m| m.remove(&sock));
        if let Some(Sock::Tls(t)) = gone {
            // A writable socket is so at once; a full one gets no
            // close_notify, as SSL_shutdown's one non-blocking write gives none.
            self.rt.block_on(async {
                let _ =
                    tokio::time::timeout(Duration::from_millis(50), t.stream.close_notify()).await;
            });
        }
        let on: Vec<OpId> = self
            .tasks
            .iter()
            .filter(|(_, (s, _))| *s == Some(sock))
            .map(|(op, _)| *op)
            .collect();
        for op in on {
            self.cancel(op);
        }
    }

    fn timer(&mut self, op: OpId, after: Duration) {
        self.spawn(op, None, async move {
            tokio::time::sleep(after).await;
            Completion::Fired
        });
    }

    fn cancel(&mut self, op: OpId) {
        if let Some((_, h)) = self.tasks.remove(&op) {
            h.abort();
        }
    }

    fn info(&self, sock: SockId) -> Option<(SocketAddr, SocketAddr)> {
        match self.sock(sock)? {
            Sock::Tcp(t) | Sock::TlsDown(t) => Some((t.local_addr().ok()?, t.peer_addr().ok()?)),
            Sock::Tls(t) => {
                let tcp = t.stream.tcp();
                Some((tcp.local_addr().ok()?, tcp.peer_addr().ok()?))
            }
            Sock::Udp(u) => {
                let local = u.local_addr().ok()?;
                let remote = u
                    .peer_addr()
                    .unwrap_or_else(|_| unspecified(local.is_ipv6()));
                Some((local, remote))
            }
        }
    }

    fn poll(&mut self, wait: Duration) -> Vec<(OpId, Completion)> {
        let mut out = Vec::new();
        if !self.tasks.is_empty() {
            let rx = &mut self.rx;
            if let Some(Some(first)) = self
                .rt
                .block_on(async { tokio::time::timeout(wait, rx.recv()).await.ok() })
            {
                out.push(first);
            }
        }
        while let Ok(c) = self.rx.try_recv() {
            out.push(c);
        }
        for (op, _) in &out {
            self.tasks.remove(op);
        }
        out
    }

    fn resolve(&mut self, name: &str, family: Family) -> Result<Vec<IpAddr>, String> {
        let found = (name, 0u16).to_socket_addrs().map_err(|e| {
            let text = e.to_string();
            text.strip_prefix("failed to lookup address information: ")
                .unwrap_or(&text)
                .to_string()
        })?;
        let mut list: Vec<IpAddr> = Vec::new();
        for a in found {
            let ip = a.ip();
            let keep = match family {
                Family::Inet => ip.is_ipv4(),
                Family::Inet6 => ip.is_ipv6(),
                Family::Unspec => true,
            };
            // Duplicates are kept, as `resolve_all` keeps them: a name listed
            // twice in /etc/hosts resolves to its address twice.
            if keep {
                list.push(ip);
            }
        }
        if list.is_empty() {
            return Err("Name or service not known".into());
        }
        Ok(list)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_are_satisfied_as_nsocks_are() {
        assert!(!satisfied(ReadMode::Any, b""));
        assert!(satisfied(ReadMode::Any, b"x"));
        assert!(!satisfied(ReadMode::Lines(2), b"a\nb"));
        assert!(satisfied(ReadMode::Lines(2), b"a\nb\n"));
        assert!(satisfied(ReadMode::Lines(0), b"a"));
        assert!(!satisfied(ReadMode::Bytes(3), b"ab"));
        assert!(satisfied(ReadMode::Bytes(3), b"abc"));
        assert!(satisfied(ReadMode::Lines(1), &vec![b'x'; MAX_READ]));
    }
}
