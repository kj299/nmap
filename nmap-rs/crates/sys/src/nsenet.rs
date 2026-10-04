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
//! - closing a socket drops its pending operations, which never complete.
//!
//! There is no `unsafe` here: tokio's socket API is safe.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, ToSocketAddrs};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use nmap_core::nse::net::{Completion, Family, NetProto, NetStatus, OpId, ReadMode, ScriptNet, SockId};
use tokio::net::{TcpSocket, TcpStream, UdpSocket};
use tokio::sync::mpsc;
use tokio::task::AbortHandle;

#[derive(Clone)]
enum Sock {
    Tcp(Arc<TcpStream>),
    Udp(Arc<UdpSocket>),
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

/// Whether `buf` holds what `mode` waits for.
fn satisfied(mode: ReadMode, buf: &[u8]) -> bool {
    match mode {
        ReadMode::Any => !buf.is_empty(),
        ReadMode::Lines(n) => {
            let lines = buf.iter().filter(|&&b| b == b'\n').count();
            u64::try_from(lines).unwrap_or(u64::MAX) >= n.max(1)
        }
        ReadMode::Bytes(n) => u64::try_from(buf.len()).unwrap_or(u64::MAX) >= n.max(1),
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

    fn setup_udp(&mut self, sock: SockId, v6: bool, local: Option<SocketAddr>) -> Result<(), String> {
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
                None => Some(false),
            };
            match sent {
                Some(true) => Completion::Done,
                Some(false) => Completion::Failed(NetStatus::Error),
                None => Completion::Failed(NetStatus::Timeout),
            }
        });
    }

    fn sendto(&mut self, op: OpId, sock: SockId, to: SocketAddr, data: Vec<u8>, timeout: Option<Duration>) {
        let s = self.sock(sock);
        self.spawn(op, Some(sock), async move {
            let sent = match s {
                Some(Sock::Udp(u)) => within(timeout, async { u.send_to(&data, to).await.is_ok() }).await,
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
                None => Completion::Failed(NetStatus::Error),
            }
        });
    }

    fn close(&mut self, sock: SockId) {
        if let Ok(mut m) = self.socks.lock() {
            m.remove(&sock);
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
            Sock::Tcp(t) => Some((t.local_addr().ok()?, t.peer_addr().ok()?)),
            Sock::Udp(u) => {
                let local = u.local_addr().ok()?;
                let remote = u.peer_addr().unwrap_or_else(|_| unspecified(local.is_ipv6()));
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
            if keep && !list.contains(&ip) {
                list.push(ip);
            }
        }
        if list.is_empty() {
            return Err("Name or service not known".into());
        }
        Ok(list)
    }
}
