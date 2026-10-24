//! A TLS client connection over a tokio `TcpStream`, driven by hand: rustls
//! does no I/O, and every socket wait here is a tokio readiness future, so a
//! connection can be dropped (its task aborted) at any await without leaving
//! anything behind (LESSONS #017).
//!
//! The state rustls keeps sits behind one `std` mutex, held only between
//! awaits; a read and a write on the same connection can be pending at once,
//! as they can in nsock.

use std::io::{self, Read, Write};
use std::net::IpAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use rustls::pki_types::ServerName;
use rustls::ClientConnection;
use tokio::net::TcpStream;

use super::{connection_config, PeerLeaf};

/// What a read of the connection came to.
#[derive(Debug, PartialEq, Eq)]
pub enum ReadEvent {
    /// Plaintext.
    Data(Vec<u8>),
    /// The peer ended the connection: with a `close_notify` (`notify`), or by
    /// closing TCP without one.
    Closed { notify: bool },
    /// A TLS error (a bad record, an alert), or the socket's.
    Error,
}

struct Inner {
    conn: ClientConnection,
    /// Bytes read from TCP that rustls has not taken yet.
    pending: Vec<u8>,
    /// TCP reported end of file.
    tcp_eof: bool,
    /// ... and rustls has been told.
    eof_given: bool,
}

/// One TLS connection.
pub struct TlsStream {
    tcp: Arc<TcpStream>,
    inner: Mutex<Inner>,
    leaf: PeerLeaf,
}

/// How much is read from the socket at once.
const CHUNK: usize = 16 * 1024;

/// The server name rustls is given: the `SNI` name when it can carry it,
/// else the peer's address, for which rustls sends no `server_name`
/// (`nse-tls-sni-rustls-names`).
#[must_use]
pub fn server_name(sni: Option<&[u8]>, peer: IpAddr) -> ServerName<'static> {
    sni.and_then(|n| std::str::from_utf8(n).ok())
        .and_then(|n| ServerName::try_from(n.to_owned()).ok())
        .unwrap_or_else(|| ServerName::IpAddress(peer.into()))
}

fn lock(m: &Mutex<Inner>) -> MutexGuard<'_, Inner> {
    // A panic while the lock was held leaves rustls's state as it was; the
    // connection is then only as broken as rustls says it is.
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

/// Write all of `data` to the socket.
async fn send(tcp: &TcpStream, data: &[u8]) -> io::Result<()> {
    let mut off = 0;
    while off < data.len() {
        tcp.writable().await?;
        match tcp.try_write(&data[off..]) {
            Ok(n) => off = off.saturating_add(n),
            Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

impl Inner {
    /// What rustls has to send.
    fn outgoing(&mut self) -> Vec<u8> {
        let mut out = Vec::new();
        while self.conn.wants_write() {
            if self.conn.write_tls(&mut out).is_err() {
                break;
            }
        }
        out
    }

    /// Give rustls what TCP delivered and let it process: `Err` on a TLS
    /// error. Returns whether anything was given.
    fn feed(&mut self) -> Result<bool, rustls::Error> {
        if !self.pending.is_empty() {
            let mut rd: &[u8] = &self.pending;
            let n = self
                .conn
                .read_tls(&mut rd)
                .map_err(|e| rustls::Error::General(e.to_string()))?;
            self.pending.drain(..n);
            self.conn.process_new_packets()?;
            return Ok(n > 0);
        }
        if self.tcp_eof && !self.eof_given {
            self.eof_given = true;
            let mut none: &[u8] = &[];
            let _ = self.conn.read_tls(&mut none);
            self.conn.process_new_packets()?;
            return Ok(true);
        }
        Ok(false)
    }
}

impl TlsStream {
    /// The handshake, over `tcp`. On failure, the alert rustls queued is
    /// sent first (best effort), as OpenSSL sends its own. The leaf goes in
    /// `leaf` once its checks pass, whatever happens to the handshake after.
    pub async fn handshake(
        tcp: Arc<TcpStream>,
        name: ServerName<'static>,
        leaf: PeerLeaf,
    ) -> Result<Self, ()> {
        let conn = ClientConnection::new(connection_config(&leaf), name).map_err(|_| ())?;
        let s = Self {
            tcp,
            leaf,
            inner: Mutex::new(Inner {
                conn,
                pending: Vec::new(),
                tcp_eof: false,
                eof_given: false,
            }),
        };
        loop {
            let (out, failed, done) = {
                let mut i = lock(&s.inner);
                let mut failed = false;
                loop {
                    match i.feed() {
                        Ok(true) => continue,
                        Ok(false) => break,
                        Err(_) => {
                            failed = true;
                            break;
                        }
                    }
                }
                let out = i.outgoing();
                let done = !failed && !i.conn.is_handshaking();
                (out, failed, done)
            };
            if !out.is_empty() {
                let sent = send(&s.tcp, &out).await;
                if sent.is_err() && !failed {
                    return Err(());
                }
            }
            if failed {
                return Err(());
            }
            if done {
                return Ok(s);
            }
            let (eof, given) = {
                let i = lock(&s.inner);
                (i.tcp_eof, i.eof_given)
            };
            if eof {
                if given {
                    // The peer closed mid-handshake and rustls was told.
                    return Err(());
                }
                // Tell rustls on the next feed.
                continue;
            }
            s.fill().await.map_err(|_| ())?;
        }
    }

    /// Read from TCP into `pending` (only when rustls has taken everything).
    async fn fill(&self) -> io::Result<()> {
        let mut chunk = vec![0u8; CHUNK];
        loop {
            self.tcp.readable().await?;
            match self.tcp.try_read(&mut chunk) {
                Ok(0) => {
                    lock(&self.inner).tcp_eof = true;
                    return Ok(());
                }
                Ok(n) => {
                    lock(&self.inner).pending.extend_from_slice(&chunk[..n]);
                    return Ok(());
                }
                Err(e) if e.kind() == io::ErrorKind::WouldBlock => continue,
                Err(e) => return Err(e),
            }
        }
    }

    /// The next plaintext, or how the connection ended. Plaintext rustls
    /// already holds comes first, before any end it has seen.
    pub async fn read(&self) -> ReadEvent {
        loop {
            let (got, out) = {
                let mut i = lock(&self.inner);
                let mut data = Vec::new();
                let mut buf = [0u8; 4096];
                let got = loop {
                    match i.conn.reader().read(&mut buf) {
                        Ok(0) => {
                            break Some(if data.is_empty() {
                                ReadEvent::Closed { notify: true }
                            } else {
                                ReadEvent::Data(std::mem::take(&mut data))
                            })
                        }
                        Ok(n) => data.extend_from_slice(&buf[..n]),
                        Err(e) if e.kind() == io::ErrorKind::WouldBlock => {
                            if !data.is_empty() {
                                break Some(ReadEvent::Data(std::mem::take(&mut data)));
                            }
                            match i.feed() {
                                Ok(true) => continue,
                                Ok(false) => break None,
                                Err(_) => break Some(ReadEvent::Error),
                            }
                        }
                        Err(e) if e.kind() == io::ErrorKind::UnexpectedEof => {
                            break Some(if data.is_empty() {
                                ReadEvent::Closed { notify: false }
                            } else {
                                ReadEvent::Data(std::mem::take(&mut data))
                            })
                        }
                        Err(_) => break Some(ReadEvent::Error),
                    }
                };
                (got, i.outgoing())
            };
            // A key update or an alert rustls answers: sent before the read
            // goes on, as OpenSSL's `SSL_read` writes it.
            if !out.is_empty() && send(&self.tcp, &out).await.is_err() {
                return ReadEvent::Error;
            }
            if let Some(ev) = got {
                return ev;
            }
            if self.fill().await.is_err() {
                return ReadEvent::Error;
            }
        }
    }

    /// Encrypt and send all of `data`.
    pub async fn write(&self, data: &[u8]) -> io::Result<()> {
        let mut off = 0;
        loop {
            let out = {
                let mut i = lock(&self.inner);
                while off < data.len() {
                    match i.conn.writer().write(&data[off..]) {
                        Ok(0) => break,
                        Ok(n) => off = off.saturating_add(n),
                        Err(e) => return Err(e),
                    }
                }
                i.outgoing()
            };
            send(&self.tcp, &out).await?;
            if off >= data.len() {
                return Ok(());
            }
        }
    }

    /// `SSL_shutdown` as `nsock_iod_delete` calls it: a `close_notify`, sent
    /// if the socket takes it at once (`nse_status` is not waited for: the
    /// C writes once, non-blocking, and does not look at the result).
    pub async fn close_notify(&self) {
        let out = {
            let mut i = lock(&self.inner);
            i.conn.send_close_notify();
            i.outgoing()
        };
        if self.tcp.writable().await.is_ok() {
            let _ = self.tcp.try_write(&out);
        }
    }

    /// The certificate the server sent first: the leaf.
    #[must_use]
    pub fn leaf(&self) -> Option<Vec<u8>> {
        self.leaf.get()
    }

    /// The negotiated version and suite, as rustls names them.
    #[must_use]
    pub fn negotiated(&self) -> Option<(String, String)> {
        let i = lock(&self.inner);
        let v = i.conn.protocol_version()?;
        let s = i.conn.negotiated_cipher_suite()?;
        Some((format!("{v:?}"), format!("{:?}", s.suite())))
    }

    /// The socket underneath.
    #[must_use]
    pub fn tcp(&self) -> &Arc<TcpStream> {
        &self.tcp
    }
}
