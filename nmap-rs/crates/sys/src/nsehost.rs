//! What NSE needs from the system, over the run's data directories
//! ([`crate::datadir`]): `nselib/` and scripts to load, the interfaces, random
//! bytes, and a network that reports the scheduler's progress.

use std::cell::Cell;
use std::io::Read;
use std::net::{IpAddr, SocketAddr};
use std::path::Path;
use std::rc::Rc;
use std::time::{Duration, Instant};

use nmap_core::nse::choose::{Found, ScriptLocator};
use nmap_core::nse::net::{Completion, Family, NetProto, OpId, ReadMode, ScriptNet, SockId};
use nmap_core::nse::nmaplib::{Interface, Link};
use nmap_core::nse::package::LibrarySource;

use crate::datadir::DataDirs;

fn path_bytes(p: &Path) -> Vec<u8> {
    p.to_string_lossy().into_owned().into_bytes()
}

/// `nselib/` (and anything else the engine reads by name) from the data
/// directories.
pub struct DataSource(pub DataDirs);

impl LibrarySource for DataSource {
    fn find(&self, file: &[u8]) -> Option<Vec<u8>> {
        let f = std::str::from_utf8(file).ok()?;
        self.0
            .fetch(f)
            .filter(|p| p.is_file())
            .map(|p| path_bytes(&p))
    }
    fn read(&self, path: &[u8]) -> Result<Vec<u8>, Vec<u8>> {
        let p = std::str::from_utf8(path).map_err(|_| b"invalid path".to_vec())?;
        std::fs::read(p).map_err(|e| e.to_string().into_bytes())
    }
}

/// `nse_fetchscript` (`nse_main.cc:314`): an absolute name as given; else
/// `scripts/<name>` in the data directories; else the name as given, relative
/// to the working directory. The last is the operator's own file
/// (`--script ./mine.nse`), never a search, so it is kept.
pub struct DataLocator(pub DataDirs);

fn found(p: &Path, shown: Vec<u8>, name: &str) -> Option<Found> {
    let m = std::fs::metadata(p).ok()?;
    if m.is_file() {
        std::fs::File::open(p).ok()?;
        Some(Found::File(shown))
    } else if m.is_dir() {
        std::fs::read_dir(p).ok()?;
        Some(if name.ends_with('/') {
            Found::Directory(shown)
        } else {
            Found::BareDirectory(shown)
        })
    } else {
        None
    }
}

impl ScriptLocator for DataLocator {
    fn fetch_script(&self, name: &[u8]) -> Option<Found> {
        let s = std::str::from_utf8(name).ok()?;
        if s.is_empty() {
            return None;
        }
        let p = Path::new(s);
        if p.is_absolute() {
            return found(p, name.to_vec(), s);
        }
        if let Some(hit) = self.0.fetch(&format!("scripts/{s}")) {
            return found(&hit, path_bytes(&hit), s);
        }
        found(p, name.to_vec(), s)
    }

    fn list_dir(&self, path: &[u8]) -> Vec<Vec<u8>> {
        let Ok(p) = std::str::from_utf8(path) else {
            return Vec::new();
        };
        std::fs::read_dir(p)
            .map(|rd| {
                rd.flatten()
                    .map(|e| e.file_name().to_string_lossy().into_owned().into_bytes())
                    .collect()
            })
            .unwrap_or_default()
    }
}

/// A [`ScriptNet`] that notes when the scheduler last waited on it.
///
/// nmap's scheduler calls `nsock_loop` on every pass (`loop(50)`), sockets
/// or not, so a pass that never comes means one script thread has run
/// without yielding since the last one. The command line's stall limit reads
/// [`ProgressNet::last_pass`] (`nse-stall-limit`).
pub struct ProgressNet<N> {
    inner: N,
    last: Rc<Cell<Instant>>,
}

impl<N: ScriptNet> ProgressNet<N> {
    pub fn new(inner: N) -> Self {
        Self {
            inner,
            last: Rc::new(Cell::new(Instant::now())),
        }
    }

    /// When the scheduler last polled, shared: read it from the watchdog.
    pub fn last_pass(&self) -> Rc<Cell<Instant>> {
        self.last.clone()
    }
}

impl<N: ScriptNet> ScriptNet for ProgressNet<N> {
    fn connect(
        &mut self,
        op: OpId,
        sock: SockId,
        proto: NetProto,
        local: Option<SocketAddr>,
        remote: SocketAddr,
        timeout: Option<Duration>,
    ) {
        self.inner.connect(op, sock, proto, local, remote, timeout);
    }
    fn setup_udp(
        &mut self,
        sock: SockId,
        v6: bool,
        local: Option<SocketAddr>,
    ) -> Result<(), String> {
        self.inner.setup_udp(sock, v6, local)
    }
    fn write(&mut self, op: OpId, sock: SockId, data: Vec<u8>, timeout: Option<Duration>) {
        self.inner.write(op, sock, data, timeout);
    }
    fn sendto(
        &mut self,
        op: OpId,
        sock: SockId,
        to: SocketAddr,
        data: Vec<u8>,
        timeout: Option<Duration>,
    ) {
        self.inner.sendto(op, sock, to, data, timeout);
    }
    fn read(&mut self, op: OpId, sock: SockId, mode: ReadMode, timeout: Option<Duration>) {
        self.inner.read(op, sock, mode, timeout);
    }
    fn close(&mut self, sock: SockId) {
        self.inner.close(sock);
    }
    fn timer(&mut self, op: OpId, after: Duration) {
        self.inner.timer(op, after);
    }
    fn cancel(&mut self, op: OpId) {
        self.inner.cancel(op);
    }
    fn info(&self, sock: SockId) -> Option<(SocketAddr, SocketAddr)> {
        self.inner.info(sock)
    }
    fn poll(&mut self, wait: Duration) -> Vec<(OpId, Completion)> {
        let done = self.inner.poll(wait);
        self.last.set(Instant::now());
        done
    }
    fn resolve(&mut self, name: &str, family: Family) -> Result<Vec<IpAddr>, String> {
        self.inner.resolve(name, family)
    }
}

/// `getinterfaces()` as `nmap.list_interfaces` sees it: one entry per
/// address, as nmap's interface list has.
pub fn interfaces() -> Result<Vec<Interface>, Vec<u8>> {
    let list = crate::netif::interfaces().map_err(|e| e.to_string().into_bytes())?;
    let mut out = Vec::new();
    for i in list {
        let link = if i.is_loopback {
            Link::Loopback
        } else if let Some(mac) = i.mac {
            Link::Ethernet(mac)
        } else {
            Link::Other
        };
        let name = i.name.as_bytes().to_vec();
        let mtu = i.mtu.map_or(0, i64::from);
        let addrs = i
            .ipv4
            .iter()
            .map(|n| (IpAddr::V4(n.addr), n.prefix_len))
            .chain(i.ipv6.iter().map(|n| (IpAddr::V6(n.addr), n.prefix_len)));
        for (address, prefix) in addrs {
            out.push(Interface {
                device: name.clone(),
                shortname: name.clone(),
                netmask_bits: i64::from(prefix),
                address,
                link,
                up: i.is_up,
                mtu,
            });
        }
    }
    Ok(out)
}

/// `get_random_bytes`: fill `buf` from the OS, or report that it cannot.
pub fn random_bytes(buf: &mut [u8]) -> bool {
    std::fs::File::open("/dev/urandom")
        .and_then(|mut f| f.read_exact(buf))
        .is_ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    #[cfg_attr(miri, ignore)] // real files and directories; Miri has no filesystem
    fn scripts_are_found_as_nse_fetchscript_finds_them() {
        let tmp = std::env::temp_dir().join(format!("nmap-rs-nsehost-{}", std::process::id()));
        let scripts = tmp.join("data/scripts");
        std::fs::create_dir_all(scripts.join("sub")).unwrap();
        std::fs::write(scripts.join("a.nse"), "x").unwrap();
        let loc = DataLocator(DataDirs::new(vec![tmp.join("data")]));
        let shown = |p: &Path| p.to_string_lossy().into_owned().into_bytes();
        assert_eq!(
            loc.fetch_script(b"a.nse"),
            Some(Found::File(shown(&scripts.join("a.nse"))))
        );
        assert_eq!(
            loc.fetch_script(b"sub/"),
            Some(Found::Directory(shown(&scripts.join("sub/"))))
        );
        assert_eq!(
            loc.fetch_script(b"sub"),
            Some(Found::BareDirectory(shown(&scripts.join("sub"))))
        );
        let abs = scripts.join("a.nse");
        assert_eq!(
            loc.fetch_script(abs.to_str().unwrap().as_bytes()),
            Some(Found::File(shown(&abs)))
        );
        assert_eq!(loc.fetch_script(b"missing.nse"), None);
        assert_eq!(loc.fetch_script(b""), None);
        let src = DataSource(DataDirs::new(vec![tmp.join("data")]));
        assert_eq!(src.find(b"scripts/a.nse"), Some(shown(&abs)));
        assert_eq!(
            src.find(b"scripts/sub"),
            None,
            "a directory is not a library"
        );
        let _ = std::fs::remove_dir_all(&tmp);
    }

    #[test]
    fn a_poll_marks_progress() {
        let mut net = ProgressNet::new(nmap_core::nse::net::NoNet);
        let last = net.last_pass();
        let before = last.get();
        std::thread::sleep(Duration::from_millis(5));
        net.poll(Duration::ZERO);
        assert!(last.get() > before);
    }
}
