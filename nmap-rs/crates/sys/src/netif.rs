//! Network-interface enumeration — the first stop on the raw send path (pick the
//! source address / MAC / outbound interface before building a packet). Replaces
//! nmap's `libdnet` `intf-*.c`.
//!
//! The [`Interface`] type and [`interfaces`] function are the OS-agnostic seam; the
//! backend is chosen at compile time:
//!   * **Unix** — `getifaddrs(3)` (the project's first FFI). The returned linked list
//!     is walked behind a `// SAFETY:`-documented boundary and freed by an RAII guard.
//!     This is what CI builds, tests, and unsafe-audits.
//!   * **Windows** — IP Helper's `GetAdaptersAddresses` via the `windows` crate. Real
//!     bindings, but compiled and runtime-validated only on a Windows target (this
//!     Linux CI cannot link them); the shape mirrors the Unix backend exactly.
//!
//! All FFI is confined to a few audited `unsafe` blocks; the public surface is safe.

use std::net::{Ipv4Addr, Ipv6Addr};

/// A network interface and the addresses bound to it. Backend-independent.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// Kernel interface name (e.g. `eth0`, `lo`, or a Windows adapter GUID/name).
    pub name: String,
    /// Interface index (`if_nametoindex` / `IfIndex`), 0 if unavailable.
    pub index: u32,
    /// Link-layer (MAC) address, when the interface has one.
    pub mac: Option<[u8; 6]>,
    /// IPv4 addresses bound to the interface.
    pub ipv4: Vec<Ipv4Addr>,
    /// IPv6 addresses bound to the interface.
    pub ipv6: Vec<Ipv6Addr>,
    /// The interface is administratively up.
    pub is_up: bool,
    /// The interface is a loopback.
    pub is_loopback: bool,
}

impl Interface {
    fn empty(name: String) -> Interface {
        Interface {
            name,
            index: 0,
            mac: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            is_up: false,
            is_loopback: false,
        }
    }
}

/// Enumerate the host's network interfaces with their bound addresses.
///
/// # Errors
/// Returns the OS error if the underlying enumeration call fails.
pub fn interfaces() -> std::io::Result<Vec<Interface>> {
    imp::interfaces()
}

// ---------------------------------------------------------------------------------
// Unix backend: getifaddrs(3).
// ---------------------------------------------------------------------------------
#[cfg(unix)]
mod imp {
    use super::Interface;
    use std::collections::BTreeMap;
    use std::ffi::CStr;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use std::ptr;

    /// RAII owner of the `ifaddrs` list returned by `getifaddrs`, freed exactly once
    /// on drop. Holding this guard keeps every `ifa_*` pointer we walk valid.
    struct IfAddrs(*mut libc::ifaddrs);

    impl Drop for IfAddrs {
        fn drop(&mut self) {
            // SAFETY: `self.0` was returned by a successful `getifaddrs` and has not
            // been freed elsewhere (this is the sole owner); `freeifaddrs` is the
            // matching deallocator.
            unsafe { libc::freeifaddrs(self.0) };
        }
    }

    pub(super) fn interfaces() -> std::io::Result<Vec<Interface>> {
        let mut head: *mut libc::ifaddrs = ptr::null_mut();
        // SAFETY: `getifaddrs` writes a heap-allocated list head through the out-param
        // on success (return 0) and leaves it untouched on failure; we pass a valid
        // pointer to our local and check the return code before using `head`.
        let rc = unsafe { libc::getifaddrs(&mut head) };
        if rc != 0 {
            return Err(std::io::Error::last_os_error());
        }
        // Take ownership immediately so every early return still frees the list.
        let _guard = IfAddrs(head);

        let mut by_name: BTreeMap<String, Interface> = BTreeMap::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is non-null (loop guard) and points to a live `ifaddrs`
            // node owned by `_guard`; the list is not mutated while we walk it.
            let ifa = unsafe { &*cur };

            // Advance now so any `continue` still makes progress.
            cur = ifa.ifa_next;

            if ifa.ifa_name.is_null() {
                continue;
            }
            // SAFETY: `ifa_name` is a NUL-terminated C string owned by the list node,
            // valid for the lifetime of `_guard`.
            let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
                .to_string_lossy()
                .into_owned();

            let entry = by_name
                .entry(name.clone())
                .or_insert_with(|| Interface::empty(name.clone()));

            // Flags live on every node for the interface; fold them in.
            let flags = ifa.ifa_flags;
            #[allow(clippy::cast_sign_loss)]
            let iff_up = libc::IFF_UP as u32;
            #[allow(clippy::cast_sign_loss)]
            let iff_loopback = libc::IFF_LOOPBACK as u32;
            if flags & iff_up != 0 {
                entry.is_up = true;
            }
            if flags & iff_loopback != 0 {
                entry.is_loopback = true;
            }

            if entry.index == 0 {
                // SAFETY: `ifa_name` is a valid C string (checked above); `if_nametoindex`
                // reads it and returns 0 on error, which we keep as "unknown".
                entry.index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
            }

            if ifa.ifa_addr.is_null() {
                continue;
            }
            // SAFETY: `ifa_addr` is non-null and points to a `sockaddr` whose leading
            // `sa_family` field is always present regardless of the concrete variant.
            let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });

            match family {
                libc::AF_INET => {
                    // SAFETY: family AF_INET guarantees `ifa_addr` actually points to a
                    // `sockaddr_in`; we only read `sin_addr`.
                    let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                    // `s_addr` holds the address bytes in network order; `to_ne_bytes`
                    // recovers that in-memory byte layout (a.b.c.d) on any endianness.
                    entry
                        .ipv4
                        .push(Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes()));
                }
                libc::AF_INET6 => {
                    // SAFETY: family AF_INET6 guarantees `ifa_addr` points to a
                    // `sockaddr_in6`; we only read the 16-byte address.
                    let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                    entry.ipv6.push(Ipv6Addr::from(sin6.sin6_addr.s6_addr));
                }
                #[cfg(target_os = "linux")]
                libc::AF_PACKET => {
                    // SAFETY: family AF_PACKET guarantees `ifa_addr` points to a
                    // `sockaddr_ll`; we read the hardware address and its length.
                    let sll = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_ll>() };
                    if sll.sll_halen >= 6 {
                        let mut mac = [0u8; 6];
                        mac.copy_from_slice(&sll.sll_addr[..6]);
                        // Ignore all-zero MACs (e.g. loopback).
                        if mac != [0u8; 6] {
                            entry.mac = Some(mac);
                        }
                    }
                }
                _ => {}
            }
        }

        Ok(by_name.into_values().collect())
    }
}

// ---------------------------------------------------------------------------------
// Windows backend: GetAdaptersAddresses (compiled only on Windows).
// ---------------------------------------------------------------------------------
#[cfg(windows)]
mod imp {
    use super::Interface;
    use std::net::{Ipv4Addr, Ipv6Addr};
    use windows::Win32::Foundation::{ERROR_BUFFER_OVERFLOW, ERROR_SUCCESS, WIN32_ERROR};
    use windows::Win32::NetworkManagement::IpHelper::{
        GetAdaptersAddresses, GAA_FLAG_SKIP_ANYCAST, GAA_FLAG_SKIP_DNS_SERVER,
        GAA_FLAG_SKIP_MULTICAST, IP_ADAPTER_ADDRESSES_LH,
    };
    use windows::Win32::Networking::WinSock::{
        AF_INET, AF_INET6, AF_UNSPEC, SOCKADDR_IN, SOCKADDR_IN6,
    };

    pub(super) fn interfaces() -> std::io::Result<Vec<Interface>> {
        // Two-call pattern: size the buffer, then fill it.
        let flags = GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST | GAA_FLAG_SKIP_DNS_SERVER;
        let mut size: u32 = 0;
        // SAFETY: first call with a null buffer only writes the required size.
        let rc = unsafe { GetAdaptersAddresses(AF_UNSPEC.0 as u32, flags, None, None, &mut size) };
        if WIN32_ERROR(rc) != ERROR_BUFFER_OVERFLOW && WIN32_ERROR(rc) != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }
        let mut buf = vec![0u8; size as usize];
        let head = buf.as_mut_ptr().cast::<IP_ADAPTER_ADDRESSES_LH>();
        let family = AF_UNSPEC.0 as u32;
        // SAFETY: `buf` is `size` bytes as required by the sizing call; `GetAdaptersAddresses`
        // fills it with a linked list of adapters rooted at `head`.
        let rc = unsafe { GetAdaptersAddresses(family, flags, None, Some(head), &mut size) };
        if WIN32_ERROR(rc) != ERROR_SUCCESS {
            return Err(std::io::Error::from_raw_os_error(rc as i32));
        }

        let mut out = Vec::new();
        let mut cur = head;
        while !cur.is_null() {
            // SAFETY: `cur` is non-null and points into the live buffer `buf`.
            let a = unsafe { &*cur };
            cur = a.Next;

            // SAFETY: `FriendlyName` is a NUL-terminated wide string owned by `buf`.
            let name = unsafe { a.FriendlyName.to_string() }.unwrap_or_default();
            let mut iface = Interface::empty(name);
            // SAFETY: `IfIndex` is the active member of this always-initialized
            // anonymous union in every `IP_ADAPTER_ADDRESSES_LH` the API returns.
            iface.index = unsafe { a.Anonymous1.Anonymous.IfIndex };
            iface.is_up = a.OperStatus.0 == 1; // IfOperStatusUp
            iface.is_loopback = a.IfType == 24; // IF_TYPE_SOFTWARE_LOOPBACK

            let halen = a.PhysicalAddressLength as usize;
            if halen >= 6 {
                let mut mac = [0u8; 6];
                mac.copy_from_slice(&a.PhysicalAddress[..6]);
                if mac != [0u8; 6] {
                    iface.mac = Some(mac);
                }
            }

            let mut ua = a.FirstUnicastAddress;
            while !ua.is_null() {
                // SAFETY: `ua` is non-null and points into `buf`.
                let u = unsafe { &*ua };
                ua = u.Next;
                let sa = u.Address.lpSockaddr;
                if sa.is_null() {
                    continue;
                }
                // SAFETY: `lpSockaddr` points to a `SOCKADDR` whose family we read first.
                let family = unsafe { (*sa).sa_family };
                if family == AF_INET {
                    // SAFETY: AF_INET => the sockaddr is a SOCKADDR_IN.
                    let sin = unsafe { &*sa.cast::<SOCKADDR_IN>() };
                    // SAFETY: `S_addr` is the plain-`u32` member of the `IN_ADDR` union,
                    // always valid to read; the bytes are in network order.
                    let bytes = unsafe { sin.sin_addr.S_un.S_addr }.to_ne_bytes();
                    iface.ipv4.push(Ipv4Addr::from(bytes));
                } else if family == AF_INET6 {
                    // SAFETY: AF_INET6 => the sockaddr is a SOCKADDR_IN6.
                    let sin6 = unsafe { &*sa.cast::<SOCKADDR_IN6>() };
                    // SAFETY: `Byte` is the 16-byte array member of the `IN6_ADDR`
                    // union, always valid to read (network order).
                    let bytes = unsafe { sin6.sin6_addr.u.Byte };
                    iface.ipv6.push(Ipv6Addr::from(bytes));
                }
            }
            out.push(iface);
        }
        Ok(out)
    }
}

// Miri cannot execute the `getifaddrs` FFI, so these run under the normal test
// harness (and the unsafe-audit gate) but are skipped under miri.
#[cfg(all(test, unix, not(miri)))]
mod tests {
    use super::*;

    #[test]
    fn enumerates_and_finds_loopback() {
        let ifaces = interfaces().expect("getifaddrs should succeed on the CI host");
        assert!(!ifaces.is_empty(), "expected at least one interface");

        // Every host has a loopback; it must be flagged and carry 127.0.0.1 or ::1.
        let lo = ifaces
            .iter()
            .find(|i| i.is_loopback)
            .expect("a loopback interface");
        assert!(lo.is_up, "loopback should be up");
        let has_lo_addr = lo.ipv4.contains(&Ipv4Addr::LOCALHOST)
            || lo.ipv6.contains(&std::net::Ipv6Addr::LOCALHOST);
        assert!(has_lo_addr, "loopback should bind 127.0.0.1 or ::1");
    }

    #[test]
    fn names_are_unique_and_nonempty() {
        let ifaces = interfaces().unwrap();
        let mut names: Vec<&str> = ifaces.iter().map(|i| i.name.as_str()).collect();
        names.sort_unstable();
        let before = names.len();
        names.dedup();
        assert_eq!(before, names.len(), "interface names must be unique");
        assert!(ifaces.iter().all(|i| !i.name.is_empty()));
    }

    #[test]
    fn non_loopback_up_interface_has_an_address_or_mac() {
        // Sanity: a real up, non-loopback interface should have at least a MAC or IP.
        for i in interfaces()
            .unwrap()
            .iter()
            .filter(|i| i.is_up && !i.is_loopback)
        {
            assert!(
                i.mac.is_some() || !i.ipv4.is_empty() || !i.ipv6.is_empty(),
                "interface {} has neither MAC nor address",
                i.name
            );
        }
    }
}
