//! The `getifaddrs(3)` escape-hatch backend (feature `raw-ffi`, Unix only).
//!
//! Enabled off the beaten path: the default [`super::interfaces`] uses `netdev`. This
//! module exists to cross-check `netdev` against the raw OS call and to reach a field
//! `netdev` might not expose. It is the only `unsafe` in the interface layer, and the
//! `getifaddrs` list is owned by an RAII guard that frees it exactly once.

use super::{Interface, Ipv4Net, Ipv6Net};
use std::collections::BTreeMap;
use std::ffi::CStr;
use std::net::{Ipv4Addr, Ipv6Addr};
use std::ptr;

/// RAII owner of the `ifaddrs` list; `freeifaddrs` runs exactly once on drop.
struct IfAddrs(*mut libc::ifaddrs);

impl Drop for IfAddrs {
    fn drop(&mut self) {
        // SAFETY: `self.0` was returned by a successful `getifaddrs` and is owned
        // solely by this guard; `freeifaddrs` is its matching deallocator.
        unsafe { libc::freeifaddrs(self.0) };
    }
}

/// Number of set bits in an IPv4 netmask (its prefix length). Sum is 0..=32.
fn ipv4_prefix(mask: [u8; 4]) -> u8 {
    u8::try_from(mask.iter().map(|b| b.count_ones()).sum::<u32>()).unwrap_or(32)
}

/// Number of set bits in an IPv6 netmask. Sum is 0..=128.
fn ipv6_prefix(mask: [u8; 16]) -> u8 {
    u8::try_from(mask.iter().map(|b| b.count_ones()).sum::<u32>()).unwrap_or(128)
}

pub(super) fn interfaces() -> std::io::Result<Vec<Interface>> {
    let mut head: *mut libc::ifaddrs = ptr::null_mut();
    // SAFETY: `getifaddrs` writes a heap-allocated list head through the out-param on
    // success (return 0) and leaves it untouched otherwise; we pass a valid pointer to
    // our local and check the return code before using `head`.
    let rc = unsafe { libc::getifaddrs(&mut head) };
    if rc != 0 {
        return Err(std::io::Error::last_os_error());
    }
    // Own the list immediately so every early return frees it.
    let _guard = IfAddrs(head);

    let mut by_name: BTreeMap<String, Interface> = BTreeMap::new();
    let mut cur = head;
    while !cur.is_null() {
        // SAFETY: `cur` is non-null (loop guard) and points to a live list node owned
        // by `_guard`; the list is not mutated while we walk it.
        let ifa = unsafe { &*cur };
        cur = ifa.ifa_next;

        if ifa.ifa_name.is_null() {
            continue;
        }
        // SAFETY: `ifa_name` is a NUL-terminated C string valid for `_guard`'s life.
        let name = unsafe { CStr::from_ptr(ifa.ifa_name) }
            .to_string_lossy()
            .into_owned();

        let entry = by_name.entry(name.clone()).or_insert_with(|| Interface {
            name: name.clone(),
            index: 0,
            mac: None,
            ipv4: Vec::new(),
            ipv6: Vec::new(),
            mtu: None,
            is_up: false,
            is_loopback: false,
            gateway: None,
        });

        let flags = ifa.ifa_flags;
        #[allow(clippy::cast_sign_loss)]
        let iff_up = libc::IFF_UP as u32;
        #[allow(clippy::cast_sign_loss)]
        let iff_loopback = libc::IFF_LOOPBACK as u32;
        entry.is_up |= flags & iff_up != 0;
        entry.is_loopback |= flags & iff_loopback != 0;

        if entry.index == 0 {
            // SAFETY: `ifa_name` is a valid C string; `if_nametoindex` reads it and
            // returns 0 on error, which we keep as "unknown".
            entry.index = unsafe { libc::if_nametoindex(ifa.ifa_name) };
        }

        if ifa.ifa_addr.is_null() {
            continue;
        }
        // SAFETY: `ifa_addr` points to a `sockaddr` whose leading `sa_family` field is
        // always present regardless of the concrete address variant.
        let family = i32::from(unsafe { (*ifa.ifa_addr).sa_family });

        match family {
            libc::AF_INET => {
                // SAFETY: family AF_INET => `ifa_addr` points to a `sockaddr_in`.
                let sin = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in>() };
                let addr = Ipv4Addr::from(sin.sin_addr.s_addr.to_ne_bytes());
                let prefix_len = if ifa.ifa_netmask.is_null() {
                    32
                } else {
                    // SAFETY: a non-null netmask for AF_INET is a `sockaddr_in`.
                    let m = unsafe { &*ifa.ifa_netmask.cast::<libc::sockaddr_in>() };
                    ipv4_prefix(m.sin_addr.s_addr.to_ne_bytes())
                };
                entry.ipv4.push(Ipv4Net { addr, prefix_len });
            }
            libc::AF_INET6 => {
                // SAFETY: family AF_INET6 => `ifa_addr` points to a `sockaddr_in6`.
                let sin6 = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_in6>() };
                let addr = Ipv6Addr::from(sin6.sin6_addr.s6_addr);
                let prefix_len = if ifa.ifa_netmask.is_null() {
                    128
                } else {
                    // SAFETY: a non-null netmask for AF_INET6 is a `sockaddr_in6`.
                    let m = unsafe { &*ifa.ifa_netmask.cast::<libc::sockaddr_in6>() };
                    ipv6_prefix(m.sin6_addr.s6_addr)
                };
                entry.ipv6.push(Ipv6Net { addr, prefix_len });
            }
            #[cfg(target_os = "linux")]
            libc::AF_PACKET => {
                // SAFETY: family AF_PACKET => `ifa_addr` points to a `sockaddr_ll`.
                let sll = unsafe { &*ifa.ifa_addr.cast::<libc::sockaddr_ll>() };
                if sll.sll_halen >= 6 {
                    let mut mac = [0u8; 6];
                    mac.copy_from_slice(&sll.sll_addr[..6]);
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
