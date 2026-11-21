//! Host groups: which targets nmap scans together, and in what order.
//!
//! nmap does not scan a run's targets as one set. It forms a **host group**, runs
//! every phase over it (port scans, `-sV`, `-O`, scripts), reports its hosts, frees
//! it, and forms the next (`nmap.cc`'s main loop). This module is the pure half of
//! that: given the targets in order, it yields the groups 7.94 would form. It ports
//!
//! * `determineScanGroupSize` (`scan_engine.cc`) as [`scan_group_size`]: how many
//!   hosts a group may hold, from the scan types, the TCP port count, the timing
//!   level and `--min-hostgroup`/`--max-hostgroup`;
//! * `target_needs_new_hostgroup` (`targets.cc`): for a routed (raw) scan, a group
//!   shares one address family, interface, source address and direct-connectedness,
//!   and holds no address twice;
//! * the batch behind it, `refresh_hostbatch` and `nexthost` (`targets.cc`): targets
//!   are drawn [`PING_GROUP_SZ`] at a time, and one that does not fit the batch is
//!   **deferred** to the next, so later targets that do fit overtake it. Up to
//!   [`DEFER_LIMIT`] wait at once; when that buffer fills, the batch ends early.
//!
//! The order matters as much as the sizes: it is the order hosts are scanned and
//! reported in. Both are checked against 7.94 itself, which prints each group under
//! `-v` (`tests/differential/m7/hostgroup_golden.txt`).
//!
//! ## Scope / divergences
//!
//! * The port sends no host-discovery probes, so every target counts toward a
//!   group. 7.94 drops a host its ping found down as it draws it, without counting
//!   it (`nmap.cc`, the loop's `HOST_UP` test).
//! * `--randomize-hosts` (which quadruples the batch) and `-iR` are not ported, nor
//!   are SCTP scans, whose groups are 128 like UDP's.
//! * There is no untrusted input here: sizes come from the command line and keys
//!   from this host's routing table. A group is bounded by the operator's
//!   `--max-hostgroup` (default 100,000) and the size rule, a batch by
//!   `max(PING_GROUP_SZ, --min-hostgroup)`, and the defer buffer by [`DEFER_LIMIT`].

use std::collections::{HashSet, VecDeque};
use std::net::IpAddr;

/// How many targets are drawn at a time (`PING_GROUP_SZ`, `nmap.h`). nmap pings a
/// batch at once; here it is only what bounds how far a deferred target can fall
/// behind.
pub const PING_GROUP_SZ: usize = 4096;

/// How many deferred targets may wait at once (`HostGroupState::DEFER_LIMIT`,
/// `targets.h`). The batch being filled ends when the buffer reaches this.
pub const DEFER_LIMIT: usize = 64;

/// What [`scan_group_size`] reads of the run's options.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GroupSizing {
    /// A UDP scan is among the scan types (`o.UDPScan()`). Tested first, as C does,
    /// so `-sS -sU` sizes as UDP.
    pub udp: bool,
    /// A TCP scan is among them (`o.TCPScan()`): connect, SYN, ACK, Window, Maimon,
    /// FIN, NULL or Xmas.
    pub tcp: bool,
    /// The number of TCP ports to scan (`ports->tcp_count`).
    pub tcp_ports: usize,
    /// `-T`'s level, 0 to 5 (`o.timing_level`).
    pub timing_level: u8,
    /// `--min-hostgroup` (default 1).
    pub min_hostgroup: u32,
    /// `--max-hostgroup` (default 100,000).
    pub max_hostgroup: u32,
}

/// The ideal size of the next group, given how many hosts earlier groups held
/// (`determineScanGroupSize`).
///
/// 16 unless a scan type says otherwise: 128 for UDP; for TCP, `1024 / ports` and
/// at least 64. A TCP scan of more than 1,000 ports at `-T4` or slower starts with
/// a small group, 4 hosts (8 at `-T4`), "to give quick results", and shortens the
/// next by as much, to stay on network boundaries. The result is then held within
/// the operator's bounds, which therefore win over every rule above.
#[must_use]
pub fn scan_group_size(hosts_scanned: usize, s: &GroupSizing) -> usize {
    let mut size: usize = 16;
    if s.udp {
        size = 128;
    } else if s.tcp {
        // No ports is one port to this rule, as in C.
        size = 1024_usize.checked_div(s.tcp_ports).unwrap_or(1024).max(64);
        if s.tcp_ports > 1000 && s.timing_level <= 4 {
            let quick: usize = if s.timing_level == 4 { 8 } else { 4 };
            if hosts_scanned == 0 {
                size = quick;
            } else if hosts_scanned == quick && size > quick.saturating_mul(2) {
                size = size.saturating_sub(quick);
            }
        }
    }
    // C's `box(min, max, size)`: the minimum first, then the maximum, so the
    // maximum wins if the two cross (they cannot: the options are validated).
    let min = usize::try_from(s.min_hostgroup).unwrap_or(usize::MAX);
    let max = usize::try_from(s.max_hostgroup).unwrap_or(usize::MAX);
    size.max(min).min(max).max(1)
}

/// The route a raw scan sends a target's probes by: what a group must share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// The interface (`Target::deviceName`).
    pub iface: String,
    /// The source address (`Target::SourceSockAddr`).
    pub source: IpAddr,
    /// Whether the target is on that interface's link (`Target::directlyConnected`).
    pub direct: bool,
}

/// One target of the run, with what grouping reads of it and whatever the caller
/// carries along (`item`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member<T> {
    /// The target's address. A routed group holds no address twice.
    pub address: IpAddr,
    /// Its route, for a scan that routes its targets (a raw scan). `None` for one
    /// that does not (a connect scan): C applies no homogeneity rule then
    /// (`target_needs_new_hostgroup`'s "no restrictions on non-root scans").
    pub route: Option<RouteKey>,
    /// The caller's own data for this target.
    pub item: T,
}

/// Whether `target` must wait for a later group than the one `first` began and
/// `addresses` lists (`target_needs_new_hostgroup`).
fn needs_new_group<T>(first: &Member<T>, addresses: &HashSet<IpAddr>, target: &Member<T>) -> bool {
    let Some(route) = &target.route else {
        return false;
    };
    if first.address.is_ipv4() != target.address.is_ipv4() {
        return true;
    }
    if let Some(group) = &first.route {
        if group.iface != route.iface
            || group.source != route.source
            || group.direct != route.direct
        {
            return true;
        }
    }
    // "ultra_scan doesn't cope with that, because it uses IP addresses to look up
    // targets from replies."
    addresses.contains(&target.address)
}

/// A run's targets as the groups nmap scans them in: an iterator of groups.
///
/// It draws from `source` only as far as the next group needs (at most a batch
/// ahead, plus the defer buffer), so a large target list is never held whole.
pub struct HostGroups<I, T>
where
    I: Iterator<Item = Member<T>>,
{
    source: I,
    sizing: GroupSizing,
    batch_size: usize,
    /// The batch drawn and not yet handed out, in order (`hostbatch` from
    /// `next_batch_no` on).
    batch: VecDeque<Member<T>>,
    /// Deferred while the current batch was filled (`defer_buffer`).
    deferred: Vec<Member<T>>,
    /// Deferred by an earlier batch, to be drawn before `source` (`undeferred`).
    undeferred: VecDeque<Member<T>>,
    /// Hosts in the groups handed out so far (`o.numhosts_scanned`).
    scanned: usize,
}

impl<I, T> HostGroups<I, T>
where
    I: Iterator<Item = Member<T>>,
{
    /// Group `source` under `sizing`. The batch is [`PING_GROUP_SZ`], or
    /// `--min-hostgroup` when that is larger (`nmap.cc`, before the main loop).
    pub fn new(source: I, sizing: GroupSizing) -> Self {
        let min = usize::try_from(sizing.min_hostgroup).unwrap_or(usize::MAX);
        HostGroups {
            source,
            sizing,
            batch_size: PING_GROUP_SZ.max(min),
            batch: VecDeque::new(),
            deferred: Vec::new(),
            undeferred: VecDeque::new(),
            scanned: 0,
        }
    }

    /// Fill the batch (`refresh_hostbatch`): the targets earlier batches deferred
    /// first, then the source. One that does not fit the batch is deferred; when
    /// [`DEFER_LIMIT`] are waiting, the batch ends.
    fn refresh(&mut self) {
        self.undeferred.extend(self.deferred.drain(..));
        let mut addresses: HashSet<IpAddr> = HashSet::new();
        while self.batch.len() < self.batch_size {
            let Some(target) = self.undeferred.pop_front().or_else(|| self.source.next()) else {
                break;
            };
            let misfit = self
                .batch
                .front()
                .is_some_and(|first| needs_new_group(first, &addresses, &target));
            if misfit {
                self.deferred.push(target);
                if self.deferred.len() < DEFER_LIMIT {
                    continue;
                }
                break;
            }
            addresses.insert(target.address);
            self.batch.push_back(target);
        }
    }

    /// The next target in batch order (`nexthost`).
    fn next_host(&mut self) -> Option<Member<T>> {
        if self.batch.is_empty() {
            self.refresh();
        }
        self.batch.pop_front()
    }
}

impl<I, T> Iterator for HostGroups<I, T>
where
    I: Iterator<Item = Member<T>>,
{
    type Item = Vec<Member<T>>;

    /// The next group (`nmap.cc`'s main loop): targets in batch order until the
    /// group has its ideal size, the targets run out, or the next one cannot share
    /// a group with those drawn, in which case it is handed back (`returnhost`)
    /// and starts the next group.
    fn next(&mut self) -> Option<Self::Item> {
        let ideal = scan_group_size(self.scanned, &self.sizing);
        let mut group: Vec<Member<T>> = Vec::new();
        let mut addresses: HashSet<IpAddr> = HashSet::new();
        while group.len() < ideal {
            let Some(target) = self.next_host() else {
                break;
            };
            if group
                .first()
                .is_some_and(|first| needs_new_group(first, &addresses, &target))
            {
                self.batch.push_front(target);
                break;
            }
            addresses.insert(target.address);
            group.push(target);
        }
        if group.is_empty() {
            return None;
        }
        self.scanned = self.scanned.saturating_add(group.len());
        Some(group)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    fn sizing() -> GroupSizing {
        GroupSizing {
            udp: false,
            tcp: true,
            tcp_ports: 1,
            timing_level: 3,
            min_hostgroup: 1,
            max_hostgroup: 100_000,
        }
    }

    /// `determineScanGroupSize`, rule by rule.
    #[test]
    fn the_size_follows_scan_type_port_count_and_timing() {
        let tcp = |ports| GroupSizing {
            tcp_ports: ports,
            ..sizing()
        };
        // 1024 / ports, and never under 64.
        for (ports, want) in [
            (0, 1024),
            (1, 1024),
            (2, 512),
            (15, 68),
            (16, 64),
            (17, 64),
            (1000, 64),
        ] {
            assert_eq!(scan_group_size(0, &tcp(ports)), want, "{ports} ports");
            assert_eq!(
                scan_group_size(500, &tcp(ports)),
                want,
                "{ports} ports, later"
            );
        }
        // Past 1,000 ports: a quick first group, and the next shortened by it.
        assert_eq!(scan_group_size(0, &tcp(1001)), 4);
        assert_eq!(scan_group_size(4, &tcp(1001)), 60);
        assert_eq!(scan_group_size(64, &tcp(1001)), 64);
        assert_eq!(scan_group_size(3, &tcp(1001)), 64, "a short first group");
        let at = |level| GroupSizing {
            timing_level: level,
            ..tcp(1001)
        };
        assert_eq!(
            (scan_group_size(0, &at(4)), scan_group_size(8, &at(4))),
            (8, 56)
        );
        assert_eq!(scan_group_size(4, &at(4)), 64, "4 is -T3's first group");
        assert_eq!(scan_group_size(0, &at(5)), 64, "-T5 has no quick group");
        assert_eq!(scan_group_size(0, &at(0)), 4);
        // UDP is 128 and is tested before TCP; neither is 16.
        let udp = GroupSizing {
            udp: true,
            tcp_ports: 2000,
            ..sizing()
        };
        assert_eq!(scan_group_size(0, &udp), 128);
        let neither = GroupSizing {
            tcp: false,
            ..sizing()
        };
        assert_eq!(scan_group_size(0, &neither), 16);
    }

    /// The operator's bounds hold the result, over every other rule.
    #[test]
    fn the_operators_bounds_win() {
        let bounded = |min, max, ports| GroupSizing {
            tcp_ports: ports,
            min_hostgroup: min,
            max_hostgroup: max,
            ..sizing()
        };
        assert_eq!(scan_group_size(0, &bounded(1, 2, 1)), 2);
        assert_eq!(scan_group_size(0, &bounded(100, 100_000, 20)), 100);
        assert_eq!(
            scan_group_size(0, &bounded(6, 100_000, 1001)),
            6,
            "over the quick group"
        );
        assert_eq!(scan_group_size(4, &bounded(1, 3, 1001)), 3);
        assert_eq!(scan_group_size(0, &bounded(5000, 100_000, 1)), 5000);
        // A maximum of 0 is refused before this is reached; it is still a group.
        assert_eq!(scan_group_size(0, &bounded(0, 0, 1)), 1);
    }

    fn lo(source: [u8; 4]) -> Option<RouteKey> {
        Some(RouteKey {
            iface: "lo".into(),
            source: IpAddr::V4(Ipv4Addr::from(source)),
            direct: true,
        })
    }

    fn member(last: u8, route: Option<RouteKey>) -> Member<u8> {
        Member {
            address: IpAddr::V4(Ipv4Addr::new(10, 0, 0, last)),
            route,
            item: last,
        }
    }

    fn groups(targets: Vec<Member<u8>>, sizing: GroupSizing) -> Vec<Vec<u8>> {
        HostGroups::new(targets.into_iter(), sizing)
            .map(|g| g.into_iter().map(|m| m.item).collect())
            .collect()
    }

    /// Each thing a routed group must share, and the address it may not repeat.
    #[test]
    fn a_routed_group_is_homogeneous() {
        let a = lo([127, 0, 0, 1]);
        let other_source = lo([192, 0, 2, 2]);
        let other_iface = Some(RouteKey {
            iface: "eth0".into(),
            ..a.clone().unwrap()
        });
        let off_link = Some(RouteKey {
            direct: false,
            ..a.clone().unwrap()
        });
        for (name, odd) in [
            ("source", other_source),
            ("interface", other_iface),
            ("directness", off_link),
        ] {
            let got = groups(
                vec![member(1, a.clone()), member(2, odd), member(3, a.clone())],
                sizing(),
            );
            assert_eq!(
                got,
                [vec![1, 3], vec![2]],
                "a different {name} waits, and is overtaken"
            );
        }
        // The same address again waits too.
        let got = groups(
            vec![
                member(1, a.clone()),
                member(1, a.clone()),
                member(2, a.clone()),
            ],
            sizing(),
        );
        assert_eq!(got, [vec![1, 2], vec![1]]);
        // Another family.
        let v6 = Member {
            address: IpAddr::V6(Ipv6Addr::LOCALHOST),
            route: a.clone(),
            item: 6,
        };
        let got = groups(vec![member(1, a.clone()), v6, member(2, a)], sizing());
        assert_eq!(got, [vec![1, 2], vec![6]]);
    }

    /// A scan that does not route its targets has no such rule: mixed sources and
    /// repeats share a group, in input order.
    #[test]
    fn an_unrouted_scan_groups_by_size_alone() {
        let got = groups(
            vec![member(1, None), member(1, None), member(2, None)],
            sizing(),
        );
        assert_eq!(got, [vec![1, 1, 2]]);
    }

    /// `--min-hostgroup` cannot merge what the rule separates, and a group does
    /// not reach across a batch to fill itself with a target that does not fit.
    #[test]
    fn the_minimum_does_not_override_homogeneity() {
        let a = lo([127, 0, 0, 1]);
        let b = lo([192, 0, 2, 2]);
        let min3 = GroupSizing {
            min_hostgroup: 3,
            ..sizing()
        };
        let got = groups(vec![member(1, a.clone()), member(2, b), member(3, a)], min3);
        assert_eq!(got, [vec![1, 3], vec![2]]);
    }

    /// The defer buffer holds [`DEFER_LIMIT`]: the target that fills it ends the
    /// batch, so targets after it are not drawn into this batch even if they fit.
    #[test]
    fn a_full_defer_buffer_ends_the_batch() {
        let a = lo([127, 0, 0, 1]);
        let b = lo([192, 0, 2, 2]);
        let odd = |n: usize| -> Vec<Member<u8>> {
            // Distinct addresses on another source: each is deferred, none repeats.
            (0..n)
                .map(|i| member(100 + u8::try_from(i).unwrap(), b.clone()))
                .collect()
        };
        let run = |n: usize| {
            let mut t = vec![member(1, a.clone())];
            t.extend(odd(n));
            t.push(member(2, a.clone()));
            groups(t, sizing())
        };
        // One short of the limit: the fitting target after them joins the first.
        let got = run(DEFER_LIMIT - 1);
        assert_eq!(got[0], [1, 2]);
        assert_eq!(got[1].len(), DEFER_LIMIT - 1);
        // At the limit the batch ends with the first target alone. The deferred
        // ones form the next batch, and the fitting one is deferred behind them.
        let got = run(DEFER_LIMIT);
        assert_eq!(got[0], [1]);
        assert_eq!(got[1].len(), DEFER_LIMIT);
        assert_eq!(got[2], [2]);
    }

    /// The quick-group rule reads the hosts of every group so far, not of the last
    /// one: a later group that happens to hold four hosts shortens nothing. It
    /// takes three routes to end a batch on such a group, which loopback and one
    /// address cannot give the golden.
    #[test]
    fn hosts_scanned_counts_every_earlier_group() {
        let route = |last: u8| lo([127, 0, 0, last]);
        let on = |r: &Option<RouteKey>, n: u32, base: u32| -> Vec<Member<u32>> {
            (0..n)
                .map(|i| Member {
                    address: IpAddr::V4(Ipv4Addr::from(base + i)),
                    route: r.clone(),
                    item: base + i,
                })
                .collect()
        };
        let (a, b, c) = (route(1), route(2), route(3));
        // 68 on one route, then 64 on a second (they fill the defer buffer and end
        // the batch), then one on a third so the second's batch ends too.
        let mut targets = on(&a, 68, 0x0a00_0000);
        targets.extend(on(&b, 64, 0x0a01_0000));
        targets.extend(on(&c, 1, 0x0a02_0000));
        let many_ports = GroupSizing {
            tcp_ports: 1001,
            ..sizing()
        };
        let sizes: Vec<usize> = HostGroups::new(targets.into_iter(), many_ports)
            .map(|g| g.len())
            .collect();
        assert_eq!(sizes, [4, 60, 4, 64, 1]);
    }

    /// The source is drawn only as far as a batch and its defer buffer need.
    #[test]
    fn the_source_is_drawn_lazily() {
        use std::cell::Cell;
        let drawn = Cell::new(0usize);
        let source = (0u32..1_000_000).map(|i| {
            drawn.set(drawn.get() + 1);
            Member {
                address: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)),
                route: None,
                item: i,
            }
        });
        let capped = GroupSizing {
            max_hostgroup: 10,
            ..sizing()
        };
        let mut g = HostGroups::new(source, capped);
        assert_eq!(g.next().map(|v| v.len()), Some(10));
        assert_eq!(drawn.get(), PING_GROUP_SZ, "one batch, not the run");
        // A minimum above the batch raises the batch to it.
        let wide = GroupSizing {
            min_hostgroup: 5000,
            ..sizing()
        };
        let source = (0u32..6000).map(|i| Member {
            address: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)),
            route: None,
            item: i,
        });
        let sizes: Vec<usize> = HostGroups::new(source, wide).map(|v| v.len()).collect();
        assert_eq!(sizes, [5000, 1000]);
    }

    #[test]
    fn no_targets_no_groups() {
        assert!(groups(Vec::new(), sizing()).is_empty());
    }
}
