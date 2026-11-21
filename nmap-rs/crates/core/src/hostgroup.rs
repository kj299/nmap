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
//! * Every target here takes a place in a group. In 7.94 a host found down takes
//!   none: the loop reports and frees it as it is drawn, and adds it to
//!   `o.numhosts_scanned`, which the quick-group rule reads (`nmap.cc`, the loop's
//!   `HOST_UP` test). The port has no such verdict when it forms a group: it
//!   sends no IPv4 discovery probes at all, and its one discovery, the IPv6 ND
//!   ping, runs after grouping. `-Pn` does not close the gap: 7.94 still puts
//!   an on-link Ethernet target to its ARP or ND ping under `-Pn`
//!   (`refresh_hostbatch`'s `arpping`, which no ping type switches off), and a
//!   silent one is down.
//!   The two agree when every target is up; step b decides how a down verdict
//!   enters here.
//! * `--randomize-hosts` (which quadruples the batch) and `-iR` are not ported, nor
//!   are SCTP scans, whose groups are 128 like UDP's.
//! * The source is asked again after it has ended: whenever a group wants a
//!   target and the batch is spent, as `nexthost` calls `refresh_hostbatch`.
//!   7.94's source resumes. Targets a script adds (`target.add`) are read by
//!   `next_expression` once the command line is spent, so they are drawn after
//!   the command line's targets, and from there are batched, deferred and
//!   grouped like any other target. The targets a source here yields after its
//!   end are treated the same way, and [`HostGroups`] may likewise yield a
//!   group after it has yielded `None`.
//!   7.94's loop ends at the first empty group, so a caller stops at the first
//!   `None`. The port does not scan script-added targets yet
//!   (`nse-new-targets-not-scanned`); when it does, this is the way in. A caller
//!   whose iterator must not be asked past its end fuses it.
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
    /// FIN, NULL or Xmas. C's predicate also holds for the bounce and idle scans,
    /// which are not ported.
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
    // C's `box(min, max, size)`. It asserts `min <= max`. 7.94 refuses a minimum
    // above the maximum, but a maximum that reads negative as a 32-bit `int`
    // (`-1`, or anything from 2^31 to 2^32 - 1) passes its checks and trips the
    // assertion. The caller must refuse both kinds; if the two crossed here,
    // this would return the maximum. The final `max(1)` is not in C: a group of
    // none would end the run, and nothing valid reaches it.
    let min = usize::try_from(s.min_hostgroup).unwrap_or(usize::MAX);
    let max = usize::try_from(s.max_hostgroup).unwrap_or(usize::MAX);
    size.max(min).min(max).max(1)
}

/// The route a raw scan sends a target's probes by: what a group must share.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct RouteKey {
    /// The interface (`Target::deviceName`).
    pub iface: String,
    /// The source address the probes carry (`Target::SourceSockAddr`): `-S`'s when
    /// given, which makes one group of targets the routing table would separate.
    pub source: IpAddr,
    /// Whether the target is on that interface's link (`Target::directlyConnected`).
    pub direct: bool,
}

impl RouteKey {
    /// The key of a routed run's target that has no route. 7.94 drops such a
    /// target before grouping (`targets.cc:409-413`), so it shapes no group;
    /// the port keeps it, to report it (`raw-scan-unroutable-target-reported`).
    /// No interface is named "", so this key matches no routed target's, and
    /// [`HostGroups`] sets a target with it aside as it is drawn: it takes no
    /// batch or defer slot, is not counted as scanned, and is handed out in
    /// groups of unroutable targets alone; it ends no batch and no group.
    /// (`None` would mean "not routed",
    /// and lift the rule for the whole group.)
    #[must_use]
    pub fn unroutable(target: IpAddr) -> Self {
        RouteKey {
            iface: String::new(),
            source: match target {
                IpAddr::V4(_) => IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED),
                IpAddr::V6(_) => IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED),
            },
            direct: false,
        }
    }

    /// Whether this is [`RouteKey::unroutable`]'s key: no interface is named "".
    #[must_use]
    pub fn is_unroutable(&self) -> bool {
        self.iface.is_empty()
    }
}

/// One target of the run, with what grouping reads of it and whatever the caller
/// carries along (`item`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Member<T> {
    /// The target's address. A routed group holds no address twice.
    pub address: IpAddr,
    /// Its route, when the run routes its targets, and `None` when it does not: C
    /// applies no homogeneity rule then (`target_needs_new_hostgroup`'s "no
    /// restrictions on non-root scans"). 7.94 routes a target when it is root and
    /// `o.RawScan()` holds (`targets.cc`, `NmapOps.cc`). That is every raw port
    /// scan, and also a connect scan with `-O` or `--traceroute`, or without
    /// `-Pn`, whose pings are raw. Only an unprivileged run, or a connect scan
    /// under `-Pn` with neither, has no route.
    pub route: Option<RouteKey>,
    /// The caller's own data for this target.
    pub item: T,
}

/// Whether `target` must wait for a later group than the one `first` began and
/// `addresses` lists (`target_needs_new_hostgroup`).
fn needs_new_group<T>(first: &Member<T>, addresses: &HashSet<IpAddr>, target: &Member<T>) -> bool {
    misfits(first.address, first.route.as_ref(), addresses, target)
}

/// [`needs_new_group`] against a first target known by its address and route,
/// as a suspended batch fill remembers it.
fn misfits<T>(
    first_address: IpAddr,
    first_route: Option<&RouteKey>,
    addresses: &HashSet<IpAddr>,
    target: &Member<T>,
) -> bool {
    let Some(route) = &target.route else {
        return false;
    };
    if first_address.is_ipv4() != target.address.is_ipv4() {
        return true;
    }
    if let Some(group) = first_route {
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

/// A batch fill under way (`refresh_hostbatch`'s locals), kept while it is
/// suspended: the batch's first target, the addresses placed, how many.
#[derive(Default)]
struct Fill {
    first: Option<(IpAddr, Option<RouteKey>)>,
    addresses: HashSet<IpAddr>,
    placed: usize,
}

/// Whether `m` is a routed run's target with no route ([`RouteKey::unroutable`]).
fn is_unroutable<T>(m: &Member<T>) -> bool {
    m.route.as_ref().is_some_and(RouteKey::is_unroutable)
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
    /// Unroutable targets of a routed run, set aside as they are drawn. 7.94
    /// drops such a target in `setup_target` (`targets.cc:409-413`) before it
    /// reaches the batch, so it takes no batch or defer slot; the port keeps it
    /// to report it, in groups of its own, at most a batch ahead.
    unroutable: VecDeque<Member<T>>,
    /// A fill suspended because a batch's worth of unroutable targets are
    /// waiting: it resumes, with its first target and addresses, once they
    /// are handed out, so they end no batch (7.94 never sees them).
    fill: Option<Fill>,
    /// A routed group that ran dry while its fill was suspended, with its
    /// addresses: kept (at most a group, as 7.94's `Targets` is) while the
    /// unroutable targets are handed out, then completed from the resumed
    /// fill, as 7.94's group goes on into a batch that holds none of them.
    partial: Option<(Vec<Member<T>>, HashSet<IpAddr>)>,
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
            unroutable: VecDeque::new(),
            fill: None,
            partial: None,
            scanned: 0,
        }
    }

    /// Fill the batch (`refresh_hostbatch`): the targets earlier batches deferred
    /// first, then the source. One that does not fit the batch is deferred; when
    /// [`DEFER_LIMIT`] are waiting, the batch ends.
    fn refresh(&mut self) {
        let mut fill = if let Some(fill) = self.fill.take() {
            fill
        } else {
            self.undeferred.extend(self.deferred.drain(..));
            Fill::default()
        };
        while fill.placed < self.batch_size {
            let Some(target) = self.undeferred.pop_front().or_else(|| self.source.next()) else {
                break;
            };
            if is_unroutable(&target) {
                self.unroutable.push_back(target);
                if self.unroutable.len() < self.batch_size {
                    continue;
                }
                // A batch's worth waiting: suspend, to resume once they are out.
                self.fill = Some(fill);
                return;
            }
            let misfit = fill.first.as_ref().is_some_and(|(address, route)| {
                misfits(*address, route.as_ref(), &fill.addresses, &target)
            });
            if misfit {
                self.deferred.push(target);
                if self.deferred.len() < DEFER_LIMIT {
                    continue;
                }
                break;
            }
            if fill.first.is_none() {
                fill.first = Some((target.address, target.route.clone()));
            }
            fill.addresses.insert(target.address);
            fill.placed = fill.placed.saturating_add(1);
            self.batch.push_back(target);
        }
    }

    /// The unroutable targets set aside, as a group of their own: one family,
    /// no address twice; one that cannot join waits for the next.
    fn unroutable_group(&mut self, ideal: usize) -> Vec<Member<T>> {
        let mut group: Vec<Member<T>> = Vec::new();
        let mut addresses: HashSet<IpAddr> = HashSet::new();
        while group.len() < ideal {
            let Some(target) = self.unroutable.pop_front() else {
                break;
            };
            if group
                .first()
                .is_some_and(|first| needs_new_group(first, &addresses, &target))
            {
                self.unroutable.push_front(target);
                break;
            }
            addresses.insert(target.address);
            group.push(target);
        }
        group
    }

    /// The next target in batch order (`nexthost`). While a fill is suspended
    /// no new one starts: the group in progress is kept (`partial`) until it
    /// resumes.
    fn next_host(&mut self) -> Option<Member<T>> {
        if self.batch.is_empty() && self.fill.is_none() {
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
        loop {
            let ideal = scan_group_size(self.scanned, &self.sizing);
            // Finish the fill under way, or start one, before a routed group is
            // formed; the unroutable targets it sets aside come out first, as
            // groups of their own, not counted as scanned.
            if self.unroutable.is_empty()
                && (self.fill.is_some() || (self.batch.is_empty() && self.partial.is_none()))
            {
                self.refresh();
            }
            if !self.unroutable.is_empty() {
                return Some(self.unroutable_group(ideal));
            }
            // A group kept while its fill was suspended goes on where it was;
            // `scanned` has not moved since, so neither has `ideal`.
            let (mut group, mut addresses) = self.partial.take().unwrap_or_default();
            while group.len() < ideal {
                let Some(target) = self.next_host() else {
                    if self.fill.is_some() {
                        // Dry with the fill suspended: keep the group, hand out
                        // the unroutable targets, resume, and go on.
                        self.partial =
                            Some((std::mem::take(&mut group), std::mem::take(&mut addresses)));
                        break;
                    }
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
            if self.partial.is_some() {
                continue;
            }
            if group.is_empty() {
                if self.unroutable.is_empty() && self.fill.is_none() {
                    return None;
                }
                continue;
            }
            // `o.numhosts_scanned` (`nmap.cc:2337`) counts the targets 7.94
            // scans; a routed group holds no unroutable one.
            self.scanned = self.scanned.saturating_add(group.len());
            return Some(group);
        }
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

    /// In a routed run, a target with no route neither joins a routed group nor
    /// lifts the rule for one: the unroutable ones group alone, ahead of the
    /// routed targets drawn with them.
    #[test]
    fn an_unroutable_target_shapes_no_routed_group() {
        let a = lo([127, 0, 0, 1]);
        let eth = Some(RouteKey {
            iface: "eth0".into(),
            ..a.clone().unwrap()
        });
        let none = |last: u8| {
            let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, last));
            Member {
                address: addr,
                route: Some(RouteKey::unroutable(addr)),
                item: last,
            }
        };
        // Starting a group: the lo and eth0 targets still split from it and
        // from each other.
        let got = groups(
            vec![
                none(1),
                member(2, a.clone()),
                member(3, eth.clone()),
                none(4),
            ],
            sizing(),
        );
        assert_eq!(got, [vec![1, 4], vec![2], vec![3]]);
        // Between routed targets: it is set aside as it is drawn and reported
        // first, and the routed group is whole.
        let got = groups(vec![member(1, a.clone()), none(2), member(3, a)], sizing());
        assert_eq!(got, [vec![2], vec![1, 3]]);
    }

    /// An unroutable target is not counted as scanned, as 7.94 never scans it:
    /// the quick first group (`-T4`, over 1,000 ports: 8) still comes first
    /// for the routed targets after it.
    #[test]
    fn an_unroutable_target_does_not_count_toward_the_quick_group() {
        let quick = GroupSizing {
            tcp_ports: 65_535,
            timing_level: 4,
            ..sizing()
        };
        let a = lo([127, 0, 0, 1]);
        let routed: Vec<Member<u8>> = (1..=20).map(|i| member(i, a.clone())).collect();
        let alone: Vec<usize> = groups(routed.clone(), quick).iter().map(Vec::len).collect();
        assert_eq!(alone, [8, 12]);
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 1, 1));
        let mut with = vec![Member {
            address: addr,
            route: Some(RouteKey::unroutable(addr)),
            item: 0,
        }];
        with.extend(routed);
        let got: Vec<usize> = groups(with, quick).iter().map(Vec::len).collect();
        assert_eq!(got, [1, 8, 12]);
    }

    /// Unroutable targets take no defer slot: 64 of them between routed ones
    /// change no routed group, as 7.94, dropping them before the batch, has
    /// the routed ones alone (`targets.cc:409-413`).
    #[test]
    fn unroutable_targets_take_no_defer_slot() {
        let eth = |n: &str| {
            Some(RouteKey {
                iface: n.into(),
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                direct: true,
            })
        };
        let unroutable = |i: u8| {
            let addr = IpAddr::V4(Ipv4Addr::new(10, 1, 0, i));
            Member {
                address: addr,
                route: Some(RouteKey::unroutable(addr)),
                item: 100 + i,
            }
        };
        let mut with = vec![member(1, eth("eth0"))];
        with.extend((0..64).map(unroutable));
        with.extend([
            member(2, eth("eth0")),
            member(3, eth("eth1")),
            member(4, eth("eth0")),
        ]);
        let routed_groups: Vec<Vec<u8>> = groups(with, sizing())
            .into_iter()
            .filter(|g| g.iter().all(|&i| i < 100))
            .collect();
        let without = vec![
            member(1, eth("eth0")),
            member(2, eth("eth0")),
            member(3, eth("eth1")),
            member(4, eth("eth0")),
        ];
        assert_eq!(routed_groups, groups(without, sizing()));
        assert_eq!(routed_groups, [vec![1, 2, 4], vec![3]]);
    }

    /// A batch's worth of unroutable targets or more, inside one batch, end it
    /// no earlier than 7.94, which never sees them: the fill is suspended
    /// while they are handed out, and resumed. Below, at and past the cap.
    #[test]
    fn a_batch_of_unroutable_targets_ends_no_batch() {
        let route = |n: &str| {
            Some(RouteKey {
                iface: n.into(),
                source: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                direct: true,
            })
        };
        let unroutable = |i: u32| {
            let addr = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i));
            Member {
                address: addr,
                route: Some(RouteKey::unroutable(addr)),
                item: 0,
            }
        };
        for n in [
            PING_GROUP_SZ - 1,
            PING_GROUP_SZ,
            PING_GROUP_SZ + 904,
            3 * PING_GROUP_SZ,
        ] {
            let mut with = vec![member(1, route("a")), member(2, route("b"))];
            with.extend((0..u32::try_from(n).unwrap()).map(unroutable));
            with.push(member(3, route("a")));
            let got = groups(with, sizing());
            let routed: Vec<&Vec<u8>> = got.iter().filter(|g| !g.contains(&0)).collect();
            assert_eq!(routed, [&vec![1, 3], &vec![2]], "{n} unroutable");
            assert_eq!(
                got.iter().map(Vec::len).sum::<usize>(),
                n + 3,
                "{n}: none lost"
            );
        }
    }

    /// A group that runs into a new batch goes on through it, however many
    /// unroutable targets that batch holds before its routed ones, and a
    /// resumed fill keeps the first target and addresses it had and the count
    /// it placed: the routed groups are those of the same run without them.
    #[test]
    fn a_suspended_fill_resumes_where_it_was() {
        let a = lo([127, 0, 0, 1]);
        let b = Some(RouteKey {
            iface: "eth0".into(),
            ..a.clone().unwrap()
        });
        let at = |i: u32, route: &Option<RouteKey>| Member {
            address: IpAddr::V4(Ipv4Addr::from(0x0a00_0000 + i)),
            route: route.clone(),
            item: i,
        };
        let unroutable = |i: u32| {
            let addr = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i));
            Member {
                address: addr,
                route: Some(RouteKey::unroutable(addr)),
                item: u32::MAX,
            }
        };
        let routed_groups = |v: Vec<Member<u32>>, sizing: GroupSizing| -> Vec<Vec<u32>> {
            HostGroups::new(v.into_iter(), sizing)
                .map(|g| g.into_iter().map(|m| m.item).collect::<Vec<_>>())
                .filter(|g: &Vec<u32>| !g.contains(&u32::MAX))
                .collect()
        };
        let thousand = GroupSizing {
            max_hostgroup: 1000,
            ..sizing()
        };
        let batch = u32::try_from(PING_GROUP_SZ).unwrap();
        // A group crossing into a batch whose fill suspends after one routed
        // target: 6,097 routed ones make six groups of 1,000 and one of 97.
        let mut with: Vec<Member<u32>> = (0..=batch).map(|i| at(i, &a)).collect();
        with.extend((0..batch).map(unroutable));
        with.extend((batch + 1..batch + 2001).map(|i| at(i, &a)));
        let without: Vec<Member<u32>> = with
            .iter()
            .filter(|m| m.item != u32::MAX)
            .cloned()
            .collect();
        let got = routed_groups(with, thousand);
        assert_eq!(got, routed_groups(without, thousand));
        assert_eq!(
            got.iter().map(Vec::len).collect::<Vec<_>>(),
            [1000, 1000, 1000, 1000, 1000, 1000, 97]
        );
        // The resumed fill's first target and addresses: A1, a batch of
        // unroutable, B2, A3 gives [A1, A3], [B2].
        let mut with = vec![at(1, &a)];
        with.extend((0..batch).map(unroutable));
        with.extend([at(2, &b), at(3, &a)]);
        assert_eq!(routed_groups(with, sizing()), [vec![1, 3], vec![2]]);
        // The count it placed: a batch's worth, with a suspension at the
        // middle, still ends the batch after 4,096 placed. A misfit then
        // waits for the next batch rather than being drawn into this one.
        let mut with: Vec<Member<u32>> = (0..batch / 2).map(|i| at(i, &a)).collect();
        with.push(at(batch * 4, &b));
        with.extend((0..batch).map(unroutable));
        with.extend((batch / 2..batch + 1).map(|i| at(i, &a)));
        let without: Vec<Member<u32>> = with
            .iter()
            .filter(|m| m.item != u32::MAX)
            .cloned()
            .collect();
        assert_eq!(
            routed_groups(with, sizing()),
            routed_groups(without, sizing())
        );
    }

    /// However many targets are unroutable, the groups draw from the source no
    /// further than a batch of them, a batch and the defer buffer ahead.
    #[test]
    fn unroutable_targets_are_held_a_batch_at_most() {
        let drawn = std::cell::Cell::new(0usize);
        let source = (0..100_000u32).map(|i| {
            drawn.set(drawn.get() + 1);
            let addr = IpAddr::V4(Ipv4Addr::from(0x0b00_0000 + i));
            Member {
                address: addr,
                route: Some(RouteKey::unroutable(addr)),
                item: 0u8,
            }
        });
        let mut groups = HostGroups::new(source, sizing());
        let first = groups.next().expect("a group");
        assert!(!first.is_empty());
        assert!(
            drawn.get() <= PING_GROUP_SZ + DEFER_LIMIT,
            "drew {} for the first group",
            drawn.get()
        );
        assert_eq!(
            groups.map(|g| g.len()).sum::<usize>() + first.len(),
            100_000
        );
    }

    /// An unroutable target that cannot join the unroutable group being formed
    /// (its address again, or the other family) waits for the next; none is
    /// lost.
    #[test]
    fn no_unroutable_target_is_lost() {
        let v4 = IpAddr::V4(Ipv4Addr::new(10, 1, 0, 1));
        let v6 = IpAddr::V6(Ipv6Addr::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1));
        let u = |addr: IpAddr, item: u8| Member {
            address: addr,
            route: Some(RouteKey::unroutable(addr)),
            item,
        };
        let got = groups(
            vec![u(v4, 1), u(v4, 2), u(v6, 3), member(4, lo([127, 0, 0, 1]))],
            sizing(),
        );
        assert_eq!(got, [vec![1], vec![2], vec![3], vec![4]]);
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
    /// one: a later group that happens to hold four hosts shortens nothing. The
    /// golden shows the same with repeats on one route
    /// (`l1-l68,l65x64,l69-l140`); here a second route ends the batch.
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

    /// The source is asked again when a group wants a target and the batch is
    /// spent, as `nexthost` calls `refresh_hostbatch`: one that ends and later
    /// has more adds groups. 7.94 does this with the targets a script adds while
    /// a group is scanned (*measured*: `--script-args newtargets`, a script
    /// adding two hosts to a run of one, scans "127.0.0.1" and then "2 hosts").
    #[test]
    fn a_source_that_resumes_adds_groups() {
        use std::cell::RefCell;
        let queue = RefCell::new(VecDeque::from([member(1, None)]));
        let source = std::iter::from_fn(|| queue.borrow_mut().pop_front());
        let mut groups = HostGroups::new(source, sizing());
        let items = |g: Option<Vec<Member<u8>>>| -> Option<Vec<u8>> {
            g.map(|g| g.into_iter().map(|m| m.item).collect())
        };
        assert_eq!(items(groups.next()), Some(vec![1]));
        // The group is scanned, and a script adds two targets.
        queue
            .borrow_mut()
            .extend([member(2, None), member(3, None)]);
        assert_eq!(items(groups.next()), Some(vec![2, 3]));
        assert_eq!(items(groups.next()), None);
    }

    #[test]
    fn no_targets_no_groups() {
        assert!(groups(Vec::new(), sizing()).is_empty());
    }
}
