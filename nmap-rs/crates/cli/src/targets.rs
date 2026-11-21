//! The run's targets as a lazy source (M7 cutover step b).
//!
//! nmap draws targets as each host group needs them (`nexthost`), so a range
//! of a million addresses is never held whole. [`prepare`] does the work that
//! must come first: it parses every expression and resolves every name, in
//! command-line order, printing what fails as it goes. [`TargetSource`] then
//! expands the ranges one address at a time, drops what an exclusion covers,
//! and stops at [`MAX_TARGETS`].

use std::collections::VecDeque;
use std::net::IpAddr;

use nmap_core::options::RunConfig;
use nmap_core::targets::{parse_target, ExcludeSet, Ipv4Ranges, TargetSpec};
use nmap_sys::net::resolve_host;

/// The most targets a run draws. Not in C; kept from the MVP.
pub const MAX_TARGETS: usize = 65_536;

/// One target expression, ready to be expanded.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A numeric IPv4 range, expanded lazily.
    Range(Box<Ipv4Ranges>),
    /// One address, with the name it was resolved from.
    One(IpAddr, Option<String>),
}

/// Parse and resolve every target expression of the run, in order, printing
/// each one that fails, as the CLI always has.
pub async fn prepare(cfg: &RunConfig) -> Vec<Expr> {
    let mut out = Vec::new();
    for expr in &cfg.targets {
        match parse_target(expr, cfg.ipv6) {
            Ok(TargetSpec::Ipv4(ranges)) => out.push(Expr::Range(ranges)),
            Ok(TargetSpec::Ipv6(ip)) => out.push(Expr::One(IpAddr::V6(ip), None)),
            Ok(TargetSpec::Hostname { name, .. }) => match resolve_host(&name).await {
                Ok(ips) if !ips.is_empty() => {
                    // Scan the first resolved address (nmap's default), tagged
                    // with the name for the report.
                    out.push(Expr::One(ips[0], Some(name)));
                }
                Ok(_) => eprintln!("nmap-rs: failed to resolve \"{name}\": no addresses"),
                Err(e) => eprintln!("nmap-rs: failed to resolve \"{name}\": {e}"),
            },
            Err(e) => eprintln!("nmap-rs: bad target \"{expr}\": {e:?}"),
        }
    }
    out
}

/// The run's targets, one at a time, with the names they came from.
pub struct TargetSource {
    exprs: VecDeque<Expr>,
    current: Option<Box<dyn Iterator<Item = std::net::Ipv4Addr>>>,
    excludes: ExcludeSet,
    /// Targets drawn, before exclusion: what [`MAX_TARGETS`] bounds.
    drawn: usize,
    /// Targets an exclusion dropped.
    excluded: usize,
    finished: bool,
}

impl TargetSource {
    /// A source over `exprs`, less what `excludes` covers.
    #[must_use]
    pub fn new(exprs: Vec<Expr>, excludes: ExcludeSet) -> Self {
        TargetSource {
            exprs: exprs.into(),
            current: None,
            excludes,
            drawn: 0,
            excluded: 0,
            finished: false,
        }
    }

    /// How many targets were drawn, before exclusion.
    #[must_use]
    pub fn drawn(&self) -> usize {
        self.drawn
    }

    /// How many targets an exclusion dropped.
    #[must_use]
    #[cfg_attr(not(test), allow(dead_code))]
    pub fn excluded(&self) -> usize {
        self.excluded
    }

    /// The next target, before exclusion.
    fn draw(&mut self) -> Option<(IpAddr, Option<String>)> {
        loop {
            if let Some(it) = self.current.as_mut() {
                if let Some(ip) = it.next() {
                    return Some((IpAddr::V4(ip), None));
                }
                self.current = None;
            }
            match self.exprs.pop_front()? {
                Expr::Range(r) => self.current = Some(Box::new(r.into_addresses())),
                Expr::One(ip, name) => return Some((ip, name)),
            }
        }
    }

    fn finish(&mut self, truncated: bool) {
        if self.finished {
            return;
        }
        self.finished = true;
        if truncated {
            eprintln!("nmap-rs: target list truncated at {MAX_TARGETS} hosts (MVP cap)");
        }
        if self.excluded > 0 {
            nmap_core::verbose!(1, "excluded {} host(s)", self.excluded);
        }
    }
}

impl Iterator for TargetSource {
    type Item = (IpAddr, Option<String>);

    fn next(&mut self) -> Option<Self::Item> {
        if self.finished {
            return None;
        }
        loop {
            if self.drawn >= MAX_TARGETS {
                // Only a target beyond the cap makes it a truncation.
                let more = self.draw().is_some();
                self.finish(more);
                return None;
            }
            let Some((ip, name)) = self.draw() else {
                self.finish(false);
                return None;
            };
            self.drawn = self.drawn.saturating_add(1);
            if self.excludes.contains(ip) {
                self.excluded = self.excluded.saturating_add(1);
                continue;
            }
            return Some((ip, name));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn range(spec: &str) -> Expr {
        match parse_target(spec, false) {
            Ok(TargetSpec::Ipv4(r)) => Expr::Range(r),
            other => panic!("{spec}: {other:?}"),
        }
    }

    fn v4(a: [u8; 4]) -> IpAddr {
        IpAddr::V4(Ipv4Addr::from(a))
    }

    /// In command-line order, each range expanded in nmap's order, less what
    /// is excluded; and counted as it goes.
    #[test]
    fn targets_come_in_order_less_the_excluded() {
        let mut ex = ExcludeSet::new();
        ex.add("10.0.0.2", false).expect("exclude");
        let mut src = TargetSource::new(
            vec![
                range("10.0.0.1-3"),
                Expr::One(v4([192, 0, 2, 9]), Some("named".into())),
                range("10.0.1.1"),
            ],
            ex,
        );
        let got: Vec<_> = src.by_ref().collect();
        assert_eq!(
            got,
            [
                (v4([10, 0, 0, 1]), None),
                (v4([10, 0, 0, 3]), None),
                (v4([192, 0, 2, 9]), Some("named".to_string())),
                (v4([10, 0, 1, 1]), None),
            ]
        );
        assert_eq!((src.drawn(), src.excluded()), (5, 1));
        assert_eq!(src.next(), None, "stays ended");
    }

    /// A range is drawn one address at a time: a /8 costs nothing until it
    /// is walked, and the cap stops it.
    #[test]
    fn a_range_is_expanded_lazily_and_capped() {
        let mut src = TargetSource::new(vec![range("10.0.0.0/8")], ExcludeSet::new());
        assert_eq!(src.next(), Some((v4([10, 0, 0, 0]), None)));
        assert_eq!(src.drawn(), 1);
        let rest = src.by_ref().count();
        assert_eq!(rest, MAX_TARGETS - 1);
        assert_eq!(src.drawn(), MAX_TARGETS);
    }

    /// Exactly the cap is not a truncation; nothing is lost.
    #[test]
    fn exactly_the_cap_is_drawn_whole() {
        let mut src = TargetSource::new(vec![range("10.0.0.0/16")], ExcludeSet::new());
        assert_eq!(src.by_ref().count(), 65_536);
        assert_eq!(src.drawn(), MAX_TARGETS);
    }

    /// Everything excluded: nothing comes, and the count says why.
    #[test]
    fn everything_excluded_yields_nothing() {
        let mut ex = ExcludeSet::new();
        ex.add("10.0.0.0/24", false).expect("exclude");
        let mut src = TargetSource::new(vec![range("10.0.0.1-5")], ex);
        assert_eq!(src.next(), None);
        assert_eq!((src.drawn(), src.excluded()), (5, 5));
    }
}
