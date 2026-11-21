//! The run's targets as a lazy source (M7 cutover step b).
//!
//! nmap draws targets as each host group needs them (`nexthost`), so a range
//! of a million addresses is never held whole. [`prepare`] does the work that
//! must come first: it checks every expression and resolves every name, in
//! command-line order, printing what fails as it goes, and says up front if the
//! list will be cut at [`MAX_TARGETS`]. A numeric expression is kept as the
//! text it was given (a parsed range is a kilobyte; a `-iL` list of a million
//! lines is a million of them) and parsed again when [`TargetSource`] reaches
//! it. The source expands ranges one address at a time, drops what an
//! exclusion covers, and stops at the cap.

use std::collections::VecDeque;
use std::net::IpAddr;

use nmap_core::targets::{parse_target, ExcludeSet, TargetSpec};
use nmap_sys::net::resolve_host;

/// The most targets a run draws. Not in C; kept from the MVP.
pub const MAX_TARGETS: usize = 65_536;

/// One target expression, ready to be expanded.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A numeric IPv4 range, as written; parsed when it is reached.
    Range(String),
    /// One address, with the name it was resolved from.
    One(IpAddr, Option<String>),
}

/// Check and resolve the run's target expressions, in order, printing each one
/// that fails, as the CLI always has. Stops at the first expression past
/// [`MAX_TARGETS`], and says so now, before anything is scanned.
pub async fn prepare(specs: Vec<String>, ipv6: bool) -> Vec<Expr> {
    let mut out = Vec::new();
    let mut planned: u64 = 0;
    let cap = u64::try_from(MAX_TARGETS).unwrap_or(u64::MAX);
    let mut specs = specs.into_iter();
    for expr in specs.by_ref() {
        if planned >= cap {
            // One more expression than the cap holds.
            planned = planned.saturating_add(1);
            break;
        }
        match parse_target(&expr, ipv6) {
            Ok(TargetSpec::Ipv4(ranges)) => {
                planned = planned.saturating_add(ranges.count());
                out.push(Expr::Range(expr));
            }
            Ok(TargetSpec::Ipv6(ip)) => {
                planned = planned.saturating_add(1);
                out.push(Expr::One(IpAddr::V6(ip), None));
            }
            Ok(TargetSpec::Hostname { name, .. }) => match resolve_host(&name).await {
                Ok(ips) if !ips.is_empty() => {
                    // Scan the first resolved address (nmap's default), tagged
                    // with the name for the report.
                    planned = planned.saturating_add(1);
                    out.push(Expr::One(ips[0], Some(name)));
                }
                Ok(_) => eprintln!("nmap-rs: failed to resolve \"{name}\": no addresses"),
                Err(e) => eprintln!("nmap-rs: failed to resolve \"{name}\": {e}"),
            },
            Err(e) => eprintln!("nmap-rs: bad target \"{expr}\": {e:?}"),
        }
    }
    if planned > cap {
        eprintln!("nmap-rs: target list truncated at {MAX_TARGETS} hosts (MVP cap)");
    }
    out
}

/// The run's targets, one at a time, with the names they came from.
pub struct TargetSource {
    exprs: VecDeque<Expr>,
    ipv6: bool,
    current: Option<Box<dyn Iterator<Item = std::net::Ipv4Addr>>>,
    excludes: ExcludeSet,
    /// Targets drawn, before exclusion: what [`MAX_TARGETS`] bounds.
    drawn: usize,
    /// Targets an exclusion dropped.
    excluded: usize,
    finished: bool,
}

impl TargetSource {
    /// A source over `exprs`, less what `excludes` covers. `ipv6` is `-6`,
    /// which the numeric expressions are parsed again under.
    #[must_use]
    pub fn new(exprs: Vec<Expr>, ipv6: bool, excludes: ExcludeSet) -> Self {
        TargetSource {
            exprs: exprs.into(),
            ipv6,
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
                Expr::Range(spec) => {
                    // It parsed in `prepare`; parsing is a pure function of
                    // the text, so it parses again.
                    if let Ok(TargetSpec::Ipv4(r)) = parse_target(&spec, self.ipv6) {
                        self.current = Some(Box::new(r.into_addresses()));
                    }
                }
                Expr::One(ip, name) => return Some((ip, name)),
            }
        }
    }

    /// The source is spent. The count of excluded targets is known only now,
    /// so the `-v` line that reports it comes at the end of the run.
    fn finish(&mut self) {
        if self.finished {
            return;
        }
        self.finished = true;
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
                // `prepare` has said so, if anything lay beyond.
                self.finish();
                return None;
            }
            let Some((ip, name)) = self.draw() else {
                self.finish();
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
        assert!(
            matches!(parse_target(spec, false), Ok(TargetSpec::Ipv4(_))),
            "{spec}"
        );
        Expr::Range(spec.to_string())
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
            false,
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
        let mut src = TargetSource::new(vec![range("10.0.0.0/8")], false, ExcludeSet::new());
        assert_eq!(src.next(), Some((v4([10, 0, 0, 0]), None)));
        assert_eq!(src.drawn(), 1);
        let rest = src.by_ref().count();
        assert_eq!(rest, MAX_TARGETS - 1);
        assert_eq!(src.drawn(), MAX_TARGETS);
    }

    /// Exactly the cap is not a truncation; nothing is lost.
    #[test]
    fn exactly_the_cap_is_drawn_whole() {
        let mut src = TargetSource::new(vec![range("10.0.0.0/16")], false, ExcludeSet::new());
        assert_eq!(src.by_ref().count(), 65_536);
        assert_eq!(src.drawn(), MAX_TARGETS);
    }

    /// The list is checked before anything is drawn: a name past the cap is
    /// not resolved, and the expressions kept are text.
    #[tokio::test]
    async fn prepare_stops_past_the_cap() {
        let specs = vec![
            "10.0.0.0/16".to_string(),
            "10.1.0.1".to_string(),
            "no-such-name.invalid".to_string(),
        ];
        let exprs = prepare(specs, false).await;
        assert_eq!(exprs.len(), 1, "{exprs:?}");
        assert!(matches!(&exprs[0], Expr::Range(s) if s == "10.0.0.0/16"));
    }

    /// Everything excluded: nothing comes, and the count says why.
    #[test]
    fn everything_excluded_yields_nothing() {
        let mut ex = ExcludeSet::new();
        ex.add("10.0.0.0/24", false).expect("exclude");
        let mut src = TargetSource::new(vec![range("10.0.0.1-5")], false, ex);
        assert_eq!(src.next(), None);
        assert_eq!((src.drawn(), src.excluded()), (5, 5));
    }
}
