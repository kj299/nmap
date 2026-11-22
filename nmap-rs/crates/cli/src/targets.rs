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

/// The most targets a run draws. Not in C; kept from the MVP
/// (`target-cap-65536`, ledgered).
pub const MAX_TARGETS: usize = 65_536;

/// One target expression, ready to be expanded.
#[derive(Debug, Clone)]
pub enum Expr {
    /// A numeric IPv4 range, as written; parsed when it is reached.
    Range(String),
    /// One address, with the name it was resolved from.
    One(IpAddr, Option<String>),
}

/// What [`prepare`] made of the target list.
#[derive(Debug)]
pub struct Prepared {
    /// The expressions to draw from, in order.
    pub exprs: Vec<Expr>,
    /// How many specifications were read, valid or not. Zero means the list
    /// held none at all.
    pub seen: usize,
}

/// Check and resolve the run's target expressions, in order, printing each one
/// that fails, as the CLI always has.
///
/// `specs` is read only as far as it is needed, so an `-iL` file is read up to
/// the first expression past [`MAX_TARGETS`]'s worth and no further. That is a
/// truncation if the expression is a target: a name past the cap counts
/// without being resolved, and one that does not parse is reported and passed
/// over, as before the cap. It is said now, before anything is scanned. A
/// specification that could not be read ends it with the error.
pub async fn prepare<E>(
    specs: impl Iterator<Item = Result<String, E>>,
    ipv6: bool,
) -> Result<Prepared, E> {
    let mut out = Vec::new();
    let mut seen = 0usize;
    let mut planned: u64 = 0;
    let cap = u64::try_from(MAX_TARGETS).unwrap_or(u64::MAX);
    let mut truncated = false;
    for expr in specs {
        let expr = expr?;
        seen = seen.saturating_add(1);
        let parsed = parse_target(&expr, ipv6);
        if planned >= cap {
            match parsed {
                Ok(_) => {
                    truncated = true;
                    break;
                }
                Err(e) => {
                    eprintln!("nmap-rs: bad target \"{expr}\": {e:?}");
                    continue;
                }
            }
        }
        match parsed {
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
    if truncated || planned > cap {
        eprintln!("nmap-rs: target list truncated at {MAX_TARGETS} hosts (MVP cap)");
    }
    Ok(Prepared { exprs: out, seen })
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
    /// so the `-v` line that reports it comes when the source runs dry, which
    /// grouping can reach before the first group is written (a batch draws up
    /// to 4096 ahead). 7.94 prints no such line.
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

    fn specs(list: &[&str]) -> impl Iterator<Item = Result<String, ()>> {
        list.iter()
            .map(|s| Ok((*s).to_string()))
            .collect::<Vec<_>>()
            .into_iter()
    }

    /// The list is read no further than the cap: a name past it is not
    /// resolved, and what is kept is text.
    #[tokio::test]
    async fn prepare_stops_past_the_cap() {
        let p = prepare(specs(&["10.0.0.0/16", "localhost", "10.1.0.1"]), false)
            .await
            .unwrap();
        assert_eq!(p.exprs.len(), 1, "{p:?}");
        assert!(matches!(&p.exprs[0], Expr::Range(s) if s == "10.0.0.0/16"));
        assert_eq!(p.seen, 2, "read one past the cap, and no further");
        // Below the cap, the same name resolves and is kept.
        let p = prepare(specs(&["10.0.0.0/24", "localhost"]), false)
            .await
            .unwrap();
        assert_eq!(p.exprs.len(), 2, "{p:?}");
    }

    /// Reading stops at the first unreadable specification, with its error.
    #[tokio::test]
    async fn an_unreadable_spec_ends_the_list() {
        let list = vec![
            Ok("10.0.0.1".to_string()),
            Err("broken"),
            Ok("10.0.0.2".to_string()),
        ];
        assert_eq!(
            prepare(list.into_iter(), false).await.unwrap_err(),
            "broken"
        );
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
