//! UDP probe payloads — the port of nmap's `payload.cc`.
//!
//! A bare UDP probe (no payload) only elicits a reply from a service that answers
//! anything at all; most don't, so the port reads `open|filtered`. nmap therefore sends
//! a **protocol-specific payload** on well-known UDP ports — a DNS query to 53, an SNMP
//! get to 161 — which coaxes a real answer and resolves the port to `open`.
//!
//! ## Where the payloads come from
//!
//! There is no separate payload database: `payload.cc` **derives** the table from
//! `nmap-service-probes`, which [`crate::probedb`] already parses. Every `Probe` line
//! that is `UDP` and not flagged `no-payload` contributes its probe string as a payload
//! for each port in its `ports` directive. So this module is a pure *index* over data we
//! already parse and fuzz — it adds no new untrusted-input surface.
//!
//! A port may have **several** payloads. nmap sends all of them for one logical probe,
//! from the same source port (see the comment on `payload_service_match` in the C), so a
//! reply is matched by port, not by which payload provoked it.
//!
//! ## Divergences (ledgered in `DIVERGENCES.md`)
//!
//! * `payload-cap-warns-not-fatal` — the C `fatal()`s if a port accumulates more than
//!   [`MAX_PAYLOADS_PER_PORT`] payloads, killing the scan over a data-file property. We
//!   cap the list and record the port in [`UdpPayloads::capped_ports`] instead: a
//!   too-generous data file degrades detection slightly rather than aborting.

use std::collections::HashMap;

use crate::probedb::{ProbeDb, ProbeProtocol};

/// Ceiling on payloads recorded per port, matching the C's `MAX_PAYLOADS_PER_PORT`.
/// The C limit exists because its count and index are `u8`; we keep the same ceiling so
/// the payload *sequence* matches, but cap rather than abort (see the module docs).
pub const MAX_PAYLOADS_PER_PORT: usize = 0xff;

/// No payloads at all — every port resolves to an empty payload. The behavior when
/// `nmap-service-probes` is unavailable.
const NO_PAYLOADS: &[Vec<u8>] = &[];

/// UDP destination port → the payloads nmap would send to it, in `nmap-service-probes`
/// order (which is the order the C's index selects them in).
#[derive(Debug, Clone, Default)]
pub struct UdpPayloads {
    by_port: HashMap<u16, Vec<Vec<u8>>>,
    capped_ports: Vec<u16>,
}

impl UdpPayloads {
    /// An empty table: every port gets a zero-length payload, reproducing the
    /// pre-payload behavior.
    #[must_use]
    pub fn empty() -> Self {
        Self::default()
    }

    /// Build the port → payload index from a parsed `nmap-service-probes`.
    ///
    /// Mirrors `init_payloads()`: every UDP probe not flagged `no-payload` contributes
    /// its probe string to each of its `ports`. Probes are visited in file order, so a
    /// port's payload list is ordered exactly as the C's vector is.
    #[must_use]
    pub fn from_probe_db(db: &ProbeDb) -> Self {
        let mut by_port: HashMap<u16, Vec<Vec<u8>>> = HashMap::new();
        let mut capped_ports = Vec::new();
        // The NULL probe is deliberately not consulted: it carries no probe string, and
        // the C's `AllProbes::probes` excludes it too.
        for probe in &db.probes {
            if probe.protocol != ProbeProtocol::Udp || probe.no_payload {
                continue;
            }
            if probe.probestring.is_empty() {
                continue; // nothing to send — indistinguishable from no payload
            }
            for &port in &probe.ports {
                let list = by_port.entry(port).or_default();
                if list.len() >= MAX_PAYLOADS_PER_PORT {
                    // The C aborts the whole scan here; we drop the extras and remember
                    // the port so the caller can report it.
                    if !capped_ports.contains(&port) {
                        capped_ports.push(port);
                    }
                    continue;
                }
                list.push(probe.probestring.clone());
            }
        }
        capped_ports.sort_unstable();
        Self {
            by_port,
            capped_ports,
        }
    }

    /// How many payloads this port has (`udp_payload_count`). `0` means "send an empty
    /// datagram".
    #[must_use]
    pub fn count(&self, dport: u16) -> usize {
        self.by_port.get(&dport).map_or(0, Vec::len)
    }

    /// Every payload for `dport`, in order; empty if the port has none.
    #[must_use]
    pub fn for_port(&self, dport: u16) -> &[Vec<u8>] {
        self.by_port
            .get(&dport)
            .map_or(NO_PAYLOADS, |v| v.as_slice())
    }

    /// The payload the C's `udp_port2payload(dport, .., index)` would return: the
    /// `index`-th payload modulo the count, or an empty slice when the port has none.
    #[must_use]
    pub fn get(&self, dport: u16, index: usize) -> &[u8] {
        let list = self.for_port(dport);
        // `index % len` reproduces the C's wrap. `checked_rem` rather than `%` so an
        // empty list can only ever yield the empty payload, never a division by zero.
        match index.checked_rem(list.len()).and_then(|i| list.get(i)) {
            Some(payload) => payload.as_slice(),
            None => &[],
        }
    }

    /// The datagram payloads to send for one logical probe of `dport`: every payload for
    /// the port, or a single empty payload when it has none — the C's
    /// `MAX(numpayloads, 1)` loop.
    #[must_use]
    pub fn probe_payloads(&self, dport: u16) -> Vec<&[u8]> {
        let list = self.for_port(dport);
        if list.is_empty() {
            vec![&[]]
        } else {
            list.iter().map(Vec::as_slice).collect()
        }
    }

    /// True when no port has a payload (e.g. the probe DB was unavailable).
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.by_port.is_empty()
    }

    /// How many ports have at least one payload.
    #[must_use]
    pub fn ports_with_payloads(&self) -> usize {
        self.by_port.len()
    }

    /// Ports whose payload list hit [`MAX_PAYLOADS_PER_PORT`] and was truncated, sorted.
    /// Empty for the shipped data file; a caller may warn if not.
    #[must_use]
    pub fn capped_ports(&self) -> &[u16] {
        &self.capped_ports
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A miniature `nmap-service-probes` exercising the selection rules.
    const DB: &str = concat!(
        "Probe TCP NULL q||\n",
        // UDP with two ports -> payload for both.
        "Probe UDP DNSStatusRequest q|\\0\\0\\x10\\0\\0\\0\\0\\0\\0\\0\\0\\0|\n",
        "ports 53,5353\n",
        // A second UDP probe for port 53 -> 53 gets two payloads, in file order.
        "Probe UDP DNSVersionBindReq q|\\x01\\x02|\n",
        "ports 53\n",
        // no-payload flag -> excluded entirely.
        "Probe UDP Skipped q|nope| no-payload\n",
        "ports 7777\n",
        // TCP probes never contribute UDP payloads.
        "Probe TCP GetRequest q|GET / HTTP/1.0\\r\\n\\r\\n|\n",
        "ports 80\n",
    );

    fn table() -> UdpPayloads {
        UdpPayloads::from_probe_db(&ProbeDb::parse(DB))
    }

    #[test]
    fn indexes_udp_probes_by_their_probable_ports() {
        let p = table();
        assert_eq!(p.count(53), 2, "two UDP probes list port 53");
        assert_eq!(p.count(5353), 1);
        assert_eq!(
            p.for_port(53)[0],
            b"\0\0\x10\0\0\0\0\0\0\0\0\0".to_vec(),
            "file order: DNSStatusRequest first"
        );
        assert_eq!(p.for_port(53)[1], b"\x01\x02".to_vec());
    }

    #[test]
    fn excludes_no_payload_probes_and_tcp_probes() {
        let p = table();
        assert_eq!(p.count(7777), 0, "no-payload probe must not contribute");
        assert_eq!(p.count(80), 0, "TCP probe must not contribute");
        assert!(p.get(7777, 0).is_empty());
    }

    #[test]
    fn unknown_ports_get_an_empty_payload() {
        let p = table();
        assert_eq!(p.count(9999), 0);
        assert!(p.get(9999, 0).is_empty());
        assert!(p.for_port(9999).is_empty());
        // One empty datagram is still sent — the C's MAX(numpayloads, 1).
        assert_eq!(p.probe_payloads(9999), vec![&[] as &[u8]]);
    }

    #[test]
    fn get_wraps_the_index_like_the_c() {
        let p = table();
        assert_eq!(p.get(53, 0), p.get(53, 2), "index wraps modulo the count");
        assert_eq!(p.get(53, 1), p.get(53, 3));
        // A huge index must not panic or go out of bounds.
        assert!(!p.get(53, usize::MAX).is_empty());
    }

    #[test]
    fn probe_payloads_lists_every_payload_for_the_port() {
        let p = table();
        let all = p.probe_payloads(53);
        assert_eq!(all.len(), 2);
        assert_eq!(all[0], p.get(53, 0));
        assert_eq!(all[1], p.get(53, 1));
    }

    #[test]
    fn empty_table_is_the_no_payload_behavior() {
        let p = UdpPayloads::empty();
        assert!(p.is_empty());
        assert_eq!(p.count(53), 0);
        assert!(p.get(53, 0).is_empty());
        assert_eq!(p.probe_payloads(53), vec![&[] as &[u8]]);
        assert!(p.capped_ports().is_empty());
    }

    #[test]
    fn a_port_over_the_cap_is_truncated_not_fatal() {
        // MAX_PAYLOADS_PER_PORT + 10 distinct UDP probes all claiming port 53.
        let mut src = String::new();
        for i in 0..MAX_PAYLOADS_PER_PORT + 10 {
            src.push_str(&format!("Probe UDP P{i} q|payload{i}|\nports 53\n"));
        }
        let p = UdpPayloads::from_probe_db(&ProbeDb::parse(&src));
        assert_eq!(p.count(53), MAX_PAYLOADS_PER_PORT, "capped, not unbounded");
        assert_eq!(p.capped_ports(), &[53], "the cap is reported, not fatal");
        // Still usable: every index resolves inside the truncated list.
        assert!(!p.get(53, MAX_PAYLOADS_PER_PORT + 5).is_empty());
    }

    #[test]
    fn probes_with_an_empty_probe_string_contribute_nothing() {
        let p = UdpPayloads::from_probe_db(&ProbeDb::parse("Probe UDP Hollow q||\nports 4444\n"));
        assert_eq!(p.count(4444), 0);
    }
}
