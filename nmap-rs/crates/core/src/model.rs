//! The scan data model — the Rust analog of nmap's C structs (`Port`/`Host`/
//! port-state defines in `portlist.h`, `portreasons.h`). Prefer owned, bounded
//! types (`String`, `Vec`, enums) over the C habit of raw pointers + length
//! fields and integer state codes; that habit is where the bugs lived.
//!
//! Fidelity anchors (must match the C so the differential passes):
//!
//!   - [`PortState::as_str`] mirrors `statenum2str()` (portlist.cc) exactly.
//!   - [`Protocol::as_str`] mirrors `proto2ascii_lowercase()`.
//!
//! Milestone 1 (connect scan) only ever *produces* `Open`/`Closed`/`Filtered`,
//! but the full state set is modeled so later milestones don't reshape the type.

use std::net::IpAddr;

/// Transport protocol of a scanned port. Mirrors nmap's `IPPROTO_TCP/UDP/SCTP`
/// usage; the string form matches `proto2ascii_lowercase()`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Protocol {
    Tcp,
    Udp,
    Sctp,
}

impl Protocol {
    /// Lowercase protocol name as printed by nmap (`"tcp"`/`"udp"`/`"sctp"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Protocol::Tcp => "tcp",
            Protocol::Udp => "udp",
            Protocol::Sctp => "sctp",
        }
    }
}

/// State of a scanned port. Discriminants match the `PORT_*` defines in
/// `portlist.h` so a numeric round-trip against the C is exact; [`as_str`]
/// matches `statenum2str()`.
///
/// [`as_str`]: PortState::as_str
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum PortState {
    Unknown = 0,
    Closed = 1,
    Open = 2,
    Filtered = 3,
    // 4 (PORT_TESTING) and 5 (PORT_FRESH) are transient internal engine states,
    // never a final result; intentionally omitted from the result model.
    Unfiltered = 6,
    OpenFiltered = 7,
    ClosedFiltered = 8,
}

impl PortState {
    /// Human string exactly as `statenum2str()` (portlist.cc) prints it.
    pub fn as_str(self) -> &'static str {
        match self {
            PortState::Open => "open",
            PortState::Filtered => "filtered",
            PortState::Unfiltered => "unfiltered",
            PortState::Closed => "closed",
            PortState::OpenFiltered => "open|filtered",
            PortState::ClosedFiltered => "closed|filtered",
            PortState::Unknown => "unknown",
        }
    }
}

/// Why a port is in its state — the analog of `portreasons.h` `reason_codes`.
/// Only the subset reachable from an unprivileged connect scan (Milestone 1) is
/// modeled; more variants land with the raw scans (M4). [`as_str`] returns the
/// short reason token nmap prints under `--reason` / in XML `reason=`.
///
/// [`as_str`]: Reason::as_str
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Reason {
    /// TCP connection accepted → port open (`ER_CONACCEPT`).
    ConnAccept,
    /// TCP connection refused (RST) → port closed (`ER_CONREFUSED`).
    ConnRefused,
    /// No response within the timeout → filtered (`ER_NORESPONSE`).
    NoResponse,
    /// Host administratively unreachable → filtered (`ER_HOSTUNREACH`).
    HostUnreach,
    /// Network unreachable → filtered (`ER_NETUNREACH`).
    NetUnreach,
    /// Loopback / local address (`ER_LOCALHOST`).
    Localhost,
    /// Reason not otherwise classified (`ER_UNKNOWN`).
    Unknown,
}

impl Reason {
    /// Short reason token as nmap emits it (e.g. `"conn-refused"`, `"syn-ack"`).
    pub fn as_str(self) -> &'static str {
        match self {
            Reason::ConnAccept => "syn-ack",
            Reason::ConnRefused => "conn-refused",
            Reason::NoResponse => "no-response",
            Reason::HostUnreach => "host-unreach",
            Reason::NetUnreach => "net-unreach",
            Reason::Localhost => "localhost-response",
            Reason::Unknown => "unknown",
        }
    }
}

/// Service name/info attached to a port. The `name` starts as the `nmap-services`
/// table lookup; a `-sV` probe (M3) may overwrite it and fill the version fields.
/// All version strings are display-ready (printable-escaped by the caller).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ServiceInfo {
    /// Service name (e.g. `"http"`), from `nmap-services` or a `-sV` match.
    pub name: Option<String>,
    /// `-sV` product name (e.g. `OpenSSH`).
    pub product: Option<String>,
    /// `-sV` version string (e.g. `9.6`).
    pub version: Option<String>,
    /// `-sV` extra info (e.g. `protocol 2.0`).
    pub extra_info: Option<String>,
    /// `-sV` OS type (e.g. `Unix`).
    pub ostype: Option<String>,
    /// `-sV` device type (e.g. `router`).
    pub devicetype: Option<String>,
    /// `-sV` hostname reported by the service.
    pub hostname: Option<String>,
    /// `-sV` CPE identifiers (`cpe:/a:…`).
    pub cpe: Vec<String>,
    /// How the service was identified: `"table"` (nmap-services) or `"probed"`
    /// (`-sV`). `None` until set.
    pub method: Option<String>,
    /// Detection confidence 0..=10 (nmap uses 10 for a hard `-sV` match, 3 for a
    /// table guess). `None` until set.
    pub conf: Option<u8>,
}

/// One scanned port on one host — the analog of C `struct port`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Port {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    pub reason: Reason,
    /// TTL of the response that set the reason, if known (0 = unknown).
    pub reason_ttl: u8,
    pub service: ServiceInfo,
}

impl Port {
    /// A freshly observed port with no service info and an unknown TTL.
    pub fn new(number: u16, protocol: Protocol, state: PortState, reason: Reason) -> Self {
        Self {
            number,
            protocol,
            state,
            reason,
            reason_ttl: 0,
            service: ServiceInfo::default(),
        }
    }
}

/// Whether a host is up (analog of `HOST_UP`/`HOST_DOWN` in the C).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostState {
    Up,
    Down,
    Unknown,
}

/// One scanned host — the analog of the parts of C `class Target` the M1 output
/// path needs: address, resolved name(s), liveness, and its port table.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Host {
    pub address: IpAddr,
    /// Reverse-DNS / user-supplied name, if resolved.
    pub hostname: Option<String>,
    pub state: HostState,
    /// Ports in the order discovered; render sorts as needed.
    pub ports: Vec<Port>,
}

impl Host {
    pub fn new(address: IpAddr, state: HostState) -> Self {
        Self {
            address,
            hostname: None,
            state,
            ports: Vec::new(),
        }
    }

    /// Ports matching `state`, sorted by (protocol, number) — the order nmap
    /// prints them in.
    pub fn ports_in_state(&self, state: PortState) -> Vec<&Port> {
        let mut v: Vec<&Port> = self.ports.iter().filter(|p| p.state == state).collect();
        v.sort_by_key(|p| (p.protocol, p.number));
        v
    }
}

/// The whole scan's result set — every host, in scan order.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ScanResults {
    pub hosts: Vec<Host>,
}

impl ScanResults {
    pub fn new() -> Self {
        Self::default()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn port_state_strings_match_statenum2str() {
        // Exact fidelity to portlist.cc statenum2str().
        assert_eq!(PortState::Open.as_str(), "open");
        assert_eq!(PortState::Closed.as_str(), "closed");
        assert_eq!(PortState::Filtered.as_str(), "filtered");
        assert_eq!(PortState::Unfiltered.as_str(), "unfiltered");
        assert_eq!(PortState::OpenFiltered.as_str(), "open|filtered");
        assert_eq!(PortState::ClosedFiltered.as_str(), "closed|filtered");
        assert_eq!(PortState::Unknown.as_str(), "unknown");
    }

    #[test]
    fn port_state_discriminants_match_c_defines() {
        assert_eq!(PortState::Unknown as u8, 0);
        assert_eq!(PortState::Closed as u8, 1);
        assert_eq!(PortState::Open as u8, 2);
        assert_eq!(PortState::Filtered as u8, 3);
        assert_eq!(PortState::Unfiltered as u8, 6);
        assert_eq!(PortState::OpenFiltered as u8, 7);
        assert_eq!(PortState::ClosedFiltered as u8, 8);
    }

    #[test]
    fn protocol_strings() {
        assert_eq!(Protocol::Tcp.as_str(), "tcp");
        assert_eq!(Protocol::Udp.as_str(), "udp");
        assert_eq!(Protocol::Sctp.as_str(), "sctp");
    }

    #[test]
    fn ports_in_state_sorts_by_proto_then_number() {
        let mut h = Host::new(IpAddr::V4(Ipv4Addr::LOCALHOST), HostState::Up);
        h.ports.push(Port::new(
            80,
            Protocol::Tcp,
            PortState::Open,
            Reason::ConnAccept,
        ));
        h.ports.push(Port::new(
            22,
            Protocol::Tcp,
            PortState::Open,
            Reason::ConnAccept,
        ));
        h.ports.push(Port::new(
            53,
            Protocol::Tcp,
            PortState::Closed,
            Reason::ConnRefused,
        ));
        let open = h.ports_in_state(PortState::Open);
        assert_eq!(
            open.iter().map(|p| p.number).collect::<Vec<_>>(),
            vec![22, 80]
        );
    }
}
