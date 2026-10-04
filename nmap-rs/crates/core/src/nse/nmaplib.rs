//! The `nmap` module's non-I/O half (`nse_nmaplib.cc`): what a script can ask
//! nmap about the scan without opening a socket.
//!
//! The functions read three kinds of state, and each comes from outside this
//! module so that the module stays pure:
//!
//! * **The run's options** — verbosity, timing, `--ttl`, `-e` and so on — in
//!   an [`NmapEnv`], filled by whoever starts NSE. So are the few facts that
//!   come from the system (DNS servers, interfaces, a clock, random bytes, the
//!   data-file search, the log), as values or callbacks.
//! * **The hosts being scripted**, as [`ScriptHost`]s: what `set_hostinfo`
//!   and `set_portinfo` read out of a `Target` and its `PortList`, with the
//!   `PortList` operations the functions perform (`nextPort`,
//!   `setPortState`, `setServiceProbeResults`) reproduced over them.
//! * **NSE's own bookkeeping**: the hosts of the current group, the new-targets
//!   queue, the version-intensity cache and whether the running script was
//!   selected by name, in [`NmapLib`].
//!
//! What a script can observe is the C's, quirks included — they are listed in
//! DIVERGENCES.md under M6.3 as reproduced behaviour. Two examples worth
//! knowing before reading the code: `get_ports` iterating TCP ports continues
//! into the UDP and SCTP ones (`PortList::nextPort` falls through), and a port
//! table naming an unscanned TCP port matches a scanned UDP port of the same
//! number (the lookup walks the same chain).
//!
//! The I/O half — sockets, `dnet`, `resolve`, and `mutex`/`condvar`, which
//! need NSE's scheduler — is M6.4. Their names are installed now, as
//! functions that raise, so that a script reaching for one fails loudly.

use std::cell::RefCell;
use std::collections::{BTreeSet, HashMap, VecDeque};
use std::net::IpAddr;
use std::pin::Pin;
use std::rc::Rc;

use gc_arena::Collect;
use piccolo::{
    BoxSequence, Callback, CallbackReturn, Context, Error, Execution, Function, Sequence,
    SequencePoll, Stack, Table, UserData, Value,
};

use super::scriptargs::{ArgTable, ArgValue};
use super::stdlib::strpack::PackError;
use super::stdlib::{lua_error_bytes, type_error, LuaArgs};
use crate::model::{PortState, Protocol};
use crate::ports::{PortList, ServiceTable};

/// `SERVICE_TUNNEL_*`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Tunnel {
    /// No tunnel (`"none"`).
    #[default]
    None,
    /// The service was reached through SSL (`"ssl"`).
    Ssl,
}

/// `SERVICE_DETECTION_*`: where the service name came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum DetectionType {
    /// From `nmap-services` (`"table"`).
    #[default]
    Table,
    /// From a `-sV` probe (`"probed"`).
    Probed,
}

/// `struct serviceDeductions` (`portlist.h`): what is known about a port's
/// service. A port with no record is looked up in `nmap-services` when read.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct ServiceDeductions {
    pub name: Option<Vec<u8>>,
    /// 0..=10. Lua sees it as a float, as `lua_pushnumber` makes it.
    pub name_confidence: i64,
    pub product: Option<Vec<u8>>,
    pub version: Option<Vec<u8>>,
    pub extrainfo: Option<Vec<u8>>,
    pub hostname: Option<Vec<u8>>,
    pub ostype: Option<Vec<u8>>,
    pub devicetype: Option<Vec<u8>>,
    pub tunnel: Tunnel,
    pub service_fp: Option<Vec<u8>>,
    pub dtype: DetectionType,
    pub cpe: Vec<Vec<u8>>,
}

/// One scanned port of a [`ScriptHost`], as `set_portinfo` reads it.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptPort {
    pub number: u16,
    pub protocol: Protocol,
    pub state: PortState,
    /// The reason token (`reason_str`), e.g. `"syn-ack"`.
    pub reason: &'static str,
    pub reason_ttl: u8,
    /// `Port::service`; `None` is the C's `NULL`, read through the
    /// `nmap-services` table.
    pub service: Option<ServiceDeductions>,
}

impl ScriptPort {
    /// A port from the scan's result model.
    pub fn from_model(p: &crate::model::Port) -> Self {
        let s = &p.service;
        let has_record = s.method.is_some() || s.product.is_some() || s.conf.is_some();
        let bytes = |v: &Option<String>| v.as_ref().map(|x| x.as_bytes().to_vec());
        Self {
            number: p.number,
            protocol: p.protocol,
            state: p.state,
            reason: p.reason.as_str(),
            reason_ttl: p.reason_ttl,
            service: has_record.then(|| ServiceDeductions {
                name: bytes(&s.name),
                name_confidence: i64::from(s.conf.unwrap_or(0)),
                product: bytes(&s.product),
                version: bytes(&s.version),
                extrainfo: bytes(&s.extra_info),
                hostname: bytes(&s.hostname),
                ostype: bytes(&s.ostype),
                devicetype: bytes(&s.devicetype),
                tunnel: Tunnel::None,
                service_fp: bytes(&s.fingerprint),
                dtype: if s.method.as_deref() == Some("probed") {
                    DetectionType::Probed
                } else {
                    DetectionType::Table
                },
                cpe: s.cpe.iter().map(|c| c.as_bytes().to_vec()).collect(),
            }),
        }
    }
}

/// One traceroute hop.
#[derive(Debug, Clone, PartialEq)]
pub struct TraceHop {
    /// A hop that timed out is an empty table.
    pub timed_out: bool,
    pub ip: Option<IpAddr>,
    pub name: Option<Vec<u8>>,
    /// The hop's round trip, in the unit `TracerouteHop::rtt` holds it;
    /// scripts see it divided by 1000.
    pub rtt: f64,
}

/// One OS classification (`push_osclass_table`).
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OsClass {
    pub vendor: Option<Vec<u8>>,
    pub osfamily: Option<Vec<u8>>,
    pub osgen: Option<Vec<u8>>,
    pub device_type: Option<Vec<u8>>,
    pub cpe: Vec<Vec<u8>>,
}

/// What `set_hostinfo` reads of an OS scan.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct OsFacts {
    /// `FPR->merge_fpr(...)`: the fingerprint, as `host.os_fp`.
    pub fingerprint: Vec<u8>,
    /// `overall_results == OSSCAN_SUCCESS`.
    pub success: bool,
    /// The names of the perfect matches. `host.os` exists only for one to
    /// eight of them.
    pub perfect_matches: Vec<Vec<u8>>,
    /// The overall classification. Every match's `classes` is this same list,
    /// as in the C, which passes the overall results to each match.
    pub classes: Vec<OsClass>,
}

/// The `timeout_info` of a host, in microseconds, as `host.times` divides it.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Times {
    pub srtt: i64,
    pub rttvar: i64,
    pub timeout: i64,
}

/// A host being scripted: what `set_hostinfo` reads out of a `Target`.
#[derive(Debug, Clone, PartialEq)]
pub struct ScriptHost {
    pub ip: IpAddr,
    /// `HostName()`: the reverse-DNS name, or `""`.
    pub hostname: Vec<u8>,
    /// `TargetName()`: the name given on the command line, if one was.
    pub targetname: Option<Vec<u8>>,
    pub reason: &'static str,
    pub reason_ttl: u8,
    /// `directlyConnectedOrUnset()`, `None` when unset.
    pub directly_connected: Option<bool>,
    pub mac: Option<[u8; 6]>,
    pub next_hop_mac: Option<[u8; 6]>,
    pub src_mac: Option<[u8; 6]>,
    /// `deviceName()`.
    pub interface: Option<Vec<u8>>,
    pub mtu: i64,
    /// `SourceSockAddr()`, when its family is known.
    pub source: Option<IpAddr>,
    pub times: Times,
    pub traceroute: Vec<TraceHop>,
    /// Present when an OS scan was performed and left results.
    pub os: Option<OsFacts>,
    /// The scanned ports. Order does not matter; lookups sort by number.
    pub ports: Vec<ScriptPort>,
}

impl ScriptHost {
    /// A host with nothing known but its address.
    pub fn new(ip: IpAddr) -> Self {
        Self {
            ip,
            hostname: Vec::new(),
            targetname: None,
            reason: "unknown",
            reason_ttl: 0,
            directly_connected: None,
            mac: None,
            next_hop_mac: None,
            src_mac: None,
            interface: None,
            mtu: 0,
            source: None,
            times: Times::default(),
            traceroute: Vec::new(),
            os: None,
            ports: Vec::new(),
        }
    }
}

/// `o.current_scantype` as NSE sees it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Phase {
    PreScan,
    Scan,
    PostScan,
}

/// An interface's link type and, for Ethernet, its address.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    Ethernet([u8; 6]),
    Loopback,
    P2p,
    Other,
}

/// One entry of `nmap.list_interfaces()`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Interface {
    /// `devfullname`.
    pub device: Vec<u8>,
    /// `devname`.
    pub shortname: Vec<u8>,
    pub netmask_bits: i64,
    pub address: IpAddr,
    pub link: Link,
    pub up: bool,
    pub mtu: i64,
}

/// Where a log line goes: the C's `LOG_*` destinations.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LogTarget {
    /// `LOG_STDOUT`.
    Stdout,
    /// `LOG_STDERR`.
    Stderr,
    /// `LOG_NORMAL|LOG_STDERR`: what nmap's `error()` writes to.
    Error,
    /// `LOG_PLAIN`.
    Plain,
}

/// `nmap_fetchfile`: a data file's path, if it is found.
pub type FetchFile = Box<dyn Fn(&[u8]) -> Option<Vec<u8>>>;
/// Fill the buffer with random bytes, or fail.
pub type RandomBytes = Box<dyn FnMut(&mut [u8]) -> bool>;
/// Write a log line.
pub type LogSink = Box<dyn FnMut(LogTarget, &[u8])>;

/// The run's options and the system facts the module reads.
pub struct NmapEnv {
    /// `o.verbose`.
    pub verbose: i64,
    /// `o.debugging`.
    pub debugging: i64,
    /// `o.timing_level` (`-T`, 3 by default).
    pub timing_level: i64,
    /// `o.version_intensity`.
    pub version_intensity: i64,
    /// `o.ttl`, `-1` when `--ttl` was not given.
    pub ttl: i64,
    /// `o.extra_payload_length`, `-1` when `--data-length` was not given.
    pub data_length: i64,
    /// Whether this build has SSL.
    pub have_ssl: bool,
    /// `o.isr00t`.
    pub privileged: bool,
    /// `o.af() == AF_INET6`.
    pub ipv6: bool,
    /// `-e`.
    pub interface: Option<Vec<u8>>,
    pub dns_servers: Vec<Vec<u8>>,
    /// The `Exclude` ports of `nmap-service-probes` when `-sV` ran without
    /// `--allports`; `None` otherwise, and nothing is excluded.
    pub excluded_ports: Option<PortList>,
    /// `nmap-services`, for names of ports with no service record.
    pub services: Option<ServiceTable>,
    pub phase: Phase,
    /// `getinterfaces()`, or its error string.
    pub interfaces: Result<Vec<Interface>, Vec<u8>>,
    /// `nmap_fetchfile`: a data file's path, if it is found.
    pub fetchfile: FetchFile,
    /// `gettimeofday`: seconds and microseconds since the epoch.
    pub clock: Box<dyn Fn() -> (i64, i64)>,
    /// `get_random_bytes`: fill the buffer, or fail.
    pub random: RandomBytes,
    /// `log_write`.
    pub log: LogSink,
}

/// NSE's state behind the module, shared by its functions.
pub struct NmapLib {
    pub env: NmapEnv,
    hosts: Vec<ScriptHost>,
    /// `NSE_CURRENT_HOSTS`: target name and IP string to host.
    current: HashMap<Vec<u8>, usize>,
    /// Bumped by every [`NmapLib::set_hosts`], so that a host table kept from
    /// an earlier group no longer names a host.
    group: u64,
    /// `NewTargets`.
    history: BTreeSet<Vec<u8>>,
    queue: VecDeque<Vec<u8>>,
    /// `l_get_version_intensity`'s `static int intensity`.
    intensity: Option<i64>,
    /// Whether the running script was selected by name (`nse_selectedbyname`).
    pub selected_by_name: bool,
}

/// The module's state, as its functions hold it.
pub type Shared = Rc<RefCell<NmapLib>>;

impl NmapLib {
    pub fn new(env: NmapEnv) -> Shared {
        Rc::new(RefCell::new(Self {
            env,
            hosts: Vec::new(),
            current: HashMap::new(),
            group: 0,
            history: BTreeSet::new(),
            queue: VecDeque::new(),
            intensity: None,
            selected_by_name: false,
        }))
    }

    /// Start a new host group (`run_main`): these are the hosts scripts can
    /// now name, by target name and by IP, a later entry winning.
    pub fn set_hosts(&mut self, hosts: Vec<ScriptHost>) {
        self.group = self.group.wrapping_add(1);
        self.current.clear();
        for (i, h) in hosts.iter().enumerate() {
            if let Some(name) = h.targetname.as_ref().filter(|n| !n.is_empty()) {
                self.current.insert(name.clone(), i);
            }
            self.current.insert(h.ip.to_string().into_bytes(), i);
        }
        self.hosts = hosts;
    }

    /// The hosts of the current group, with whatever scripts changed.
    pub fn hosts(&self) -> &[ScriptHost] {
        &self.hosts
    }

    /// The new-targets queue, oldest first.
    pub fn queued_targets(&self) -> impl Iterator<Item = &[u8]> {
        self.queue.iter().map(Vec::as_slice)
    }

    fn log(&mut self, to: LogTarget, msg: &[u8]) {
        (self.env.log)(to, msg);
    }
}

/// The `_Target` field of a host table: which host it is, in which group.
/// The C stores a raw `Target *` there; this cannot dangle or be forged.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct HostToken {
    group: u64,
    index: usize,
}

#[derive(Collect)]
#[collect(require_static)]
pub(crate) struct Handle(pub(crate) Shared);

/// A failure, as `luaL_argerror` (`arg` set) or `luaL_error` would raise it.
/// Messages are bytes: they quote script data.
pub(crate) struct Fail {
    arg: Option<usize>,
    msg: Vec<u8>,
}

impl Fail {
    pub(crate) fn err(msg: impl Into<Vec<u8>>) -> Self {
        Self {
            arg: None,
            msg: msg.into(),
        }
    }

    pub(crate) fn arg(arg: usize, msg: impl Into<Vec<u8>>) -> Self {
        Self {
            arg: Some(arg),
            msg: msg.into(),
        }
    }

    pub(crate) fn raise<'gc>(&self, ctx: Context<'gc>, fname: &str) -> Error<'gc> {
        match self.arg {
            Some(n) => {
                let mut m = format!("bad argument #{n} to '{fname}' (").into_bytes();
                m.extend_from_slice(&self.msg);
                m.push(b')');
                lua_error_bytes(ctx, &m)
            }
            None => lua_error_bytes(ctx, &self.msg),
        }
    }
}

impl From<PackError> for Fail {
    fn from(e: PackError) -> Self {
        Self {
            arg: e.arg,
            msg: e.msg.into_bytes(),
        }
    }
}

/// The bytes of `s` before its first NUL: what C sees of a Lua string.
fn c_str(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i])
}

/// `lua_isstring`: a string or a number.
fn is_string(v: Value<'_>) -> bool {
    matches!(v, Value::String(_) | Value::Integer(_) | Value::Number(_))
}

/// `lua_tostring`: the bytes of a string or number, `None` for anything else.
fn to_bytes<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<Vec<u8>> {
    match v {
        Value::String(s) => Some(s.as_bytes().to_vec()),
        Value::Integer(_) | Value::Number(_) => v.into_string(ctx).map(|s| s.as_bytes().to_vec()),
        _ => None,
    }
}

/// `luaL_checkoption(L, arg, def, lst)`: the index of the option named.
fn check_option(
    args: &LuaArgs<'_, '_, '_>,
    arg: usize,
    def: Option<&str>,
    options: &[&str],
) -> Result<usize, Fail> {
    let name: Vec<u8> = match (def, args.get(arg)) {
        (Some(d), None | Some(Value::Nil)) => d.as_bytes().to_vec(),
        _ => args.string(arg)?.into_owned(),
    };
    let name = c_str(&name);
    options
        .iter()
        .position(|o| o.as_bytes() == name)
        .ok_or_else(|| {
            let mut m = b"invalid option '".to_vec();
            m.extend_from_slice(name);
            m.push(b'\'');
            Fail::arg(arg, m)
        })
}

const PROTOCOLS: [&str; 3] = ["tcp", "udp", "sctp"];
const PROTOCOL_VALUES: [Protocol; 3] = [Protocol::Tcp, Protocol::Udp, Protocol::Sctp];

/// `nseU_gettarget(L, 1)`: the host a host table names.
pub(crate) fn get_target(lib: &NmapLib, args: &LuaArgs<'_, '_, '_>, idx: usize) -> Result<usize, Fail> {
    let Some(Value::Table(t)) = args.get(idx) else {
        return Err(type_error(args.get(idx), idx, "table").into());
    };
    let ctx = args.ctx;
    let token = t.get_value(ctx, "_Target");
    let targetname = t.get_value(ctx, "targetname");
    let ip = t.get_value(ctx, "ip");
    if !(is_string(targetname) || is_string(ip)) {
        return Err(Fail::err(
            "host table does not have a 'ip' or 'targetname' field",
        ));
    }
    if let Value::UserData(u) = token {
        if let Ok(tok) = u.downcast_static::<HostToken>() {
            if tok.group == lib.group && tok.index < lib.hosts.len() {
                return Ok(tok.index);
            }
        }
    }
    // `nse_gettarget` looks the value itself up, so only a string can match.
    for key in [ip, targetname] {
        if let Value::String(s) = key {
            if let Some(&i) = lib.current.get(s.as_bytes()) {
                return Ok(i);
            }
        }
    }
    Err(Fail::arg(1, "host is not being processed right now"))
}

/// Which protocols `nextPort` may visit when it starts afresh.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Allowed {
    One(Protocol),
    UdpAndSctp,
}

/// `PortList::nextPort`: the port after `cur` (or the first) in the
/// protocol's numeric order whose state is `state` (`None`: any) — and,
/// faithfully, when `cur`'s protocol list runs out, the ports of the
/// protocols after it, whatever protocol was asked for.
fn next_port(
    host: &ScriptHost,
    cur: Option<usize>,
    allowed: Allowed,
    state: Option<PortState>,
) -> Option<usize> {
    let (proto, after) = match cur {
        Some(c) => (host.ports[c].protocol, Some(host.ports[c].number)),
        None => match allowed {
            Allowed::One(p) => (p, None),
            Allowed::UdpAndSctp => (Protocol::Udp, None),
        },
    };
    let mut list: Vec<usize> = (0..host.ports.len())
        .filter(|&i| host.ports[i].protocol == proto)
        .collect();
    list.sort_by_key(|&i| host.ports[i].number);
    let found = list
        .into_iter()
        .filter(|&i| after.is_none_or(|a| host.ports[i].number > a))
        .find(|&i| state.is_none_or(|s| host.ports[i].state == s));
    if found.is_some() {
        return found;
    }
    let continues = |from: Protocol| match cur {
        Some(_) => proto == from,
        None => from == Protocol::Udp && allowed == Allowed::UdpAndSctp,
    };
    if cur.is_some() && proto == Protocol::Tcp {
        return next_port(host, None, Allowed::UdpAndSctp, state);
    }
    if continues(Protocol::Udp) {
        return next_port(host, None, Allowed::One(Protocol::Sctp), state);
    }
    None
}

/// `nseU_getport(L, target, &port, idx)`: the scanned port a port table names.
pub(crate) fn get_port(
    lib: &NmapLib,
    host: usize,
    args: &LuaArgs<'_, '_, '_>,
    idx: usize,
) -> Result<Option<usize>, Fail> {
    let Some(Value::Table(t)) = args.get(idx) else {
        return Err(type_error(args.get(idx), idx, "table").into());
    };
    let ctx = args.ctx;
    let Value::Integer(number) = t.get_value(ctx, "number") else {
        return Err(Fail::err("port 'number' field must be an integer"));
    };
    let proto_v = t.get_value(ctx, "protocol");
    if !is_string(proto_v) {
        return Err(Fail::err("port 'protocol' field must be a string"));
    }
    // `(int) lua_tointeger(...)`: the integer wraps to 32 bits.
    #[allow(clippy::cast_possible_truncation)]
    let portno = number as i32;
    let proto_bytes = to_bytes(ctx, proto_v).unwrap_or_default();
    let Some(p) = PROTOCOLS
        .iter()
        .position(|n| n.as_bytes() == c_str(&proto_bytes))
    else {
        return Err(Fail::err(
            "port 'protocol' field must be \"udp\", \"sctp\" or \"tcp\"",
        ));
    };
    let h = &lib.hosts[host];
    let mut cur = None;
    while let Some(i) = next_port(h, cur, Allowed::One(PROTOCOL_VALUES[p]), None) {
        if i32::from(h.ports[i].number) == portno {
            return Ok(Some(i));
        }
        cur = Some(i);
    }
    Ok(None)
}

fn set_bytes<'gc>(ctx: Context<'gc>, t: Table<'gc>, key: &'static str, v: Option<&[u8]>) {
    // `nseU_setsfield` with NULL sets nil, which is no field at all.
    if let Some(v) = v {
        t.set_field(ctx, key, ctx.intern(c_str(v)));
    }
}

fn string_list<'gc>(ctx: Context<'gc>, items: &[Vec<u8>]) -> Table<'gc> {
    let t = Table::new(&ctx);
    for (i, s) in items.iter().enumerate() {
        let _ = t.set(ctx, Value::Integer(lua_index(i)), ctx.intern(c_str(s)));
    }
    t
}

#[allow(clippy::cast_possible_wrap)] // an index into a list held in memory
fn lua_index(i: usize) -> i64 {
    (i as i64).saturating_add(1)
}

fn bin_ip(ip: IpAddr) -> Vec<u8> {
    match ip {
        IpAddr::V4(a) => a.octets().to_vec(),
        IpAddr::V6(a) => a.octets().to_vec(),
    }
}

/// `getServiceDeductions`: the port's record, or a table lookup.
fn deductions(env: &NmapEnv, port: &ScriptPort) -> ServiceDeductions {
    port.service.clone().unwrap_or_else(|| ServiceDeductions {
        name: env
            .services
            .as_ref()
            .and_then(|s| s.service_name(port.number, port.protocol))
            .map(|n| n.as_bytes().to_vec()),
        name_confidence: 3,
        ..ServiceDeductions::default()
    })
}

/// `set_portinfo`: a port table.
pub fn port_table<'gc>(ctx: Context<'gc>, env: &NmapEnv, port: &ScriptPort) -> Table<'gc> {
    let sd = deductions(env, port);
    let t = Table::new(&ctx);
    t.set_field(ctx, "number", Value::Integer(i64::from(port.number)));
    set_bytes(ctx, t, "service", sd.name.as_deref());
    t.set_field(ctx, "protocol", port.protocol.as_str());
    t.set_field(ctx, "state", port.state.as_str());
    t.set_field(ctx, "reason", port.reason);
    t.set_field(
        ctx,
        "reason_ttl",
        Value::Integer(i64::from(port.reason_ttl)),
    );
    let v = Table::new(&ctx);
    set_bytes(ctx, v, "name", sd.name.as_deref());
    #[allow(clippy::cast_precision_loss)] // 0..=10
    v.set_field(
        ctx,
        "name_confidence",
        Value::Number(sd.name_confidence as f64),
    );
    set_bytes(ctx, v, "product", sd.product.as_deref());
    set_bytes(ctx, v, "version", sd.version.as_deref());
    set_bytes(ctx, v, "extrainfo", sd.extrainfo.as_deref());
    set_bytes(ctx, v, "hostname", sd.hostname.as_deref());
    set_bytes(ctx, v, "ostype", sd.ostype.as_deref());
    set_bytes(ctx, v, "devicetype", sd.devicetype.as_deref());
    v.set_field(
        ctx,
        "service_tunnel",
        match sd.tunnel {
            Tunnel::None => "none",
            Tunnel::Ssl => "ssl",
        },
    );
    set_bytes(ctx, v, "service_fp", sd.service_fp.as_deref());
    v.set_field(
        ctx,
        "service_dtype",
        match sd.dtype {
            DetectionType::Table => "table",
            DetectionType::Probed => "probed",
        },
    );
    v.set_field(ctx, "cpe", string_list(ctx, &sd.cpe));
    t.set_field(ctx, "version", v);
    t
}

/// `set_hostinfo`: the host table for host `index` of the current group.
pub fn host_table<'gc>(ctx: Context<'gc>, lib: &Shared, index: usize) -> Table<'gc> {
    let lib = lib.borrow();
    let h = &lib.hosts[index];
    let t = Table::new(&ctx);
    let token = HostToken {
        group: lib.group,
        index,
    };
    t.set_field(ctx, "_Target", UserData::new_static(&ctx, token));
    t.set_field(ctx, "ip", ctx.intern(h.ip.to_string().as_bytes()));
    t.set_field(ctx, "name", ctx.intern(c_str(&h.hostname)));
    set_bytes(ctx, t, "targetname", h.targetname.as_deref());
    t.set_field(ctx, "reason", h.reason);
    t.set_field(ctx, "reason_ttl", Value::Integer(i64::from(h.reason_ttl)));
    if let Some(d) = h.directly_connected {
        t.set_field(ctx, "directly_connected", d);
    }
    for (key, mac) in [
        ("mac_addr", h.mac),
        ("mac_addr_next_hop", h.next_hop_mac),
        ("mac_addr_src", h.src_mac),
    ] {
        if let Some(m) = mac {
            t.set_field(ctx, key, ctx.intern(&m));
        }
    }
    set_bytes(ctx, t, "interface", h.interface.as_deref());
    t.set_field(ctx, "interface_mtu", Value::Integer(h.mtu));
    t.set_field(ctx, "bin_ip", ctx.intern(&bin_ip(h.ip)));
    if let Some(src) = h.source {
        t.set_field(ctx, "bin_ip_src", ctx.intern(&bin_ip(src)));
    }
    let times = Table::new(&ctx);
    #[allow(clippy::cast_precision_loss)] // microsecond timings
    for (key, v) in [
        ("srtt", h.times.srtt),
        ("rttvar", h.times.rttvar),
        ("timeout", h.times.timeout),
    ] {
        times.set_field(ctx, key, Value::Number(v as f64 / 1_000_000.0));
    }
    t.set_field(ctx, "times", times);
    t.set_field(ctx, "registry", Table::new(&ctx));
    if !h.traceroute.is_empty() {
        let tr = Table::new(&ctx);
        for (i, hop) in h.traceroute.iter().enumerate() {
            let ht = Table::new(&ctx);
            if !hop.timed_out {
                if let Some(ip) = hop.ip {
                    ht.set_field(ctx, "ip", ctx.intern(ip.to_string().as_bytes()));
                }
                if let Some(n) = hop.name.as_ref().filter(|n| !n.is_empty()) {
                    ht.set_field(ctx, "name", ctx.intern(c_str(n)));
                }
                ht.set_field(ctx, "srtt", Value::Number(hop.rtt / 1000.0));
            }
            let _ = tr.set(ctx, Value::Integer(lua_index(i)), ht);
        }
        t.set_field(ctx, "traceroute", tr);
    }
    if let Some(os) = &h.os {
        t.set_field(ctx, "os_fp", ctx.intern(c_str(&os.fingerprint)));
        let n = os.perfect_matches.len();
        if os.success && (1..=8).contains(&n) {
            let list = Table::new(&ctx);
            for (i, name) in os.perfect_matches.iter().enumerate() {
                let m = Table::new(&ctx);
                m.set_field(ctx, "name", ctx.intern(c_str(name)));
                let classes = Table::new(&ctx);
                for (j, c) in os.classes.iter().enumerate() {
                    let ct = Table::new(&ctx);
                    set_bytes(ctx, ct, "vendor", c.vendor.as_deref());
                    set_bytes(ctx, ct, "osfamily", c.osfamily.as_deref());
                    set_bytes(ctx, ct, "osgen", c.osgen.as_deref());
                    set_bytes(ctx, ct, "type", c.device_type.as_deref());
                    ct.set_field(ctx, "cpe", string_list(ctx, &c.cpe));
                    let _ = classes.set(ctx, Value::Integer(lua_index(j)), ct);
                }
                m.set_field(ctx, "classes", classes);
                let _ = list.set(ctx, Value::Integer(lua_index(i)), m);
            }
            t.set_field(ctx, "os", list);
        }
    }
    t
}

/// A registry value from a parsed argument.
fn arg_value<'gc>(ctx: Context<'gc>, v: &ArgValue) -> Value<'gc> {
    match v {
        ArgValue::Str(s) => Value::String(ctx.intern(s)),
        ArgValue::Table(t) => Value::Table(arg_table(ctx, t)),
    }
}

fn arg_table<'gc>(ctx: Context<'gc>, a: &ArgTable) -> Table<'gc> {
    let t = Table::new(&ctx);
    for (i, v) in a.array.iter().enumerate() {
        let _ = t.set(ctx, Value::Integer(lua_index(i)), arg_value(ctx, v));
    }
    for (k, v) in &a.fields {
        let _ = t.set(ctx, Value::String(ctx.intern(k)), arg_value(ctx, v));
    }
    t
}

pub(crate) type Body = for<'gc, 'a> fn(&Shared, Context<'gc>, &mut Stack<'gc, 'a>) -> Result<(), Fail>;

pub(crate) fn install<'gc>(
    ctx: Context<'gc>,
    t: Table<'gc>,
    lib: &Shared,
    name: &'static str,
    body: Body,
) {
    t.set_field(
        ctx,
        name,
        Callback::from_fn_with(
            &ctx,
            Handle(lib.clone()),
            move |h, ctx, _, mut stack| match body(&h.0, ctx, &mut stack) {
                Ok(()) => Ok(CallbackReturn::Return),
                Err(e) => Err(e.raise(ctx, name)),
            },
        ),
    );
}

/// Build the `nmap` table (`luaopen_nmap`), with `registry.args` from the
/// parsed script arguments, and set it as the global `nmap`.
pub fn load_nmap<'gc>(ctx: Context<'gc>, lib: &Shared, args: &ArgTable) -> Table<'gc> {
    let t = Table::new(&ctx);
    let fns: [(&'static str, Body); 25] = [
        ("get_port_state", l_get_port_state),
        ("get_ports", l_get_ports),
        ("set_port_state", l_set_port_state),
        ("set_port_version", l_set_port_version),
        ("port_is_excluded", l_port_is_excluded),
        ("clock_ms", l_clock_ms),
        ("clock", l_clock),
        ("log_write", l_log_write),
        ("version_intensity", l_version_intensity),
        ("verbosity", l_verbosity),
        ("debugging", |l, _, s| {
            put(s, Value::Integer(l.borrow().env.debugging))
        }),
        ("have_ssl", |l, _, s| {
            put(s, Value::Boolean(l.borrow().env.have_ssl))
        }),
        ("fetchfile", l_fetchfile),
        ("timing_level", |l, _, s| {
            put(s, Value::Integer(l.borrow().env.timing_level))
        }),
        ("add_targets", l_add_targets),
        ("new_targets_num", |l, _, s| {
            put(s, Value::Integer(len_i64(l.borrow().history.len())))
        }),
        ("get_dns_servers", |l, ctx, s| {
            let t = string_list(ctx, &l.borrow().env.dns_servers);
            put(s, Value::Table(t))
        }),
        ("is_privileged", |l, _, s| {
            put(s, Value::Boolean(l.borrow().env.privileged))
        }),
        ("address_family", |l, ctx, s| {
            let v: &[u8] = if l.borrow().env.ipv6 {
                b"inet6"
            } else {
                b"inet"
            };
            put(s, Value::String(ctx.intern(v)))
        }),
        ("get_interface", |l, ctx, s| {
            let v = match &l.borrow().env.interface {
                Some(d) if !d.is_empty() => Value::String(ctx.intern(c_str(d))),
                _ => Value::Nil,
            };
            put(s, v)
        }),
        ("list_interfaces", l_list_interfaces),
        ("get_ttl", |l, _, s| {
            let ttl = l.borrow().env.ttl;
            put(
                s,
                Value::Integer(if (0..=255).contains(&ttl) { ttl } else { 64 }),
            )
        }),
        ("get_payload_length", |l, _, s| {
            put(s, Value::Integer(l.borrow().env.data_length.max(0)))
        }),
        ("get_random_bytes", l_get_random_bytes),
        ("resolve", |_, _, _| Err(not_yet("resolve"))),
    ];
    for (name, body) in fns {
        install(ctx, t, lib, name, body);
    }
    t.set_field(
        ctx,
        "new_try",
        Callback::from_fn_with(&ctx, Handle(lib.clone()), l_new_try),
    );
    let io: [(&'static str, Body); 2] = [
        ("mutex", |_, _, _| Err(not_yet("mutex"))),
        ("condvar", |_, _, _| Err(not_yet("condvar"))),
    ];
    for (name, body) in io {
        install(ctx, t, lib, name, body);
    }
    // `luaopen_nmap` requires `nmap.socket` and `nmap.dnet` and keeps them as
    // `nmap.socket` and `nmap.dnet`, with `new_socket`, `new_dnet` and
    // `get_interface_info` taken out of them. Their functions do I/O (M6.4d);
    // until then each raises, but the tables are there for libraries to load.
    // `loop` is the exception: with no socket it has nothing to do.
    let socket = Table::new(&ctx);
    let socket_fns: [(&'static str, Body); 5] = [
        // `l_loop` runs nsock's event loop for up to the given milliseconds;
        // with no socket open it has no event to wait for, and returns at
        // once. The engine calls it once per pass of its scheduler.
        ("loop", |_, ctx, s| {
            LuaArgs { ctx, stack: s }.check_integer(1)?;
            s.clear();
            Ok(())
        }),
        ("new", |_, _, _| Err(not_yet("socket.new"))),
        ("sleep", |_, _, _| Err(not_yet("socket.sleep"))),
        ("parse_ssl_certificate", |_, _, _| {
            Err(not_yet("socket.parse_ssl_certificate"))
        }),
        ("get_stats", |_, _, _| Err(not_yet("socket.get_stats"))),
    ];
    for (name, body) in socket_fns {
        install(ctx, socket, lib, name, body);
    }
    t.set_field(ctx, "new_socket", socket.get_value(ctx, "new"));
    t.set_field(ctx, "socket", socket);
    let dnet = Table::new(&ctx);
    let dnet_fns: [(&'static str, Body); 2] = [
        ("new", |_, _, _| Err(not_yet("dnet.new"))),
        ("get_interface_info", |_, _, _| {
            Err(not_yet("dnet.get_interface_info"))
        }),
    ];
    for (name, body) in dnet_fns {
        install(ctx, dnet, lib, name, body);
    }
    t.set_field(ctx, "new_dnet", dnet.get_value(ctx, "new"));
    t.set_field(
        ctx,
        "get_interface_info",
        dnet.get_value(ctx, "get_interface_info"),
    );
    t.set_field(ctx, "dnet", dnet);
    let registry = Table::new(&ctx);
    registry.set_field(ctx, "args", arg_table(ctx, args));
    t.set_field(ctx, "registry", registry);
    ctx.set_global("nmap", t);
    t
}

fn not_yet(name: &str) -> Fail {
    Fail::err(format!(
        "nmap.{name} is not available before M6.4 (it needs I/O)"
    ))
}

#[allow(clippy::cast_possible_wrap)] // a count of things held in memory
fn len_i64(n: usize) -> i64 {
    n as i64
}

/// Replace the arguments with one result.
fn put<'gc>(s: &mut Stack<'gc, '_>, v: Value<'gc>) -> Result<(), Fail> {
    s.clear();
    s.push_back(v);
    Ok(())
}

fn l_get_port_state<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let l = lib.borrow();
    let args = LuaArgs { ctx, stack: s };
    let host = get_target(&l, &args, 1)?;
    let port = get_port(&l, host, &args, 2)?;
    let v = match port {
        Some(p) => Value::Table(port_table(ctx, &l.env, &l.hosts[host].ports[p])),
        None => Value::Nil,
    };
    drop(l);
    put(s, v)
}

const STATES: [&str; 6] = [
    "open",
    "filtered",
    "unfiltered",
    "closed",
    "open|filtered",
    "closed|filtered",
];
const STATE_VALUES: [PortState; 6] = [
    PortState::Open,
    PortState::Filtered,
    PortState::Unfiltered,
    PortState::Closed,
    PortState::OpenFiltered,
    PortState::ClosedFiltered,
];

fn l_get_ports<'gc>(lib: &Shared, ctx: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let l = lib.borrow();
    let args = LuaArgs { ctx, stack: s };
    let host = get_target(&l, &args, 1)?;
    let proto = PROTOCOL_VALUES[check_option(&args, 3, None, &PROTOCOLS)?];
    let state = STATE_VALUES[check_option(&args, 4, None, &STATES)?];
    // `!lua_isnil(L, 2)`: an absent argument is not nil, so it is checked.
    let cur = match args.get(2) {
        Some(Value::Nil) => None,
        _ => get_port(&l, host, &args, 2)?,
    };
    let h = &l.hosts[host];
    let v = match next_port(h, cur, Allowed::One(proto), Some(state)) {
        Some(p) => Value::Table(port_table(ctx, &l.env, &h.ports[p])),
        None => Value::Nil,
    };
    drop(l);
    put(s, v)
}

fn l_set_port_state<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let mut l = lib.borrow_mut();
    let args = LuaArgs { ctx, stack: s };
    let host = get_target(&l, &args, 1)?;
    // The new state is only checked once the port is found.
    if let Some(p) = get_port(&l, host, &args, 2)? {
        let state = [PortState::Open, PortState::Closed]
            [check_option(&args, 3, None, &["open", "closed"])?];
        let (number, protocol) = {
            let port = &l.hosts[host].ports[p];
            (port.number, port.protocol)
        };
        if l.hosts[host].ports[p].state != state {
            // `PortList::setPortState` announces it, then `setStateReason`.
            if (state == PortState::Open && l.env.verbose != 0) || l.env.debugging > 1 {
                let ip = l.hosts[host].ip;
                let msg = format!(
                    "Discovered {} port {}/{} on {ip}\n",
                    state.as_str(),
                    number,
                    protocol.as_str()
                );
                l.log(LogTarget::Stdout, msg.as_bytes());
            }
            let port = &mut l.hosts[host].ports[p];
            port.state = state;
            port.reason = "script-set";
            port.reason_ttl = 0;
        }
    }
    drop(l);
    s.clear();
    Ok(())
}

/// `cstringSanityCheck`: at most `len` bytes of the C string, every
/// unprintable byte replaced by `.`.
pub fn sanitize(s: &[u8], len: usize) -> Vec<u8> {
    c_str(s)
        .iter()
        .take(len)
        .map(|&b| if (0x20..=0x7e).contains(&b) { b } else { b'.' })
        .collect()
}

const PROBE_STATES: [&str; 5] = [
    "hardmatched",
    "softmatched",
    "nomatch",
    "tcpwrapped",
    "incomplete",
];

fn l_set_port_version<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let mut l = lib.borrow_mut();
    let args = LuaArgs { ctx, stack: s };
    let probestate = check_option(&args, 3, Some("hardmatched"), &PROBE_STATES)?;
    let host = get_target(&l, &args, 1)?;
    let Some(p) = get_port(&l, host, &args, 2)? else {
        drop(l);
        s.clear();
        return Ok(()); // invalid port
    };
    let Some(Value::Table(port_t)) = args.get(2) else {
        unreachable!("get_port checked argument 2 is a table");
    };
    let Value::Table(v) = port_t.get_value(ctx, "version") else {
        return Err(Fail::err("port 'version' field must be a table"));
    };
    let field = |k: &'static str| to_bytes(ctx, v.get_value(ctx, k));
    let name = field("name");
    let product = field("product");
    let version = field("version");
    let extrainfo = field("extrainfo");
    let hostname = field("hostname");
    let ostype = field("ostype");
    let devicetype = field("devicetype");
    let service_fp = field("service_fp");
    let tunnel = match field("service_tunnel").as_deref().map(c_str) {
        None | Some(b"none") => Tunnel::None,
        Some(b"ssl") => Tunnel::Ssl,
        Some(_) => {
            return Err(Fail::arg(
                2,
                "invalid value for port.version.service_tunnel",
            ))
        }
    };
    let mut cpe = Vec::new();
    match v.get_value(ctx, "cpe") {
        Value::Nil => {}
        Value::Table(c) => {
            for (_, item) in c.iter() {
                if let Some(b) = to_bytes(ctx, item) {
                    cpe.push(sanitize(&b, 80));
                }
            }
        }
        _ => return Err(Fail::err("port.version 'cpe' field must be a table")),
    }

    // `PortList::setServiceProbeResults`.
    let (number, protocol) = {
        let port = &l.hosts[host].ports[p];
        (port.number, port.protocol)
    };
    let mut name = name.map(|n| c_str(&n).to_vec());
    let (dtype, confidence) = match probestate {
        0 | 1 => (DetectionType::Probed, 10),
        3 => {
            name.get_or_insert_with(|| b"tcpwrapped".to_vec());
            (DetectionType::Probed, 8)
        }
        _ => {
            if name.is_none() {
                name = l
                    .env
                    .services
                    .as_ref()
                    .and_then(|t| t.service_name(number, protocol))
                    .map(|n| n.as_bytes().to_vec());
            }
            (DetectionType::Table, 3)
        }
    };
    let sd = ServiceDeductions {
        name,
        name_confidence: confidence,
        product: product.map(|x| sanitize(&x, 80)),
        version: version.map(|x| sanitize(&x, 80)),
        extrainfo: extrainfo.map(|x| sanitize(&x, 256)),
        hostname: hostname.map(|x| sanitize(&x, 80)),
        ostype: ostype.map(|x| sanitize(&x, 32)),
        devicetype: devicetype.map(|x| sanitize(&x, 32)),
        tunnel,
        // A hard match never keeps a fingerprint.
        service_fp: if probestate == 0 {
            None
        } else {
            service_fp.map(|f| c_str(&f).to_vec())
        },
        dtype,
        cpe,
    };
    l.hosts[host].ports[p].service = Some(sd);
    drop(l);
    s.clear();
    Ok(())
}

fn l_port_is_excluded<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let mut l = lib.borrow_mut();
    let args = LuaArgs { ctx, stack: s };
    // `(unsigned short) luaL_checkinteger(L, 1)`
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let portno = args.check_integer(1)? as u16;
    let proto = PROTOCOL_VALUES[check_option(&args, 2, None, &PROTOCOLS)?];
    let excluded = l.env.excluded_ports.as_ref().is_some_and(|x| {
        match proto {
            Protocol::Tcp => &x.tcp,
            Protocol::Udp => &x.udp,
            Protocol::Sctp => &x.sctp,
        }
        .contains(&portno)
    });
    if excluded && l.env.debugging != 0 {
        let msg = format!("EXCLUDING {portno}/{}\n", proto.as_str());
        l.log(LogTarget::Plain, msg.as_bytes());
    }
    drop(l);
    put(s, Value::Boolean(excluded))
}

fn l_clock_ms<'gc>(lib: &Shared, _: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let (sec, usec) = (lib.borrow().env.clock)();
    #[allow(clippy::cast_precision_loss)] // as the C's `(lua_Number)` casts
    let ms = (sec as f64 * 1000.0 + usec as f64 / 1000.0).ceil();
    put(s, Value::Number(ms))
}

fn l_clock<'gc>(lib: &Shared, _: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let (sec, usec) = (lib.borrow().env.clock)();
    #[allow(clippy::cast_precision_loss)] // `TIMEVAL_SECS`
    let secs = sec as f64 + usec as f64 / 1_000_000.0;
    put(s, Value::Number(secs))
}

fn l_log_write<'gc>(lib: &Shared, ctx: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    let to = [LogTarget::Stdout, LogTarget::Stderr]
        [check_option(&args, 1, None, &["stdout", "stderr"])?];
    let msg = args.string(2)?;
    let mut line = b"NSE: ".to_vec();
    line.extend_from_slice(c_str(&msg));
    line.push(b'\n');
    lib.borrow_mut().log(to, &line);
    s.clear();
    Ok(())
}

/// The arguments' `script-intensity`, as `lua_tointegerx` reads it.
fn script_intensity(ctx: Context<'_>) -> Option<i64> {
    let Value::Table(nmap) = ctx.globals().get_value(ctx, "nmap") else {
        return None;
    };
    let Value::Table(reg) = nmap.get_value(ctx, "registry") else {
        return None;
    };
    let Value::Table(args) = reg.get_value(ctx, "args") else {
        return None;
    };
    match args.get_value(ctx, "script-intensity") {
        v @ (Value::Integer(_) | Value::Number(_) | Value::String(_)) => v.to_integer(),
        _ => None,
    }
}

fn l_version_intensity<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let mut l = lib.borrow_mut();
    let v = if l.selected_by_name {
        9
    } else if let Some(i) = l.intensity {
        i
    } else {
        let i = match script_intensity(ctx) {
            Some(i) => {
                if !(0..=9).contains(&i) {
                    let msg = format!(
                        "Warning: Valid values of script arg script-intensity are between 0 and 9. Using {i} nevertheless.\n\n",
                    );
                    l.log(LogTarget::Error, msg.as_bytes());
                }
                // `int script_intensity = lua_tointegerx(...)`
                #[allow(clippy::cast_possible_truncation)]
                i64::from(i as i32)
            }
            None => l.env.version_intensity,
        };
        l.intensity = Some(i);
        i
    };
    drop(l);
    put(s, Value::Integer(v))
}

fn l_verbosity<'gc>(lib: &Shared, _: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let l = lib.borrow();
    let v = l.env.verbose.saturating_add(i64::from(l.selected_by_name));
    drop(l);
    put(s, Value::Integer(v))
}

fn l_fetchfile<'gc>(lib: &Shared, ctx: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    let name = args.string(1)?;
    let found = (lib.borrow().env.fetchfile)(c_str(&name));
    let v = match found {
        Some(p) => Value::String(ctx.intern(&p)),
        None => Value::Nil,
    };
    put(s, v)
}

/// `NewTargets::insert`: the queue's length, 1 for a target already seen, 0
/// for a refusal.
fn insert_target(l: &mut NmapLib, target: &[u8]) -> usize {
    if !target.is_empty() {
        if l.env.phase == Phase::PostScan {
            l.log(
                LogTarget::Error,
                b"ERROR: adding targets is disabled in the Post-scanning phase.\n",
            );
            return 0;
        }
        if target.len() >= 1024 {
            l.log(
                LogTarget::Error,
                b"ERROR: new target is too long (>= 1024), failed to add it.\n",
            );
            return 0;
        }
        if l.history.insert(target.to_vec()) {
            l.queue.push_back(target.to_vec());
            if l.env.debugging > 2 {
                let mut m = b"New Targets: target ".to_vec();
                m.extend_from_slice(target);
                m.extend_from_slice(b" pushed onto the queue.\n");
                l.log(LogTarget::Plain, &m);
            }
        } else {
            if l.env.debugging > 2 {
                let mut m = b"New Targets: target ".to_vec();
                m.extend_from_slice(target);
                m.extend_from_slice(b" was already added.\n");
                l.log(LogTarget::Plain, &m);
            }
            return 1;
        }
    }
    l.queue.len()
}

fn l_add_targets<'gc>(lib: &Shared, ctx: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let mut l = lib.borrow_mut();
    let n = s.len();
    if n == 0 {
        let q = len_i64(l.queue.len());
        drop(l);
        return put(s, Value::Integer(q));
    }
    let args = LuaArgs { ctx, stack: s };
    let mut added: i64 = 0;
    for i in 1..=n {
        let target = args.string(i)?;
        if insert_target(&mut l, c_str(&target)) == 0 {
            break;
        }
        added = added.saturating_add(1);
    }
    drop(l);
    s.clear();
    s.push_back(Value::Integer(added));
    if added == 0 {
        s.push_back(Value::String(ctx.intern(b"failed to add new targets.")));
    }
    Ok(())
}

fn l_list_interfaces<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let l = lib.borrow();
    s.clear();
    match &l.env.interfaces {
        Ok(list) if !list.is_empty() => {
            let t = Table::new(&ctx);
            for (i, iface) in list.iter().enumerate() {
                let e = Table::new(&ctx);
                e.set_field(ctx, "device", ctx.intern(c_str(&iface.device)));
                e.set_field(ctx, "shortname", ctx.intern(c_str(&iface.shortname)));
                e.set_field(ctx, "netmask", Value::Integer(iface.netmask_bits));
                e.set_field(
                    ctx,
                    "address",
                    ctx.intern(iface.address.to_string().as_bytes()),
                );
                let link: &[u8] = match iface.link {
                    Link::Ethernet(mac) => {
                        e.set_field(ctx, "mac", ctx.intern(&mac));
                        if let IpAddr::V4(a) = iface.address {
                            let bits = u32::try_from(iface.netmask_bits.clamp(0, 32)).unwrap_or(32);
                            let mask = u32::MAX
                                .checked_shl(32_u32.saturating_sub(bits))
                                .unwrap_or(0);
                            let b = std::net::Ipv4Addr::from(u32::from(a) | !mask);
                            e.set_field(ctx, "broadcast", ctx.intern(b.to_string().as_bytes()));
                        }
                        b"ethernet"
                    }
                    Link::Loopback => b"loopback",
                    Link::P2p => b"p2p",
                    Link::Other => b"other",
                };
                e.set_field(ctx, "link", ctx.intern(link));
                e.set_field(ctx, "up", if iface.up { "up" } else { "down" });
                e.set_field(ctx, "mtu", Value::Integer(iface.mtu));
                let _ = t.set(ctx, Value::Integer(lua_index(i)), e);
            }
            s.push_back(Value::Table(t));
        }
        // `nseU_safeerror(L, "%s", errstr)`
        Ok(_) => {
            s.push_back(Value::Boolean(false));
            s.push_back(Value::String(ctx.intern(b"")));
        }
        Err(e) => {
            s.push_back(Value::Boolean(false));
            s.push_back(Value::String(ctx.intern(c_str(e))));
        }
    }
    Ok(())
}

fn l_get_random_bytes<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    // `int numbytes = luaL_checkinteger(L, 1)`
    #[allow(clippy::cast_possible_truncation)]
    let n = args.check_integer(1)? as i32;
    let Ok(n) = usize::try_from(n) else {
        return Err(Fail::err("Invalid length argument to get_random_bytes."));
    };
    let mut buf = Vec::new();
    if buf.try_reserve_exact(n).is_err() {
        return Err(Fail::err("not enough memory"));
    }
    buf.resize(n, 0);
    if n > 0 && !(lib.borrow_mut().env.random)(&mut buf) {
        return Err(Fail::err("Error in nbase's get_random_bytes."));
    }
    put(s, Value::String(ctx.intern(&buf)))
}

/// What a `new_try` function holds: the module, for its warning, and the
/// handler.
#[derive(Collect)]
#[collect(no_drop)]
struct TryRoot<'gc> {
    lib: Handle,
    handler: Value<'gc>,
}

/// `nmap.new_try([handler])`: a function that passes through a `true` and the
/// values after it, and turns a falsy first value into an error table.
fn l_new_try<'gc>(
    h: &Handle,
    ctx: Context<'gc>,
    _: Execution<'gc, '_>,
    mut stack: Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    // `lua_settop(L, 1)`: the handler, or nil.
    let root = TryRoot {
        lib: Handle(h.0.clone()),
        handler: stack.get(0),
    };
    stack.clear();
    let f = Callback::from_fn_with(&ctx, root, |root, ctx, _, mut stack| {
        let first = stack.get(0);
        if !matches!(first, Value::Boolean(_) | Value::Nil) {
            // nmap's `error()`: a warning on stderr, not a Lua error.
            root.lib.0.borrow_mut().log(
                LogTarget::Error,
                b"finalizing a non-conforming function that did not first return a boolean\n",
            );
        }
        finish_try(ctx, root.handler, first, &mut stack)
    });
    stack.push_back(Value::Function(Function::Callback(f)));
    Ok(CallbackReturn::Return)
}

fn finish_try<'gc>(
    ctx: Context<'gc>,
    handler: Value<'gc>,
    first: Value<'gc>,
    stack: &mut Stack<'gc, '_>,
) -> Result<CallbackReturn<'gc>, Error<'gc>> {
    if first.to_bool() {
        // `return lua_gettop(L)-1`: everything after the first value.
        if !stack.is_empty() {
            stack.pop_front();
        }
        return Ok(CallbackReturn::Return);
    }
    // `lua_settop(L, 2)`: the message, possibly nil.
    let message = stack.get(1);
    stack.clear();
    if handler.is_nil() {
        return Err(try_error(ctx, message));
    }
    // `lua_callk` on something uncallable: the C's message, as a string (the
    // VM's own would be a userdata, `vm-runtime-errors-are-not-strings`).
    let Ok(function) = piccolo::meta_ops::call(ctx, handler) else {
        let msg = format!("attempt to call a {} value", handler.type_name());
        return Err(lua_error_bytes(ctx, msg.as_bytes()));
    };
    Ok(CallbackReturn::Call {
        function,
        then: Some(BoxSequence::new(&ctx, TryCleanup { message })),
    })
}

/// `finalize_cleanup`: `{errtype = "nmap.new_try", message = ...}`, raised.
fn try_error<'gc>(ctx: Context<'gc>, message: Value<'gc>) -> Error<'gc> {
    let t = Table::new(&ctx);
    t.set_field(ctx, "errtype", "nmap.new_try");
    t.set_field(ctx, "message", message);
    Error::from(Value::Table(t))
}

/// Raises the try error once the handler has run.
#[derive(Collect)]
#[collect(no_drop)]
struct TryCleanup<'gc> {
    message: Value<'gc>,
}

impl<'gc> Sequence<'gc> for TryCleanup<'gc> {
    fn poll(
        self: Pin<&mut Self>,
        ctx: Context<'gc>,
        _exec: Execution<'gc, '_>,
        _stack: Stack<'gc, '_>,
    ) -> Result<SequencePoll<'gc>, Error<'gc>> {
        Err(try_error(ctx, self.message))
    }
}

#[cfg(test)]
mod tests {
    //! What the loopback differential cannot reach — OS results, traceroute,
    //! MAC addresses, a host from an earlier group, the post-scan phase,
    //! interface listings — end to end through the VM. In-module so that Miri
    //! runs them; few VM start-ups, because they dominate under Miri.
    use super::*;
    use piccolo::{Closure, Executor, Lua};

    type Logs = Rc<RefCell<Vec<(LogTarget, Vec<u8>)>>>;

    fn env(logs: &Logs) -> NmapEnv {
        let logs = logs.clone();
        NmapEnv {
            verbose: 0,
            debugging: 3,
            timing_level: 3,
            version_intensity: 7,
            ttl: -1,
            data_length: -1,
            have_ssl: true,
            privileged: false,
            ipv6: false,
            interface: None,
            dns_servers: vec![],
            excluded_ports: Some(PortList {
                tcp: vec![9100],
                udp: vec![],
                sctp: vec![],
            }),
            services: None,
            phase: Phase::PostScan,
            interfaces: Ok(vec![
                Interface {
                    device: b"eth0".to_vec(),
                    shortname: b"eth0".to_vec(),
                    netmask_bits: 24,
                    address: "192.0.2.10".parse().unwrap(),
                    link: Link::Ethernet([2, 0, 0, 0, 0, 1]),
                    up: true,
                    mtu: 1500,
                },
                Interface {
                    device: b"tun0".to_vec(),
                    shortname: b"tun0".to_vec(),
                    netmask_bits: 32,
                    address: "198.51.100.1".parse().unwrap(),
                    link: Link::P2p,
                    up: false,
                    mtu: 1400,
                },
            ]),
            fetchfile: Box::new(|_| None),
            clock: Box::new(|| (0, 0)),
            random: Box::new(|_| false),
            log: Box::new(move |to, m| logs.borrow_mut().push((to, m.to_vec()))),
        }
    }

    fn full_host() -> ScriptHost {
        let mut h = ScriptHost::new("192.0.2.7".parse().unwrap());
        h.hostname = b"a.example".to_vec();
        h.targetname = Some(b"target.example".to_vec());
        h.reason = "arp-response";
        h.directly_connected = Some(false);
        h.mac = Some([0, 1, 2, 3, 4, 5]);
        h.src_mac = Some([6; 6]);
        h.source = Some("192.0.2.10".parse().unwrap());
        h.times = Times {
            srtt: 1500,
            rttvar: 250,
            timeout: 100_000,
        };
        h.traceroute = vec![
            TraceHop {
                timed_out: true,
                ip: None,
                name: None,
                rtt: 0.0,
            },
            TraceHop {
                timed_out: false,
                ip: Some("192.0.2.1".parse().unwrap()),
                name: Some(b"gw.example".to_vec()),
                rtt: 2.5,
            },
        ];
        h.os = Some(OsFacts {
            fingerprint: b"OS:SCAN(V=7.94)".to_vec(),
            success: true,
            perfect_matches: vec![b"Linux 5.x".to_vec(), b"Linux 6.x".to_vec()],
            classes: vec![OsClass {
                vendor: Some(b"Linux".to_vec()),
                osfamily: Some(b"Linux".to_vec()),
                osgen: None,
                device_type: Some(b"general purpose".to_vec()),
                cpe: vec![b"cpe:/o:linux:linux_kernel".to_vec()],
            }],
        });
        h.ports.push(ScriptPort {
            number: 9100,
            protocol: Protocol::Tcp,
            state: PortState::Closed,
            reason: "reset",
            reason_ttl: 64,
            service: None,
        });
        h
    }

    /// Run `src` with `host` bound to host 0's table; its results as strings.
    fn run(lib: &Shared, src: &str) -> Vec<String> {
        let mut lua = Lua::core();
        let ex = lua.enter(|ctx| {
            crate::nse::stdlib::load_tail(ctx).unwrap();
            crate::nse::stdlib::load_format(ctx).unwrap();
            load_nmap(ctx, lib, &ArgTable::default());
            let host = host_table(ctx, lib, 0);
            ctx.set_global("host", host);
            let f = Closure::load(ctx, None, src.as_bytes()).unwrap();
            ctx.stash(Executor::start(ctx, f.into(), ()))
        });
        lua.finish(&ex).unwrap();
        lua.enter(|ctx| {
            let vs = ctx
                .fetch(&ex)
                .take_result::<piccolo::Variadic<Vec<Value>>>(ctx)
                .unwrap()
                .unwrap();
            vs.0.into_iter().map(|v| v.display().to_string()).collect()
        })
    }

    #[test]
    fn the_host_table_carries_every_fact() {
        let logs: Logs = Rc::default();
        let lib = NmapLib::new(env(&logs));
        lib.borrow_mut().set_hosts(vec![full_host()]);
        let got = run(
            &lib,
            r#"
            local os = host.os
            return host.name, host.targetname, host.reason, tostring(host.directly_connected),
                   #host.mac_addr, host.mac_addr_next_hop == nil, #host.bin_ip_src,
                   host.times.srtt, host.times.timeout,
                   #host.traceroute, next(host.traceroute[1]) == nil,
                   host.traceroute[2].ip, host.traceroute[2].name, host.traceroute[2].srtt,
                   host.os_fp, #os, os[2].name, os[2].classes[1].type, os[2].classes[1].osgen == nil,
                   os[1].classes[1].cpe[1]
            "#,
        );
        assert_eq!(
            got,
            [
                "a.example",
                "target.example",
                "arp-response",
                "false",
                "6",
                "true",
                "4",
                "0.0015",
                "0.1",
                "2",
                "true",
                "192.0.2.1",
                "gw.example",
                "0.0025",
                "OS:SCAN(V=7.94)",
                "2",
                "Linux 6.x",
                "general purpose",
                "true",
                "cpe:/o:linux:linux_kernel",
            ]
        );

        // Nine perfect matches, or a scan that did not succeed: the
        // fingerprint without the list.
        let mut h = full_host();
        h.os.as_mut().unwrap().perfect_matches = vec![b"x".to_vec(); 9];
        let mut h2 = full_host();
        h2.os.as_mut().unwrap().success = false;
        h2.ip = "192.0.2.8".parse().unwrap();
        h2.targetname = None;
        lib.borrow_mut().set_hosts(vec![h, h2]);
        let got = run(
            &lib,
            r#"
            local h2 = { ip = "192.0.2.8" }
            return host.os == nil, host.os_fp,
                   nmap.get_port_state(h2, { number = 9100, protocol = "tcp" }).state,
                   nmap.get_port_state({ targetname = "target.example" }, { number = 9100, protocol = "tcp" }).reason
            "#,
        );
        assert_eq!(got, ["true", "OS:SCAN(V=7.94)", "closed", "reset"]);
    }

    #[test]
    fn a_host_from_an_earlier_group_is_not_this_one() {
        let logs: Logs = Rc::default();
        let lib = NmapLib::new(env(&logs));
        lib.borrow_mut().set_hosts(vec![full_host()]);
        let mut lua = Lua::core();
        lua.enter(|ctx| {
            load_nmap(ctx, &lib, &ArgTable::default());
            ctx.set_global("host", host_table(ctx, &lib, 0));
        });
        // A new group without that host: the old table's token no longer
        // names anything, and its address is not being processed.
        let mut other = full_host();
        other.ip = "203.0.113.9".parse().unwrap();
        other.targetname = None;
        lib.borrow_mut().set_hosts(vec![other]);
        let ex = lua.enter(|ctx| {
            let f = Closure::load(
                ctx,
                None,
                &b"return pcall(nmap.get_port_state, host, { number = 9100, protocol = 'tcp' })"[..],
            )
            .unwrap();
            ctx.stash(Executor::start(ctx, f.into(), ()))
        });
        lua.finish(&ex).unwrap();
        let got = lua.enter(|ctx| {
            let (ok, msg) = ctx
                .fetch(&ex)
                .take_result::<(bool, piccolo::String)>(ctx)
                .unwrap()
                .unwrap();
            (ok, msg.to_str().unwrap().to_owned())
        });
        assert_eq!(
            got,
            (
                false,
                "bad argument #1 to 'get_port_state' (host is not being processed right now)"
                    .to_owned()
            )
        );
    }

    #[test]
    fn post_scan_targets_interfaces_exclusions_and_the_intensity_cache() {
        let logs: Logs = Rc::default();
        let lib = NmapLib::new(env(&logs));
        lib.borrow_mut().set_hosts(vec![full_host()]);
        let got = run(
            &lib,
            r#"
            local a, b = nmap.add_targets("192.0.2.99")
            local ifs = nmap.list_interfaces()
            nmap.registry.args["script-intensity"] = "4"
            local i1 = nmap.version_intensity()
            nmap.registry.args["script-intensity"] = "2"
            local i2 = nmap.version_intensity()
            nmap.set_port_state(host, { number = 9100, protocol = "tcp" }, "open")
            return a, b, nmap.add_targets(""), #ifs, ifs[1].link, ifs[1].broadcast, ifs[1].mac:byte(6),
                   ifs[2].link, ifs[2].up, ifs[2].broadcast == nil,
                   nmap.port_is_excluded(9100, "tcp"), i1, i2
            "#,
        );
        assert_eq!(
            got,
            [
                "0",
                "failed to add new targets.",
                "0",
                "2",
                "ethernet",
                "192.0.2.255",
                "1",
                "p2p",
                "down",
                "true",
                "true",
                "4",
                "4",
            ]
        );
        let lines: Vec<(LogTarget, String)> = logs
            .borrow()
            .iter()
            .map(|(t, m)| (*t, String::from_utf8_lossy(m).into_owned()))
            .collect();
        assert_eq!(
            lines,
            [
                (
                    LogTarget::Error,
                    "ERROR: adding targets is disabled in the Post-scanning phase.\n".to_owned()
                ),
                (
                    LogTarget::Stdout,
                    "Discovered open port 9100/tcp on 192.0.2.7\n".to_owned()
                ),
                (LogTarget::Plain, "EXCLUDING 9100/tcp\n".to_owned()),
            ]
        );
        // Without interfaces: `nseU_safeerror`.
        let lib2 = NmapLib::new(NmapEnv {
            interfaces: Err(b"no interfaces".to_vec()),
            ..env(&logs)
        });
        lib2.borrow_mut().set_hosts(vec![full_host()]);
        assert_eq!(
            run(&lib2, "return nmap.list_interfaces()"),
            ["false", "no interfaces"]
        );
    }

    #[test]
    fn sanitize_is_cstring_sanity_check() {
        assert_eq!(sanitize(b"ab\x01\x7f\xffc", 80), b"ab...c");
        assert_eq!(sanitize(b"abcdef", 3), b"abc");
        assert_eq!(sanitize(b"ab\0cd", 80), b"ab");
        assert_eq!(sanitize(b"", 80), b"");
    }
}
