//! NSE's network I/O (M6.4d): `nse_nsock.cc`'s sockets and `nmap.resolve`,
//! over a host that does the I/O ([`ScriptNet`]).
//!
//! # How a script waits
//!
//! In nmap, a socket call starts an nsock operation and yields the script's
//! thread with `nse_yield`; nsock's loop, run by the scheduler between
//! passes (`loop(50)`), completes it and `nse_restore` hands the results back
//! through the engine's `WAITING_TO_RUNNING`. Here the same happens with the
//! same pieces: the functions in this module check their arguments as the C
//! does and *start* an operation, returning its id; `prelude.lua`'s glue
//! yields the thread through the engine's own `_R[YIELD]`, and the
//! scheduler's `loop` collects completions from the host ([`ScriptNet::poll`])
//! and restores each waiting thread through `_R[WAITING_TO_RUNNING]` — the
//! verbatim scheduler sees exactly the yields and restores nsock produces.
//!
//! The host does the I/O: `sys::nsenet` over tokio. This crate does no I/O
//! of its own and stays free of `unsafe`.
//!
//! # What is not here yet
//!
//! SSL (`connect(..., "ssl")`, `reconnect_ssl`, `get_ssl_certificate`) needs
//! the `openssl` module, and answers as an nmap built without OpenSSL does.
//! Packet capture (`pcap_open`, `pcap_receive`) answers as a socket that
//! cannot be opened. `--script-trace` is not traced.

use std::cell::RefCell;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use gc_arena::Collect;
use piccolo::{Callback, CallbackReturn, Context, StashedTable, Table, UserData, Value};

use super::nmaplib::Fail;
use super::stdlib::{type_error, LuaArgs};

/// An operation the host was asked to carry out.
pub type OpId = u64;
/// A socket, as the host knows it.
pub type SockId = u64;

/// A socket's protocol.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetProto {
    Tcp,
    Udp,
}

/// The address family a name is resolved for (`AF_INET`, `AF_INET6`,
/// `AF_UNSPEC`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Family {
    Inet,
    Inet6,
    Unspec,
}

/// What a read waits for (`nsock_read`, `nsock_readlines`,
/// `nsock_readbytes`).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReadMode {
    /// Whatever arrives next.
    Any,
    /// At least this many newlines, or end of file or time-out after some
    /// data, which then succeeds with what came.
    Lines(u64),
    /// At least this many bytes, likewise.
    Bytes(u64),
}

/// How an operation failed: `nse_status2str`'s words.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NetStatus {
    Error,
    Timeout,
    Eof,
    Cancelled,
}

impl NetStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            NetStatus::Error => "ERROR",
            NetStatus::Timeout => "TIMEOUT",
            NetStatus::Eof => "EOF",
            NetStatus::Cancelled => "CANCELLED",
        }
    }
}

/// How an operation ended.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Completion {
    /// A connect, write or timer that succeeded.
    Done,
    /// A read that succeeded, with what was read.
    Data(Vec<u8>),
    /// A timer that ran out: the thread is restored with no values.
    Fired,
    /// A failure.
    Failed(NetStatus),
}

/// The network as a script sees it: nsock's operations, started now and
/// completed by [`ScriptNet::poll`].
pub trait ScriptNet {
    /// Connect `sock` (a fresh socket, from `local` when bound) to `remote`.
    fn connect(
        &mut self,
        op: OpId,
        sock: SockId,
        proto: NetProto,
        local: Option<SocketAddr>,
        remote: SocketAddr,
        timeout: Option<Duration>,
    );
    /// `nsock_setup_udp`: an unconnected UDP socket for `sendto` and
    /// `receive`; the OS's error text when it cannot be made.
    fn setup_udp(
        &mut self,
        sock: SockId,
        v6: bool,
        local: Option<SocketAddr>,
    ) -> Result<(), String>;
    fn write(&mut self, op: OpId, sock: SockId, data: Vec<u8>, timeout: Option<Duration>);
    fn sendto(
        &mut self,
        op: OpId,
        sock: SockId,
        to: SocketAddr,
        data: Vec<u8>,
        timeout: Option<Duration>,
    );
    fn read(&mut self, op: OpId, sock: SockId, mode: ReadMode, timeout: Option<Duration>);
    /// Close `sock`; its pending operations never complete
    /// (`NSOCK_PENDING_NOTIFY`, whose callbacks NSE ignores).
    fn close(&mut self, sock: SockId);
    /// A timer that completes after `after`.
    fn timer(&mut self, op: OpId, after: Duration);
    /// Cancel an operation that has not completed.
    fn cancel(&mut self, op: OpId);
    /// The socket's local and remote addresses.
    fn info(&self, sock: SockId) -> Option<(SocketAddr, SocketAddr)>;
    /// Complete what is ready, waiting at most `wait` for something to be.
    fn poll(&mut self, wait: Duration) -> Vec<(OpId, Completion)>;
    /// `getaddrinfo`: a name's addresses, or `gai_strerror`'s text.
    fn resolve(&mut self, name: &str, family: Family) -> Result<Vec<IpAddr>, String>;
}

/// A host with no network: every name fails to resolve, and nothing ever
/// completes. What tests that do no I/O run with.
#[derive(Debug, Default)]
pub struct NoNet;

impl ScriptNet for NoNet {
    fn connect(
        &mut self,
        _: OpId,
        _: SockId,
        _: NetProto,
        _: Option<SocketAddr>,
        _: SocketAddr,
        _: Option<Duration>,
    ) {
    }
    fn setup_udp(&mut self, _: SockId, _: bool, _: Option<SocketAddr>) -> Result<(), String> {
        Ok(())
    }
    fn write(&mut self, _: OpId, _: SockId, _: Vec<u8>, _: Option<Duration>) {}
    fn sendto(&mut self, _: OpId, _: SockId, _: SocketAddr, _: Vec<u8>, _: Option<Duration>) {}
    fn read(&mut self, _: OpId, _: SockId, _: ReadMode, _: Option<Duration>) {}
    fn close(&mut self, _: SockId) {}
    fn timer(&mut self, _: OpId, _: Duration) {}
    fn cancel(&mut self, _: OpId) {}
    fn info(&self, _: SockId) -> Option<(SocketAddr, SocketAddr)> {
        None
    }
    fn poll(&mut self, _: Duration) -> Vec<(OpId, Completion)> {
        Vec::new()
    }
    fn resolve(&mut self, _: &str, _: Family) -> Result<Vec<IpAddr>, String> {
        Err("Name or service not known".into())
    }
}

/// The host, shared by the functions here.
pub type SharedNet = Rc<RefCell<dyn ScriptNet>>;

/// `DEFAULT_TIMEOUT`, in milliseconds.
const DEFAULT_TIMEOUT: i32 = 30_000;

/// What `nse_nsock_udata` keeps of a socket.
#[derive(Debug)]
struct SockState {
    open: bool,
    proto: NetProto,
    v6: bool,
    /// Milliseconds; -1 for none.
    timeout: i32,
    bound: Option<SocketAddr>,
    /// `receive_buf`'s buffer (`BUFFER_I`).
    buffer: Vec<u8>,
}

/// The socket userdata.
struct Socket {
    id: SockId,
    state: RefCell<SockState>,
}

impl Socket {
    /// `initialize`: a socket as `new` makes it and `close` leaves it.
    fn reset(&self, proto: NetProto, v6: bool) {
        *self.state.borrow_mut() = SockState {
            open: false,
            proto,
            v6,
            timeout: DEFAULT_TIMEOUT,
            bound: None,
            buffer: Vec::new(),
        };
    }

    fn timeout(&self) -> Option<Duration> {
        let t = self.state.borrow().timeout;
        u64::try_from(t).ok().map(Duration::from_millis)
    }
}

/// What the `net` functions share.
pub(crate) struct NetLib {
    host: SharedNet,
    next_op: OpId,
    next_sock: SockId,
    /// `o.af() == AF_INET6`.
    ipv6: bool,
    /// The socket metatable the glue made.
    meta: Option<StashedTable>,
}

#[derive(Collect)]
#[collect(require_static)]
struct NetHandle(Rc<RefCell<NetLib>>);

type Body = for<'gc, 'a> fn(
    &Rc<RefCell<NetLib>>,
    Context<'gc>,
    &mut piccolo::Stack<'gc, 'a>,
) -> Result<(), Fail>;

fn install<'gc>(
    ctx: Context<'gc>,
    t: Table<'gc>,
    lib: &Rc<RefCell<NetLib>>,
    name: &'static str,
    shown: &'static str,
    body: Body,
) {
    t.set_field(
        ctx,
        name,
        Callback::from_fn_with(
            &ctx,
            NetHandle(lib.clone()),
            move |h, ctx, _, mut stack| match body(&h.0, ctx, &mut stack) {
                Ok(()) => Ok(CallbackReturn::Return),
                Err(e) => Err(e.raise(ctx, shown)),
            },
        ),
    );
}

/// The `net` table the glue is built on, and `nmap.resolve`, installed in
/// `nmap`.
pub(crate) fn load_net<'gc>(
    ctx: Context<'gc>,
    host: SharedNet,
    ipv6: bool,
    max_parallelism: i64,
    nmap: Table<'gc>,
) -> Table<'gc> {
    let lib = Rc::new(RefCell::new(NetLib {
        host,
        next_op: 1,
        next_sock: 1,
        ipv6,
        meta: None,
    }));
    let t = Table::new(&ctx);
    // Functions that are methods of a socket are named `?`, as PUC-Lua names
    // a function it cannot find a name for (see `stdlib-bad-argument-naming`).
    let fns: [(&'static str, &'static str, Body); 17] = [
        ("set_meta", "?", l_set_meta),
        ("new", "nmap.new_socket", l_new),
        ("check", "?", l_check),
        ("connect_args", "?", l_connect_args),
        ("connect", "?", l_connect),
        ("send", "?", l_send),
        ("sendto", "?", l_sendto),
        ("receive", "?", l_receive),
        ("close", "?", l_close),
        ("get_info", "?", l_get_info),
        ("set_timeout", "?", l_set_timeout),
        ("bind", "?", l_bind),
        ("sleep", "?", l_sleep),
        ("cancel", "?", l_cancel),
        ("poll", "?", l_poll),
        ("buffer", "?", l_buffer),
        ("set_buffer", "?", l_set_buffer),
    ];
    for (name, shown, body) in fns {
        install(ctx, t, &lib, name, shown, body);
    }
    install(ctx, t, &lib, "is_open", "?", l_is_open);
    install(ctx, t, &lib, "release", "?", l_release);
    install(ctx, nmap, &lib, "resolve", "nmap.resolve", l_resolve);
    t.set_field(ctx, "max_parallelism", Value::Integer(max_parallelism));
    t
}

fn args<'s, 'gc, 'a>(ctx: Context<'gc>, s: &'s piccolo::Stack<'gc, 'a>) -> LuaArgs<'s, 'gc, 'a> {
    LuaArgs { ctx, stack: s }
}

/// `luaL_checkoption`.
fn check_option(
    a: &LuaArgs<'_, '_, '_>,
    n: usize,
    def: Option<&str>,
    opts: &[&str],
) -> Result<usize, Fail> {
    let name: Vec<u8> = match (a.get(n), def) {
        (None | Some(Value::Nil), Some(d)) => d.as_bytes().to_vec(),
        _ => a.string(n)?.into_owned(),
    };
    match opts.iter().position(|o| o.as_bytes() == name.as_slice()) {
        Some(i) => Ok(i),
        None => {
            let mut m = b"invalid option '".to_vec();
            m.extend_from_slice(&name);
            m.push(b'\'');
            Err(Fail::arg(n, m))
        }
    }
}

/// The socket at argument `n` (`nseU_checkudata(L, n, NSOCK_SOCKET, "nsock")`).
fn socket<'gc>(a: &LuaArgs<'_, 'gc, '_>, n: usize) -> Result<&'gc Socket, Fail> {
    match a.get(n) {
        Some(Value::UserData(u)) => u
            .downcast_static::<Socket>()
            .map_err(|_| type_error(a.ctx, Some(Value::UserData(u)), n, "nsock").into()),
        v => Err(type_error(a.ctx, v, n, "nsock").into()),
    }
}

fn op_id(lib: &Rc<RefCell<NetLib>>) -> OpId {
    let mut l = lib.borrow_mut();
    let id = l.next_op;
    l.next_op = l.next_op.wrapping_add(1);
    id
}

fn op_value<'gc>(op: OpId) -> Value<'gc> {
    Value::Integer(i64::try_from(op).unwrap_or(i64::MAX))
}

/// `nseU_safeerror`: `false` and a message.
fn safe_error<'gc>(ctx: Context<'gc>, s: &mut piccolo::Stack<'gc, '_>, msg: &str) {
    s.replace(ctx, (false, ctx.intern(msg.as_bytes())));
}

fn l_set_meta<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let Some(Value::Table(t)) = args(ctx, s).get(1) else {
        return Err(Fail::err("set_meta: table expected"));
    };
    lib.borrow_mut().meta = Some(ctx.stash(t));
    s.clear();
    Ok(())
}

/// `nmap.new_socket([proto [, af]])`.
fn l_new<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let proto = [NetProto::Tcp, NetProto::Udp][check_option(&a, 1, Some("tcp"), &["tcp", "udp"])?];
    let default_af = if lib.borrow().ipv6 { "inet6" } else { "inet" };
    let v6 = check_option(&a, 2, Some(default_af), &["inet", "inet6"])? == 1;
    let id = {
        let mut l = lib.borrow_mut();
        let id = l.next_sock;
        l.next_sock = l.next_sock.wrapping_add(1);
        id
    };
    let sock = Socket {
        id,
        state: RefCell::new(SockState {
            open: false,
            proto,
            v6,
            timeout: DEFAULT_TIMEOUT,
            bound: None,
            buffer: Vec::new(),
        }),
    };
    let u = UserData::new_static(&ctx, sock);
    if let Some(meta) = &lib.borrow().meta {
        u.set_metatable(&ctx, Some(ctx.fetch(meta)));
    }
    s.replace(ctx, u);
    Ok(())
}

/// `check_nsock_udata(L, 1, open)` and, when `open`,
/// `NSOCK_UDATA_ENSURE_OPEN`: an unconnected UDP socket is set up for
/// `sendto` and `receive` on the way.
fn check_open(lib: &Rc<RefCell<NetLib>>, sock: &Socket) -> Result<(), Fail> {
    let (open, proto, v6, bound) = {
        let st = sock.state.borrow();
        (st.open, st.proto, st.v6, st.bound)
    };
    if !open && proto == NetProto::Udp {
        let host = lib.borrow().host.clone();
        let r = host.borrow_mut().setup_udp(sock.id, v6, bound);
        if let Err(e) = r {
            return Err(Fail::err(format!(
                "Error in setup of iod with proto {} and af {}: {e}",
                17,
                if v6 { 10 } else { 2 }
            )));
        }
        sock.state.borrow_mut().open = true;
    }
    if !sock.state.borrow().open {
        return Err(Fail::err("socket must be connected"));
    }
    Ok(())
}

/// The glue's `check(sock, open)`.
fn l_check<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    if a.get(2).is_some_and(|v| v.to_bool()) {
        check_open(lib, sock)?;
    }
    s.clear();
    Ok(())
}

fn l_is_open<'gc>(
    _: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let open = socket(&args(ctx, s), 1)?.state.borrow().open;
    s.replace(ctx, open);
    Ok(())
}

/// `lua_tostring`: a string, or a number's text; `None` otherwise.
fn lua_text<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<Vec<u8>> {
    match v {
        Value::String(s) => Some(s.as_bytes().to_vec()),
        v @ (Value::Integer(_) | Value::Number(_)) => {
            v.into_string(ctx).map(|s| s.as_bytes().to_vec())
        }
        _ => None,
    }
}

/// `nseU_checktarget`: the address to connect to, from a host table or a
/// string.
fn check_target(a: &LuaArgs<'_, '_, '_>, n: usize) -> Result<Vec<u8>, Fail> {
    match a.get(n) {
        Some(Value::Table(t)) => {
            let ip = lua_text(a.ctx, t.get_value(a.ctx, "ip"));
            let name = lua_text(a.ctx, t.get_value(a.ctx, "targetname"));
            ip.or(name)
                .ok_or_else(|| Fail::arg(n, "host table lacks 'ip' or 'targetname' fields"))
        }
        _ => Ok(a.string(n)?.into_owned()),
    }
}

/// `nseU_checkport`: the port, from a port table or a number, as a
/// `uint16_t` (the C truncates, and so does this), and the table's
/// protocol, if it named one.
fn check_port(a: &LuaArgs<'_, '_, '_>, n: usize) -> Result<(u16, Option<Vec<u8>>), Fail> {
    match a.get(n) {
        Some(Value::Table(t)) => {
            let Value::Integer(number) = t.get_value(a.ctx, "number") else {
                return Err(Fail::arg(n, "port table lacks integer 'number' field"));
            };
            let proto = lua_text(a.ctx, t.get_value(a.ctx, "protocol"));
            Ok((truncate_u16(number), proto))
        }
        _ => Ok((truncate_u16(a.check_integer(n)?), None)),
    }
}

/// `(uint16_t)`.
fn truncate_u16(n: i64) -> u16 {
    n.to_le_bytes()[..2]
        .iter()
        .rev()
        .fold(0u16, |acc, &b| (acc << 8) | u16::from(b))
}

/// The connect's protocol option (`luaL_checkoption(L, 4, default, op)`):
/// 0 tcp, 1 udp, 2 ssl.
fn connect_option(sock: &Socket, a: &LuaArgs<'_, '_, '_>) -> Result<(u16, Vec<u8>, usize), Fail> {
    let host = check_target(a, 2)?;
    let (port, table_proto) = check_port(a, 3)?;
    let default = match table_proto {
        Some(p) => String::from_utf8_lossy(&p).into_owned(),
        None => match sock.state.borrow().proto {
            NetProto::Tcp => "tcp".into(),
            NetProto::Udp => "udp".into(),
        },
    };
    let what = check_option(a, 4, Some(&default), &["tcp", "udp", "ssl"])?;
    Ok((port, host, what))
}

/// The glue's `connect_args(sock, host, port [, proto])`: the checks
/// `connect` makes before it takes a socket lock.
fn l_connect_args<'gc>(
    _: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    connect_option(sock, &a)?;
    s.clear();
    Ok(())
}

/// Parse a numeric address, as `getaddrinfo` with `AI_NUMERICHOST` does.
fn numeric(host: &str) -> Option<IpAddr> {
    host.parse::<IpAddr>().ok()
}

/// `getaddrinfo` as `connect` calls it: numeric first, then the name for the
/// scan's family.
fn resolve_for(lib: &Rc<RefCell<NetLib>>, host: &[u8], family: Family) -> Result<IpAddr, String> {
    let text = String::from_utf8_lossy(host).into_owned();
    if let Some(ip) = numeric(&text) {
        return Ok(ip);
    }
    let h = lib.borrow().host.clone();
    let r = h.borrow_mut().resolve(&text, family);
    match r {
        Ok(list) => list
            .into_iter()
            .next()
            .ok_or_else(|| "getaddrinfo returned success but no addresses".to_string()),
        Err(e) => Err(e),
    }
}

/// The glue's `connect(sock, host, port [, proto])`: resolve and start the
/// connection; the operation's id, or `false` and the resolver's error.
fn l_connect<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    let (port, host, what) = connect_option(sock, &a)?;
    if what == 2 {
        safe_error(ctx, s, "sorry, you don't have OpenSSL");
        return Ok(());
    }
    let family = if lib.borrow().ipv6 {
        Family::Inet6
    } else {
        Family::Inet
    };
    let ip = match resolve_for(lib, &host, family) {
        Ok(ip) => ip,
        Err(e) => {
            safe_error(ctx, s, &e);
            return Ok(());
        }
    };
    let host_net = lib.borrow().host.clone();
    if sock.state.borrow().open {
        host_net.borrow_mut().close(sock.id);
    }
    let proto = if what == 1 {
        NetProto::Udp
    } else {
        NetProto::Tcp
    };
    let op = op_id(lib);
    {
        let mut st = sock.state.borrow_mut();
        st.open = true;
        st.proto = proto;
        st.v6 = ip.is_ipv6();
    }
    let (bound, timeout) = (sock.state.borrow().bound, sock.timeout());
    host_net.borrow_mut().connect(
        op,
        sock.id,
        proto,
        bound,
        SocketAddr::new(ip, port),
        timeout,
    );
    s.replace(ctx, op_value(op));
    Ok(())
}

/// The glue's `send(sock, data)`.
fn l_send<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    check_open(lib, sock)?;
    let data = a.string(2)?.into_owned();
    let op = op_id(lib);
    let host = lib.borrow().host.clone();
    host.borrow_mut().write(op, sock.id, data, sock.timeout());
    s.replace(ctx, op_value(op));
    Ok(())
}

/// The glue's `sendto(sock, host, port, data)`.
fn l_sendto<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    check_open(lib, sock)?;
    let host = check_target(&a, 2)?;
    let (port, _) = check_port(&a, 3)?;
    let data = a.string(4)?.into_owned();
    let ip = match resolve_for(lib, &host, Family::Unspec) {
        Ok(ip) => ip,
        Err(e) => {
            safe_error(ctx, s, &e);
            return Ok(());
        }
    };
    let op = op_id(lib);
    let h = lib.borrow().host.clone();
    h.borrow_mut()
        .sendto(op, sock.id, SocketAddr::new(ip, port), data, sock.timeout());
    s.replace(ctx, op_value(op));
    Ok(())
}

/// The glue's `receive(sock, mode [, n])`: `receive`, `receive_lines` and
/// `receive_bytes`.
fn l_receive<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    check_open(lib, sock)?;
    let mode = match a.string(2)?.as_ref() {
        b"lines" => ReadMode::Lines(count(a.check_integer(3).map_err(|e| renumber(e, 2))?)),
        b"bytes" => ReadMode::Bytes(count(a.check_integer(3).map_err(|e| renumber(e, 2))?)),
        _ => ReadMode::Any,
    };
    let op = op_id(lib);
    let host = lib.borrow().host.clone();
    host.borrow_mut().read(op, sock.id, mode, sock.timeout());
    s.replace(ctx, op_value(op));
    Ok(())
}

/// The count a `receive_lines`/`receive_bytes` asks for: nsock takes an
/// `int`; anything at or below zero is satisfied by any data.
fn count(n: i64) -> u64 {
    u64::try_from(i64::from(truncate_i32(n))).unwrap_or(0)
}

/// `(int)`.
fn truncate_i32(n: i64) -> i32 {
    i32::from_le_bytes([
        n.to_le_bytes()[0],
        n.to_le_bytes()[1],
        n.to_le_bytes()[2],
        n.to_le_bytes()[3],
    ])
}

/// The glue passes the method's argument `n + 1` as its own argument `n + 1`
/// too, so a numbering mistake is the glue's; this keeps the C's numbers.
fn renumber(e: super::stdlib::strpack::PackError, n: usize) -> Fail {
    let mut f = Fail::from(e);
    f.set_arg(n);
    f
}

/// `close(sock)`.
fn l_close<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    let (open, proto, v6) = {
        let st = sock.state.borrow();
        (st.open, st.proto, st.v6)
    };
    if !open {
        safe_error(ctx, s, "socket already closed");
        return Ok(());
    }
    let host = lib.borrow().host.clone();
    host.borrow_mut().close(sock.id);
    sock.reset(proto, v6);
    s.replace(ctx, true);
    Ok(())
}

fn ip_text(ip: IpAddr) -> String {
    ip.to_string()
}

/// `get_info(sock)`: `true`, local address and port, remote address and port.
fn l_get_info<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    check_open(lib, sock)?;
    let host = lib.borrow().host.clone();
    let info = host.borrow().info(sock.id);
    let unspecified = if sock.state.borrow().v6 {
        SocketAddr::new(IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0)
    } else {
        SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
    };
    let (local, remote) = info.unwrap_or((unspecified, unspecified));
    s.replace(
        ctx,
        (
            true,
            ctx.intern(ip_text(local.ip()).as_bytes()),
            Value::Integer(i64::from(local.port())),
            ctx.intern(ip_text(remote.ip()).as_bytes()),
            Value::Integer(i64::from(remote.port())),
        ),
    );
    Ok(())
}

/// `nseU_checkinteger`: `floor` of a number, as a C `int`.
fn nse_check_integer(a: &LuaArgs<'_, '_, '_>, n: usize) -> Result<i32, Fail> {
    let v = match a.get(n) {
        Some(Value::Integer(i)) => return Ok(truncate_i32(i)),
        Some(Value::Number(f)) => f,
        Some(v @ Value::String(_)) => match v.to_number() {
            Some(f) => f,
            None => return Err(type_error(a.ctx, Some(v), n, "number").into()),
        },
        v => return Err(type_error(a.ctx, v, n, "number").into()),
    };
    let f = v.floor();
    // `lua_numbertointeger`'s range: [LUA_MININTEGER, -LUA_MININTEGER).
    #[allow(clippy::cast_precision_loss)]
    let ok = f >= i64::MIN as f64 && f < -(i64::MIN as f64);
    if !ok {
        return Err(Fail::err("Number cannot be converted to an integer"));
    }
    #[allow(clippy::cast_possible_truncation)] // in range, just checked
    Ok(truncate_i32(f as i64))
}

/// `set_timeout(sock, ms)`. The C formats a negative value with `%f` from an
/// `int` (undefined behaviour, printing garbage); here it is the value
/// (`nse-negative-timeout-message`).
fn l_set_timeout<'gc>(
    _: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    let t = nse_check_integer(&a, 2)?;
    if t < -1 {
        return Err(Fail::err(format!("Negative timeout: {}", f64::from(t))));
    }
    sock.state.borrow_mut().timeout = t;
    s.replace(ctx, true);
    Ok(())
}

/// `bind(sock [, address [, port]])`: numeric addresses only.
fn l_bind<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    let addr = match a.get(2) {
        None | Some(Value::Nil) => None,
        Some(_) => Some(a.string(2)?.into_owned()),
    };
    let port = a.check_integer(3)?;
    let ip = match &addr {
        None => {
            if lib.borrow().ipv6 {
                IpAddr::V6(Ipv6Addr::UNSPECIFIED)
            } else {
                IpAddr::V4(Ipv4Addr::UNSPECIFIED)
            }
        }
        Some(text) => match numeric(&String::from_utf8_lossy(text)) {
            Some(ip) => ip,
            None => {
                safe_error(ctx, s, "getaddrinfo: Name or service not known");
                return Ok(());
            }
        },
    };
    let Ok(port) = u16::try_from(port) else {
        safe_error(
            ctx,
            s,
            "getaddrinfo: Servname not supported for ai_socktype",
        );
        return Ok(());
    };
    sock.state.borrow_mut().bound = Some(SocketAddr::new(ip, port));
    s.replace(ctx, true);
    Ok(())
}

/// The glue's `sleep(secs)`: start the timer.
fn l_sleep<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let secs = match a.get(1) {
        Some(Value::Integer(i)) => {
            #[allow(clippy::cast_precision_loss)]
            let f = i as f64;
            f
        }
        Some(Value::Number(f)) => f,
        Some(v @ Value::String(_)) => v
            .to_number()
            .ok_or_else(|| Fail::from(type_error(ctx, Some(v), 1, "number")))?,
        v => return Err(type_error(ctx, v, 1, "number").into()),
    };
    if secs < 0.0 {
        let shown = Value::Number(secs).display().to_string();
        return Err(Fail::err(format!(
            "argument to sleep ({shown}) must not be negative\n"
        )));
    }
    // `(int) (secs * 1000 + 0.5)`; a sleep longer than an `int` of
    // milliseconds is the C's undefined behaviour, and here as long as asked.
    let ms = (secs * 1000.0 + 0.5).floor();
    let after = if ms.is_finite() && ms < 1.8e16 {
        #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)] // non-negative, bounded
        let ms = ms as u64;
        Duration::from_millis(ms)
    } else {
        Duration::MAX
    };
    let op = op_id(lib);
    let host = lib.borrow().host.clone();
    host.borrow_mut().timer(op, after);
    s.replace(ctx, op_value(op));
    Ok(())
}

fn l_cancel<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let op = args(ctx, s).check_integer(1)?;
    if let Ok(op) = u64::try_from(op) {
        let host = lib.borrow().host.clone();
        host.borrow_mut().cancel(op);
    }
    s.clear();
    Ok(())
}

/// The glue's `poll(ms)`: the completed operations, each
/// `{op, n = count, values...}` with the values the C's callbacks push:
/// `true` for a success, `true, data` for a read, `nil, status` for a
/// failure, nothing for a timer (`Fired`).
fn l_poll<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let ms = args(ctx, s).check_integer(1)?;
    let wait = Duration::from_millis(u64::try_from(ms).unwrap_or(0));
    let host = lib.borrow().host.clone();
    let done = host.borrow_mut().poll(wait);
    let list = Table::new(&ctx);
    for (i, (op, c)) in done.into_iter().enumerate() {
        let e = Table::new(&ctx);
        e.set_field(ctx, "op", op_value(op));
        let vals: Vec<Value<'gc>> = match c {
            Completion::Done => vec![Value::Boolean(true)],
            Completion::Fired => vec![],
            Completion::Data(d) => vec![Value::Boolean(true), Value::String(ctx.intern(&d))],
            Completion::Failed(st) => vec![
                Value::Nil,
                Value::String(ctx.intern(st.as_str().as_bytes())),
            ],
        };
        e.set_field(
            ctx,
            "n",
            Value::Integer(i64::try_from(vals.len()).unwrap_or(0)),
        );
        for (j, v) in vals.into_iter().enumerate() {
            let _ = e.set(ctx, i64::try_from(j).unwrap_or(0).saturating_add(1), v);
        }
        let _ = list.set(ctx, i64::try_from(i).unwrap_or(0).saturating_add(1), e);
    }
    s.replace(ctx, list);
    Ok(())
}

/// The glue's `buffer(sock)`: `receive_buf`'s buffer.
fn l_buffer<'gc>(
    _: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let sock = socket(&args(ctx, s), 1)?;
    let b = sock.state.borrow().buffer.clone();
    s.replace(ctx, ctx.intern(&b));
    Ok(())
}

fn l_set_buffer<'gc>(
    _: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let sock = socket(&a, 1)?;
    let b = a.string(2)?.into_owned();
    sock.state.borrow_mut().buffer = b;
    s.clear();
    Ok(())
}

/// The glue's `release(sock)`: after a connect completes, the socket may be
/// used by another thread (the C clears `nu->thread`). Nothing to do here;
/// the glue keeps the owner. Kept so the glue reads as the C does.
fn l_release<'gc>(
    _: &Rc<RefCell<NetLib>>,
    _: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    s.clear();
    Ok(())
}

/// `nmap.resolve(host [, family])`.
fn l_resolve<'gc>(
    lib: &Rc<RefCell<NetLib>>,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let host = a.string(1)?.into_owned();
    let family = [Family::Inet, Family::Inet6, Family::Unspec]
        [check_option(&a, 2, Some("unspec"), &["inet", "inet6", "unspec"])?];
    let text = String::from_utf8_lossy(&host).into_owned();
    let found = match numeric(&text) {
        Some(ip) => Ok(vec![ip]),
        None => {
            let h = lib.borrow().host.clone();
            let r = h.borrow_mut().resolve(&text, family);
            r
        }
    };
    let list: Vec<IpAddr> = match found {
        Ok(l) => l
            .into_iter()
            .filter(|ip| match family {
                Family::Inet => ip.is_ipv4(),
                Family::Inet6 => ip.is_ipv6(),
                Family::Unspec => true,
            })
            .collect(),
        Err(_) => Vec::new(),
    };
    // `resolve_all` returns nothing when no address of the family exists, so
    // a numeric address of the other family fails as a name would.
    if list.is_empty() {
        safe_error(ctx, s, "Failed to resolve");
        return Ok(());
    }
    let t = Table::new(&ctx);
    for (i, ip) in list.iter().enumerate() {
        let _ = t.set(
            ctx,
            i64::try_from(i).unwrap_or(0).saturating_add(1),
            ctx.intern(ip.to_string().as_bytes()),
        );
    }
    s.replace(ctx, (true, t));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn truncations_are_the_cs() {
        assert_eq!(truncate_u16(70000), 4464);
        assert_eq!(truncate_u16(-1), 65535);
        assert_eq!(truncate_i32(1 << 32), 0);
        assert_eq!(truncate_i32(-2), -2);
        assert_eq!(count(-5), 0);
        assert_eq!(count(3), 3);
    }

    #[test]
    fn statuses_are_nsocks_words() {
        assert_eq!(NetStatus::Timeout.as_str(), "TIMEOUT");
        assert_eq!(NetStatus::Eof.as_str(), "EOF");
    }
}
