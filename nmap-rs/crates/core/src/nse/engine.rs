//! The half of NSE's engine that nmap writes in C, under the half it writes in
//! Lua: `nse_main.cc`'s `cnse` library, its store of script results, and its
//! `script_scan`, which runs one phase of a scan through `nse_main.lua`'s
//! `main`.
//!
//! The Lua half runs as nmap's own code (`prelude.lua`, copied block by block
//! from `nse_main.lua`): `Script.new`, the threads, the scheduler `run`, and
//! `format_table`/`format_xml`. This module gives it what `nse_main.cc` gives
//! it, and drives it:
//!
//! - **`cnse`**: the host's ports for portrules, the setters that store a
//!   script's result against the run, a host or a port, and the XML writer
//!   `format_xml` writes through.
//! - **A phase** ([`NseState::run_phase`]): the hosts become host tables and
//!   `main(hosts, phase)` runs to completion. The VM is stepped in slices, so
//!   the host can bound the work a phase may do ([`Budget`]); nmap has no
//!   such bound.
//! - **Results**: rendered as soon as the phase ends, as nmap prints them
//!   when it ends, into [`ScriptOutput`]s for [`super::results`] to print.
//!
//! Hosts with a `--host-timeout` (`timedOut`, `startTimeOutClock`) do not
//! exist yet: the option is refused on the command line (M7.3), so no host
//! times out.

use std::cell::RefCell;
use std::rc::Rc;

use gc_arena::Collect;
use piccolo::{
    Callback, CallbackReturn, Context, Executor, Fuel, Lua, StashedExecutor, StashedValue, Table,
    Value,
};

use super::nmaplib::{get_port, get_target, port_table, Fail, Phase, ScriptHost, Shared};
use super::results::{protect_xml, xml_escape, ScriptOutput};
use super::stdlib::LuaArgs;
use crate::model::{PortState, Protocol};

/// Where a result is kept: `script_scan_results` (pre- and post-scan), a
/// host's `scriptResults`, or a port's.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Container {
    Run,
    Host(usize),
    Port(usize, usize),
}

/// A stored result before it is rendered: `ScriptResult::set_output_tab`'s
/// `{id, tab, str}`.
struct Stored {
    container: Container,
    id: Vec<u8>,
    tab: Option<StashedValue>,
    str: Option<StashedValue>,
}

/// The XML writer `format_xml` writes through (`xml.cc`, restricted to what
/// `cnse` exposes: start tags, end tags, escaped text, newlines).
#[derive(Default)]
struct XmlWriter {
    out: Vec<u8>,
    open: Vec<Vec<u8>>,
}

/// What the `cnse` functions share with the driver.
#[derive(Default)]
pub(crate) struct Store {
    stored: Vec<Stored>,
    /// For each stored result, once rendered: its text and its table's XML.
    rendered: Vec<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>>,
    xml: XmlWriter,
}

#[derive(Collect)]
#[collect(require_static)]
struct Cnse {
    lib: Shared,
    store: Rc<RefCell<Store>>,
}

type CnseBody = for<'gc, 'a> fn(
    &Cnse,
    Context<'gc>,
    &mut piccolo::Stack<'gc, 'a>,
) -> Result<(), Fail>;

fn install<'gc>(ctx: Context<'gc>, t: Table<'gc>, c: &Rc<Cnse>, name: &'static str, body: CnseBody) {
    let c = Rc::clone(c);
    t.set_field(
        ctx,
        name,
        Callback::from_fn(&ctx, move |ctx, _, mut stack| {
            match body(&c, ctx, &mut stack) {
                Ok(()) => Ok(CallbackReturn::Return),
                Err(e) => Err(e.raise(ctx, name)),
            }
        }),
    );
}

/// The run's settings `open_cnse` copies out of `NmapOps`.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct EngineOptions {
    /// `--script-timeout`, in seconds; 0 for none.
    pub script_timeout: f64,
    /// `--min-parallelism`, which raises the engine's limit on concurrent
    /// script threads (1,000) when it is higher.
    pub min_parallelism: i64,
}

impl Default for EngineOptions {
    fn default() -> Self {
        Self {
            script_timeout: 0.0,
            min_parallelism: 0,
        }
    }
}

/// `open_cnse`: the table `nse_main.lua` is called with.
pub(crate) fn load_cnse<'gc>(
    ctx: Context<'gc>,
    lib: &Shared,
    store: &Rc<RefCell<Store>>,
    options: EngineOptions,
) -> Table<'gc> {
    let c = Rc::new(Cnse {
        lib: lib.clone(),
        store: store.clone(),
    });
    let t = Table::new(&ctx);
    let fns: [(&'static str, CnseBody); 16] = [
        ("timedOut", l_timed_out),
        ("startTimeOutClock", l_check_target),
        ("stopTimeOutClock", l_check_target),
        ("ports", l_ports),
        ("script_set_output", l_script_set_output),
        ("host_set_output", l_host_set_output),
        ("port_set_output", l_port_set_output),
        ("key_was_pressed", l_key_was_pressed),
        ("scan_progress_meter", l_scan_progress_meter),
        ("xml_start_tag", l_xml_start_tag),
        ("xml_end_tag", l_xml_end_tag),
        ("xml_write_escaped", l_xml_write_escaped),
        ("xml_newline", l_xml_newline),
        ("protect_xml", l_protect_xml),
        ("xml_begin", l_xml_begin),
        ("xml_end", l_xml_end),
    ];
    for (name, body) in fns {
        install(ctx, t, &c, name, body);
    }
    install(ctx, t, &c, "rendered", l_rendered);
    t.set_field(ctx, "script_timeout", Value::Number(options.script_timeout));
    t.set_field(ctx, "min_parallelism", Value::Integer(options.min_parallelism));
    t
}

fn args<'s, 'gc, 'a>(ctx: Context<'gc>, s: &'s piccolo::Stack<'gc, 'a>) -> LuaArgs<'s, 'gc, 'a> {
    LuaArgs { ctx, stack: s }
}

/// `timedOut(host)`: whether the host's `--host-timeout` has passed; never,
/// here (see the module documentation).
fn l_timed_out<'gc>(c: &Cnse, ctx: Context<'gc>, s: &mut piccolo::Stack<'gc, '_>) -> Result<(), Fail> {
    get_target(&c.lib.borrow(), &args(ctx, s), 1)?;
    s.replace(ctx, false);
    Ok(())
}

/// `startTimeOutClock(host)`, `stopTimeOutClock(host)`: the host is checked,
/// and there is no clock to run.
fn l_check_target<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    get_target(&c.lib.borrow(), &args(ctx, s), 1)?;
    s.clear();
    Ok(())
}

/// The states whose ports portrules see, in `ports`' order.
const RULE_STATES: [PortState; 3] = [PortState::Open, PortState::OpenFiltered, PortState::Unfiltered];
const PROTOCOLS: [Protocol; 3] = [Protocol::Tcp, Protocol::Udp, Protocol::Sctp];

/// `ports(host)`: an iterator over the port tables of the host's open,
/// open|filtered and unfiltered ports, in that order of state, then by
/// protocol and number (see `nse-portrule-order`).
fn l_ports<'gc>(c: &Cnse, ctx: Context<'gc>, s: &mut piccolo::Stack<'gc, '_>) -> Result<(), Fail> {
    let lib = c.lib.borrow();
    let host = get_target(&lib, &args(ctx, s), 1)?;
    let h = &lib.hosts()[host];
    let list = Table::new(&ctx);
    let mut n: i64 = 0;
    for state in RULE_STATES {
        for proto in PROTOCOLS {
            let mut ports: Vec<_> = h
                .ports
                .iter()
                .filter(|p| p.state == state && p.protocol == proto)
                .collect();
            ports.sort_by_key(|p| p.number);
            for p in ports {
                n = n.saturating_add(1);
                list.set(ctx, n, port_table(ctx, &lib.env, p))
                    .map_err(|_| Fail::err("ports: table"))?;
            }
        }
    }
    let at = Table::new(&ctx);
    let iter = Callback::from_fn_with(&ctx, (list, at), |&(list, at), ctx, _, mut stack| {
        let i = match at.get_value(ctx, 1) {
            Value::Integer(i) => i,
            _ => 0,
        }
        .saturating_add(1);
        at.set(ctx, 1, i)?;
        stack.replace(ctx, list.get_value(ctx, i));
        Ok(CallbackReturn::Return)
    });
    s.replace(ctx, (iter, Value::Nil, Value::Nil));
    Ok(())
}

/// `ScriptResult::set_output_tab(L, base)`: the id and the two outputs at
/// `base`, checked as the C checks them, stored against `container`.
fn store_result<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &piccolo::Stack<'gc, '_>,
    base: usize,
    container: Container,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let id = a.string(base)?.into_owned();
    let tab = a.get(base.saturating_add(1)).unwrap_or(Value::Nil);
    let str = a.get(base.saturating_add(2)).unwrap_or(Value::Nil);
    if !matches!(str, Value::Nil | Value::String(_) | Value::Integer(_) | Value::Number(_)) {
        return Err(Fail::err("String output is not a string"));
    }
    let keep = |v: Value<'gc>| (!v.is_nil()).then(|| ctx.stash(v));
    c.store.borrow_mut().stored.push(Stored {
        container,
        id,
        tab: keep(tab),
        str: keep(str),
    });
    Ok(())
}

/// `script_set_output(id, tab, str)`: a pre- or post-scan result.
fn l_script_set_output<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    store_result(c, ctx, s, 1, Container::Run)?;
    s.clear();
    Ok(())
}

/// `host_set_output(host, id, tab, str)`.
fn l_host_set_output<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let host = get_target(&c.lib.borrow(), &args(ctx, s), 1)?;
    store_result(c, ctx, s, 2, Container::Host(host))?;
    s.clear();
    Ok(())
}

/// `port_set_output(host, port, id, tab, str)`. The C dereferences the port
/// it looks up without checking that it found one, so a port table the
/// script changed (through `stdnse.gethostport`) crashes nmap; here it is
/// an error (`nse-port-output-on-unknown-port`).
fn l_port_set_output<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let (host, port) = {
        let lib = c.lib.borrow();
        let a = args(ctx, s);
        let host = get_target(&lib, &a, 1)?;
        (host, get_port(&lib, host, &a, 2)?)
    };
    let Some(port) = port else {
        return Err(Fail::err("port_set_output: no such port on the host"));
    };
    store_result(c, ctx, s, 3, Container::Port(host, port))?;
    s.clear();
    Ok(())
}

/// `key_was_pressed()`: nmap's runtime-interaction keys; none here.
fn l_key_was_pressed<'gc>(
    _: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    s.replace(ctx, false);
    Ok(())
}

/// `scan_progress_meter(name)`: the closure the scheduler reports progress
/// through. It checks its operation as `scp` does, and prints nothing: the
/// progress lines (`NSE Timing: About ...% done`) are not produced yet
/// (`nse-progress-meter-silent`).
fn l_scan_progress_meter<'gc>(
    _: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    args(ctx, s).string(1)?;
    let meter = Callback::from_fn(&ctx, |ctx, _, mut stack| {
        const OPS: [&[u8]; 4] = [b"printStats", b"printStatsIfNecessary", b"mayBePrinted", b"endTask"];
        let op = args(ctx, &stack)
            .string(1)
            .map_err(|e| Fail::from(e).raise(ctx, "?"))?
            .into_owned();
        let Some(i) = OPS.iter().position(|o| *o == op.as_slice()) else {
            let mut m = b"invalid option '".to_vec();
            m.extend_from_slice(&op);
            m.push(b'\'');
            return Err(Fail::arg(1, m).raise(ctx, "?"));
        };
        if i == 2 {
            stack.replace(ctx, false);
        } else {
            stack.clear();
        }
        Ok(CallbackReturn::Return)
    });
    s.replace(ctx, meter);
    Ok(())
}

/// `xml_start_tag(name [, attrs])`.
fn l_xml_start_tag<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let name = a.string(1)?.into_owned();
    let mut tag = vec![b'<'];
    tag.extend_from_slice(&name);
    match a.get(2) {
        None | Some(Value::Nil) => {}
        Some(Value::Table(attrs)) => {
            for (k, v) in attrs {
                let text = |v: Value<'gc>| match v {
                    Value::String(s) => Some(s.as_bytes().to_vec()),
                    v @ (Value::Integer(_) | Value::Number(_)) => {
                        v.into_string(ctx).map(|s| s.as_bytes().to_vec())
                    }
                    _ => None,
                };
                let (Some(k), Some(v)) = (text(k), text(v)) else {
                    return Err(Fail::err("xml_start_tag: attributes must be strings"));
                };
                super::results::attribute(&mut tag, &k, &v);
            }
        }
        Some(_) => return Err(Fail::err("xml_start_tag: attributes must be a table")),
    }
    tag.push(b'>');
    let mut store = c.store.borrow_mut();
    store.xml.out.extend_from_slice(&tag);
    store.xml.open.push(name);
    s.clear();
    Ok(())
}

/// `xml_end_tag()`.
fn l_xml_end_tag<'gc>(
    c: &Cnse,
    _: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let mut store = c.store.borrow_mut();
    let Some(name) = store.xml.open.pop() else {
        // The C asserts.
        return Err(Fail::err("xml_end_tag: no element is open"));
    };
    store.xml.out.extend_from_slice(b"</");
    store.xml.out.extend_from_slice(&name);
    store.xml.out.push(b'>');
    s.clear();
    Ok(())
}

/// `xml_write_escaped(text)`.
fn l_xml_write_escaped<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let text = args(ctx, s).string(1)?.into_owned();
    c.store.borrow_mut().xml.out.extend_from_slice(&xml_escape(&text));
    s.clear();
    Ok(())
}

/// `xml_newline()`.
fn l_xml_newline<'gc>(
    c: &Cnse,
    _: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    c.store.borrow_mut().xml.out.push(b'\n');
    s.clear();
    Ok(())
}

/// `protect_xml(text)`.
fn l_protect_xml<'gc>(
    _: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let text = args(ctx, s).string(1)?.into_owned();
    s.replace(ctx, ctx.intern(&protect_xml(&text)));
    Ok(())
}

/// The glue's `xml_begin()`: start capturing what `format_xml` writes.
fn l_xml_begin<'gc>(
    c: &Cnse,
    _: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    c.store.borrow_mut().xml = XmlWriter::default();
    s.clear();
    Ok(())
}

/// The glue's `xml_end()`: what was written since `xml_begin`, with any
/// element left open closed, as the C's caller closes `<script>`.
fn l_xml_end<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let mut store = c.store.borrow_mut();
    let mut w = std::mem::take(&mut store.xml);
    while let Some(name) = w.open.pop() {
        w.out.extend_from_slice(b"</");
        w.out.extend_from_slice(&name);
        w.out.push(b'>');
    }
    s.replace(ctx, ctx.intern(&w.out));
    Ok(())
}

/// The glue's `rendered(i, str, xml)`: result `i`'s text and XML.
fn l_rendered<'gc>(
    c: &Cnse,
    ctx: Context<'gc>,
    s: &mut piccolo::Stack<'gc, '_>,
) -> Result<(), Fail> {
    let a = args(ctx, s);
    let i = usize::try_from(a.check_integer(1)?.saturating_sub(1)).unwrap_or(usize::MAX);
    let text = |n: usize| -> Option<Vec<u8>> {
        match a.get(n) {
            Some(Value::String(s)) => Some(s.as_bytes().to_vec()),
            Some(v @ (Value::Integer(_) | Value::Number(_))) => {
                v.into_string(ctx).map(|s| s.as_bytes().to_vec())
            }
            _ => None,
        }
    };
    let entry = (text(2), text(3));
    let mut store = c.store.borrow_mut();
    if let Some(slot) = store.rendered.get_mut(i) {
        *slot = Some(entry);
    }
    s.clear();
    Ok(())
}

/// A limit on the work one call into the engine may do, in VM fuel; `None`
/// is nmap's behaviour, no limit.
pub type Budget = Option<u64>;

/// Step `ex` until it finishes, or the budget is spent.
pub(crate) fn finish(lua: &mut Lua, ex: &StashedExecutor, budget: Budget, what: &str) -> Result<(), String> {
    const SLICE: i32 = 4096;
    let mut spent: u64 = 0;
    loop {
        let mut f = Fuel::with(SLICE);
        match lua.enter(|ctx| ctx.fetch(ex).step(ctx, &mut f)) {
            Ok(true) => return Ok(()),
            Ok(false) => {}
            Err(e) => return Err(e.to_string()),
        }
        spent = spent.saturating_add(u64::from(SLICE.unsigned_abs()));
        if budget.is_some_and(|b| spent > b) {
            return Err(format!("{what}: out of fuel"));
        }
    }
}

/// Take the outcome of a finished executor: `Ok` with nothing, or the
/// error that escaped, as text.
pub(crate) fn outcome(lua: &mut Lua, ex: &StashedExecutor) -> Result<(), String> {
    lua.enter(|ctx| match ctx.fetch(ex).take_result::<piccolo::Variadic<Vec<Value>>>(ctx) {
        Ok(Ok(_)) => Ok(()),
        Ok(Err(e)) => Err(match e {
            piccolo::Error::Lua(v) => v.0.display().to_string(),
            piccolo::Error::Runtime(r) => format!("{r:#}"),
        }),
        Err(e) => Err(e.to_string()),
    })
}

/// A script chosen to run, as `get_chosen_scripts` hands it to
/// `Script.new`: its path and the selection parameters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChosenScript {
    pub path: Vec<u8>,
    /// How it was selected: `"name"`, `"category"`, `"file path"` or
    /// `"directory"`.
    pub selection: &'static str,
    /// Selected by name or path: its debugging output is shown at `-v`.
    pub verbosity: bool,
    /// Named with a leading `+`: run whatever its rules say.
    pub forced: bool,
}

/// One host's script results after a phase.
#[derive(Debug, Clone, PartialEq)]
pub struct HostResults {
    /// The host as the scripts left it (`nmap.set_port_state` and the like).
    pub host: ScriptHost,
    /// Host-script results, in the order the scripts stored them.
    pub results: Vec<ScriptOutput>,
    /// Port-script results, per port: protocol, number, and results in the
    /// order stored.
    pub ports: Vec<(Protocol, u16, Vec<ScriptOutput>)>,
}

/// What one phase produced.
#[derive(Debug, Clone, PartialEq)]
pub struct PhaseResults {
    /// Pre- or post-scan results, in the order stored.
    pub run: Vec<ScriptOutput>,
    /// Per host, in the order the hosts were given.
    pub hosts: Vec<HostResults>,
    /// The error the engine threw, if the phase was aborted: nmap's
    /// `Script Engine Scan Aborted`. What was stored before is kept.
    pub aborted: Option<String>,
}

impl super::runtime::NseState {
    /// Load the chosen scripts (`Script.new` on each) and compute their
    /// runlevels: `get_chosen_scripts`' second half. An error is nmap's
    /// "failed to initialize the script engine".
    pub fn load_scripts(&mut self, chosen: &[ChosenScript], budget: Budget) -> Result<(), String> {
        let ex = self.lua.enter(|ctx| {
            let engine = ctx.fetch(&self.engine);
            let list = Table::new(&ctx);
            for (i, c) in chosen.iter().enumerate() {
                let params = Table::new(&ctx);
                params.set_field(ctx, "selection", c.selection);
                params.set_field(ctx, "verbosity", c.verbosity);
                params.set_field(ctx, "forced", c.forced);
                let entry = Table::new(&ctx);
                entry.set_field(ctx, "path", ctx.intern(&c.path));
                entry.set_field(ctx, "params", params);
                let n = i64::try_from(i).unwrap_or(i64::MAX).saturating_add(1);
                let _ = list.set(ctx, n, entry);
            }
            let f: piccolo::Function = engine
                .get(ctx, "load_scripts")
                .expect("the prelude returns load_scripts");
            ctx.stash(Executor::start(ctx, f, list))
        });
        finish(&mut self.lua, &ex, budget, "loading scripts")?;
        outcome(&mut self.lua, &ex)
    }

    /// Load what script selection chose ([`super::choose::choose`]): its
    /// warnings logged as `log_error` logs them, its scripts loaded, then its
    /// error, if it ended with one — the order the C raises them in.
    pub fn load_chosen(&mut self, chosen: &super::choose::Chosen, budget: Budget) -> Result<(), String> {
        for w in &chosen.warnings {
            let mut line = b"NSE: ".to_vec();
            line.extend_from_slice(w);
            line.push(b'\n');
            self.lib.borrow_mut().log(super::nmaplib::LogTarget::Stderr, &line);
        }
        self.load_scripts(&chosen.scripts, budget)?;
        match &chosen.error {
            Some(e) => Err(String::from_utf8_lossy(e).into_owned()),
            None => Ok(()),
        }
    }

    /// `script_scan(targets, phase)`: run the phase over `hosts` (none for
    /// the pre- and post-scan phases) and render what the scripts stored.
    pub fn run_phase(
        &mut self,
        phase: Phase,
        hosts: Vec<ScriptHost>,
        budget: Budget,
    ) -> PhaseResults {
        let n_hosts = hosts.len();
        {
            let mut lib = self.lib.borrow_mut();
            lib.env.phase = phase;
            lib.set_hosts(hosts);
        }
        let scantype = match phase {
            Phase::PreScan => "NSE_PRE_SCAN",
            Phase::Scan => "NSE_SCAN",
            Phase::PostScan => "NSE_POST_SCAN",
        };
        let lib = self.lib.clone();
        let ex = self.lua.enter(|ctx| {
            let engine = ctx.fetch(&self.engine);
            let list = Table::new(&ctx);
            for i in 0..n_hosts {
                let n = i64::try_from(i).unwrap_or(i64::MAX).saturating_add(1);
                let _ = list.set(ctx, n, super::nmaplib::host_table(ctx, &lib, i));
            }
            let f: piccolo::Function = engine
                .get(ctx, "main")
                .expect("the prelude returns main");
            ctx.stash(Executor::start(ctx, f, (list, scantype)))
        });
        let aborted = finish(&mut self.lua, &ex, budget, "script scan")
            .and_then(|()| outcome(&mut self.lua, &ex))
            .err();
        let mut results = self.render(budget);
        results.aborted = aborted;
        results
    }

    /// Render and collect what the phase stored, leaving the store empty.
    fn render(&mut self, budget: Budget) -> PhaseResults {
        let stored = std::mem::take(&mut self.store.borrow_mut().stored);
        self.store.borrow_mut().rendered = vec![None; stored.len()];
        let ex = self.lua.enter(|ctx| {
            let engine = ctx.fetch(&self.engine);
            let list = Table::new(&ctx);
            for (i, s) in stored.iter().enumerate() {
                let r = Table::new(&ctx);
                if let Some(t) = &s.tab {
                    r.set_field(ctx, "tab", ctx.fetch(t));
                }
                if let Some(v) = &s.str {
                    r.set_field(ctx, "str", ctx.fetch(v));
                }
                let n = i64::try_from(i).unwrap_or(i64::MAX).saturating_add(1);
                let _ = list.set(ctx, n, r);
            }
            let f: piccolo::Function = engine
                .get(ctx, "render")
                .expect("the prelude returns render");
            ctx.stash(Executor::start(ctx, f, list))
        });
        // A result whose rendering did not finish is reported with no text,
        // as the C reports a FORMAT_TABLE that failed.
        let _ = finish(&mut self.lua, &ex, budget, "rendering").and_then(|()| outcome(&mut self.lua, &ex));
        let rendered = std::mem::take(&mut self.store.borrow_mut().rendered);
        let lib = self.lib.borrow();
        let out = PhaseResults {
            run: Vec::new(),
            hosts: lib
                .hosts()
                .iter()
                .map(|h| HostResults {
                    host: h.clone(),
                    results: Vec::new(),
                    ports: Vec::new(),
                })
                .collect(),
            aborted: None,
        };
        drop(lib);
        Self::collect(out, stored, rendered)
    }

    /// File each rendered result under its run, host or port, each list in
    /// order of script id (`nse-results-sorted-by-id`).
    fn collect(
        mut out: PhaseResults,
        stored: Vec<Stored>,
        rendered: Vec<Option<(Option<Vec<u8>>, Option<Vec<u8>>)>>,
    ) -> PhaseResults {
        for (s, r) in stored.into_iter().zip(rendered) {
            let (output, table_xml) = r.unwrap_or((None, None));
            let result = ScriptOutput {
                id: s.id,
                output,
                table_xml,
            };
            match s.container {
                Container::Run => out.run.push(result),
                Container::Host(h) => {
                    if let Some(hr) = out.hosts.get_mut(h) {
                        hr.results.push(result);
                    }
                }
                Container::Port(h, p) => {
                    if let Some(hr) = out.hosts.get_mut(h) {
                        let Some(port) = hr.host.ports.get(p) else {
                            continue;
                        };
                        let key = (port.protocol, port.number);
                        match hr.ports.iter_mut().find(|(pr, n, _)| (*pr, *n) == key) {
                            Some((_, _, list)) => list.push(result),
                            None => hr.ports.push((key.0, key.1, vec![result])),
                        }
                    }
                }
            }
        }
        // `ScriptResults` is a `std::multiset<ScriptResult *>`: ordered by
        // the results' addresses, not by the `operator<` on script ids that
        // `ScriptResult` defines. Sorting by id is what that operator meant.
        out.run.sort_by(|a, b| a.id.cmp(&b.id));
        for h in &mut out.hosts {
            h.results.sort_by(|a, b| a.id.cmp(&b.id));
            for (_, _, list) in &mut h.ports {
                list.sort_by(|a, b| a.id.cmp(&b.id));
            }
        }
        out
    }
}
