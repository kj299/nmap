//! The `nmapdb` module (`nse_db.cc`): what scripts can ask nmap's data
//! files — the vendor of a MAC address, the service on a port, and the IP
//! protocols by number and by name.
//!
//! Four functions, each returning exactly one value (nil included) and
//! ignoring extra arguments, as `nse_db.cc:12-100` does:
//!
//! | function | C | answers from |
//! |---|---|---|
//! | `mac2corp(s)` | `l_mac2corp` → `MACPrefix2Corp` | `nmap-mac-prefixes` ([`crate::macvendor`]) |
//! | `getservbyport(port, proto)` | `l_getservbyport` → `nmap_getservbyport` | `nmap-services` ([`crate::ports::ServiceTable`]) |
//! | `getprotbynum(n)` | `l_getprotbynum` → `nmap_getprotbynum` | `nmap-protocols` ([`crate::protocols`]) |
//! | `getprotbyname(s)` | `l_getprotbyname` → `nmap_getprotbyname` | `nmap-protocols` |
//!
//! The module is registered as `nse_main.cc` registers it, with
//! `luaL_requiref(L, "nmapdb", luaopen_db, 1)`: a global, and in
//! `package.loaded` ([`super::runtime`]).
//!
//! **Data files.** `nmap-mac-prefixes` and `nmap-protocols` are read the
//! first time a script needs them, once, as bytes, through
//! [`super::nmaplib::NmapEnv::read_data_file`]; a missing file is reported
//! once, in the C's words, and every lookup in it is then nil. The services
//! table is the one the scan already holds. Where each file was read from is
//! kept for a "Read data files from" line, which the port does not print yet
//! (`nse-datafiles-not-reported`).
//!
//! **Errors** are raised as `luaL_error` and `luaL_argerror` raise them: with
//! the position of the Lua code that called the function (`luaL_where(L,
//! 1)`). A bad argument names the function by its registered name,
//! `'getservbyport'`, when the caller is Lua code, and otherwise (a `pcall`)
//! by the name `pushglobalfuncname` finds in `package.loaded`,
//! `'nmapdb.getservbyport'`. 7.94 names it as `getfuncname` describes the
//! call — the field, local, upvalue or global it was called through, a
//! method call's `calling 'X' on bad self`, a metamethod's event — so the two
//! agree only on a direct `nmapdb.X(...)` call and a `pcall`
//! (`nmapdb-bad-argument-naming`).
//!
//! **Where the C is not followed** (DIVERGENCES.md, Milestone 6.6 step a):
//! `getservbyport`'s option list is terminated, so an unknown protocol is a
//! clean "invalid option" error (`nmapdb-getservbyport-option-overread`);
//! `getprotbynum(255)` answers from the table, as this tree does, where 7.94
//! aborts (`nmapdb-getprotbynum-255-oracle-abort`); and a byte of 128 or more
//! is never a hex digit to `mac2corp` (`nmapdb-mac2corp-isxdigit-signed-char`).

use std::collections::BTreeMap;

use piccolo::{Callback, CallbackReturn, Context, Error, Execution, Stack, Table, Value};

use super::nmaplib::{
    c_str, check_option, Fail, Handle, LogTarget, NmapLib, Shared, PROTOCOLS, PROTOCOL_VALUES,
};
use super::stdlib::{lua_error_bytes, LuaArgs};
use crate::macvendor::MacPrefixDb;
use crate::protocols::ProtocolTable;

/// A data file as `nmap_fetchfile` and `fopen` find it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DataFile {
    /// Found and read whole: where, and its bytes.
    Read { path: Vec<u8>, bytes: Vec<u8> },
    /// Found, but it could not be read: where, and the system's reason.
    Unreadable { path: Vec<u8>, error: Vec<u8> },
    /// Not on the data path.
    NotFound,
}

/// Read a data file by name ([`super::nmaplib::NmapEnv::read_data_file`]).
pub type ReadDataFile = Box<dyn Fn(&str) -> DataFile>;

/// The tables behind the module that are read on first use, each at most
/// once, as `mac_prefix_init` and `nmap_protocols_init` read theirs.
#[derive(Debug, Default)]
pub struct Tables {
    /// `MacTable`: `None` until first needed, then the table or, if the file
    /// could not be read, nothing.
    mac: Option<Option<MacPrefixDb>>,
    /// `proto_map` and `protocol_table`, likewise.
    protocols: Option<Option<ProtocolTable>>,
    /// `o.loaded_data_files`: where each file was read from, by name.
    pub loaded: BTreeMap<&'static str, Vec<u8>>,
}

/// `isxdigit` and `nibble`: the value of a hex digit. A byte of 128 or more
/// is not one, which the C leaves to `isxdigit` of a negative `char`.
fn hex_digit(b: u8) -> Option<u8> {
    char::from(b)
        .to_digit(16)
        .filter(|_| b.is_ascii_hexdigit())
        .and_then(|d| u8::try_from(d).ok())
}

/// `l_mac2corp`'s reading of its argument (`nse_db.cc:19-41`): the address
/// it names, or `None` for "Expected a 6-byte MAC address".
///
/// - A string of exactly 6 bytes is the address itself, whatever its bytes.
/// - Otherwise it must be hex pairs, each optionally preceded by one `:`,
///   making exactly 6 bytes and using the whole string: `001122334455`,
///   `00:11:22:33:44:55`, `:00:11:22:33:44:55` and `0011:2233:4455` all
///   name the same address. A `:` is skipped only when two more bytes
///   follow it, so `00:11:22:33:44:55:` is refused.
#[must_use]
pub fn parse_mac(buf: &[u8]) -> Option<[u8; 6]> {
    if let Ok(raw) = <[u8; 6]>::try_from(buf) {
        return Some(raw);
    }
    let len = buf.len();
    let mut out = [0u8; 6];
    let (mut i, mut j) = (0usize, 0usize);
    while i.saturating_add(1) < len && j < out.len() {
        if buf[i] == b':' && i.saturating_add(2) < len {
            i = i.saturating_add(1);
        }
        let pair = (hex_digit(buf[i]), buf.get(i.saturating_add(1)).copied());
        match pair {
            (Some(hi), Some(lo)) => match hex_digit(lo) {
                Some(lo) => out[j] = (hi << 4) | lo,
                None => break,
            },
            _ => break,
        }
        j = j.saturating_add(1);
        i = i.saturating_add(2);
    }
    (j == out.len() && i >= len).then_some(out)
}

/// `error(...)`: a line to `LOG_NORMAL|LOG_STDERR`.
fn error_line(lib: &mut NmapLib, parts: &[&[u8]]) {
    let mut line = Vec::new();
    for p in parts {
        line.extend_from_slice(p);
    }
    line.push(b'\n');
    lib.log(LogTarget::Error, &line);
}

/// After the warnings a parse kept (at most ten), one line for those it
/// only counted, so a malformed file of any size costs a dozen lines of
/// output, not one per line.
fn more_line(lib: &mut NmapLib, count: usize, shown: usize, path: &[u8]) {
    let more = count.saturating_sub(shown);
    if more > 0 {
        let n = more.to_string();
        error_line(
            lib,
            &[b"... and ", n.as_bytes(), b" more parse errors in ", path],
        );
    }
}

/// `mac_prefix_init` (`MACLookup.cc:84-167`): read `nmap-mac-prefixes` the
/// first time, and the table from then on.
fn mac_table(lib: &mut NmapLib) -> Option<&MacPrefixDb> {
    if lib.db.mac.is_none() {
        let db = match (lib.env.read_data_file)("nmap-mac-prefixes") {
            DataFile::NotFound => {
                error_line(
                    lib,
                    &[b"Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed"],
                );
                None
            }
            DataFile::Unreadable { path, error } => {
                // `gh_perror`'s format: the message, then `: ` and the reason.
                error_line(
                    lib,
                    &[
                        b"Unable to open ",
                        &path,
                        b".  Ethernet vendor correlation will not be performed : ",
                        &error,
                    ],
                );
                None
            }
            DataFile::Read { path, bytes } => {
                let mut db = MacPrefixDb::parse(&bytes);
                drop(bytes);
                // The C gives up at its first bad line; this reads on, and says
                // so of the first few, then counts the rest
                // (`macvendor-parse-degrade`). The warnings are not kept with
                // the table.
                let warnings = std::mem::take(&mut db.warnings);
                for w in &warnings {
                    let n = w.line.to_string();
                    let problem = w.problem.to_string();
                    error_line(
                        lib,
                        &[
                            b"Parse error on line #",
                            n.as_bytes(),
                            b" of ",
                            &path,
                            b": ",
                            problem.as_bytes(),
                            b". Skipping it.",
                        ],
                    );
                }
                more_line(lib, db.warning_count, warnings.len(), &path);
                lib.db.loaded.insert("nmap-mac-prefixes", path);
                Some(db)
            }
        };
        lib.db.mac = Some(db);
    }
    lib.db.mac.as_ref().and_then(Option::as_ref)
}

/// `nmap_protocols_init` (`protocols.cc:87-153`): read `nmap-protocols` the
/// first time, and the table from then on. There is no `/etc/protocols` to
/// fall back on (`datafiles-no-etc-fallback`), and a file that cannot be read
/// costs the lookups, where C's `pfatal` ends the scan.
fn protocol_table(lib: &mut NmapLib) -> Option<&ProtocolTable> {
    if lib.db.protocols.is_none() {
        let table = match (lib.env.read_data_file)("nmap-protocols") {
            DataFile::NotFound => {
                error_line(lib, &[b"Unable to find nmap-protocols!"]);
                None
            }
            DataFile::Unreadable { path, error } => {
                error_line(
                    lib,
                    &[
                        b"Unable to open ",
                        &path,
                        b" for reading protocol information: ",
                        &error,
                    ],
                );
                None
            }
            DataFile::Read { path, bytes } => {
                let mut table = ProtocolTable::parse(&bytes);
                drop(bytes);
                // C says so of every bad line; this of the first few, then
                // counts the rest (`protocols-parse-warning-cap`).
                let warnings = std::mem::take(&mut table.warnings);
                for w in &warnings {
                    let n = w.line.to_string();
                    error_line(
                        lib,
                        &[
                            b"Parse error in protocols file ",
                            &path,
                            b" line ",
                            n.as_bytes(),
                        ],
                    );
                }
                more_line(lib, table.warning_count, warnings.len(), &path);
                lib.db.loaded.insert("nmap-protocols", path);
                Some(table)
            }
        };
        lib.db.protocols = Some(table);
    }
    lib.db.protocols.as_ref().and_then(Option::as_ref)
}

/// Replace the arguments with one result.
fn put<'gc>(s: &mut Stack<'gc, '_>, v: Value<'gc>) -> Result<(), Fail> {
    s.clear();
    s.push_back(v);
    Ok(())
}

/// `l_mac2corp`.
fn l_mac2corp<'gc>(lib: &Shared, ctx: Context<'gc>, s: &mut Stack<'gc, '_>) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    let buf = args.string(1)?;
    let mac = parse_mac(&buf).ok_or_else(|| Fail::err("Expected a 6-byte MAC address"))?;
    let mut l = lib.borrow_mut();
    let v = match mac_table(&mut l).and_then(|db| db.lookup(mac)) {
        Some(vendor) => Value::String(ctx.intern(vendor)),
        None => Value::Nil,
    };
    drop(l);
    put(s, v)
}

/// `l_getservbyport`: the checks in the C's order — the port is an integer,
/// the protocol is one of the list, the port is in range.
fn l_getservbyport<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    let port = args.check_integer(1)?;
    // `{"tcp", "udp", "sctp"}`, terminated here (`nse_db.cc:49-52` is not).
    let proto = check_option(&args, 2, None, &PROTOCOLS)?;
    let port = u16::try_from(port).map_err(|_| Fail::err("Port number out of range"))?;
    let l = lib.borrow();
    // `serv->s_name`, which is NULL, and pushed as nil, for the entries named
    // `unknown`.
    let v = match l
        .env
        .services
        .as_ref()
        .and_then(|t| t.stored_name(port, PROTOCOL_VALUES[proto]))
    {
        Some(name) => Value::String(ctx.intern(name.as_bytes())),
        None => Value::Nil,
    };
    drop(l);
    put(s, v)
}

/// `l_getprotbynum`. 255 is in range, and answered from the table, as this
/// tree answers it (`efa0dc36f`).
fn l_getprotbynum<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    let num = args.check_integer(1)?;
    let num = u8::try_from(num).map_err(|_| Fail::err("Protocol number out of range"))?;
    let mut l = lib.borrow_mut();
    let v = match protocol_table(&mut l).and_then(|t| t.by_number(num)) {
        Some(name) => Value::String(ctx.intern(name)),
        None => Value::Nil,
    };
    drop(l);
    put(s, v)
}

/// `l_getprotbyname`: compared with `strcmp`, so case matters and the name
/// ends at its first NUL.
fn l_getprotbyname<'gc>(
    lib: &Shared,
    ctx: Context<'gc>,
    s: &mut Stack<'gc, '_>,
) -> Result<(), Fail> {
    let args = LuaArgs { ctx, stack: s };
    let name = args.string(1)?;
    let name = c_str(&name);
    let mut l = lib.borrow_mut();
    let v = match protocol_table(&mut l).and_then(|t| t.by_name(name)) {
        Some(n) => Value::Integer(i64::from(n)),
        None => Value::Nil,
    };
    drop(l);
    put(s, v)
}

/// The name `luaL_argerror` gives the function: its registered name when the
/// caller is Lua code, whatever that code called it through, and otherwise
/// the name `pushglobalfuncname` finds for it in `package.loaded`
/// (`nmapdb-bad-argument-naming`).
fn function_name(exec: &Execution<'_, '_>, name: &'static str) -> String {
    if exec.frame_info(1).is_some_and(|f| f.lua.is_some()) {
        name.to_string()
    } else {
        format!("nmapdb.{name}")
    }
}

/// `luaL_error` and `luaL_argerror`: the message, after `luaL_where(L, 1)`.
fn raise<'gc>(
    ctx: Context<'gc>,
    exec: &Execution<'gc, '_>,
    e: &Fail,
    name: &'static str,
) -> Error<'gc> {
    let mut msg = exec.where_at(1);
    msg.extend_from_slice(&e.message(&function_name(exec, name)));
    lua_error_bytes(ctx, &msg)
}

type Body = super::nmaplib::Body;

/// `luaopen_db`: the module's table, holding its four functions and nothing
/// else.
pub fn load_nmapdb<'gc>(ctx: Context<'gc>, lib: &Shared) -> Table<'gc> {
    let t = Table::new(&ctx);
    let fns: [(&'static str, Body); 4] = [
        ("mac2corp", l_mac2corp),
        ("getservbyport", l_getservbyport),
        ("getprotbynum", l_getprotbynum),
        ("getprotbyname", l_getprotbyname),
    ];
    for (name, body) in fns {
        t.set_field(
            ctx,
            name,
            Callback::from_fn_with(&ctx, Handle(lib.clone()), move |h, ctx, exec, mut stack| {
                match body(&h.0, ctx, &mut stack) {
                    Ok(()) => Ok(CallbackReturn::Return),
                    Err(e) => Err(raise(ctx, &exec, &e, name)),
                }
            }),
        );
    }
    t
}

#[cfg(test)]
mod tests {
    //! The module through the VM, with small data files, and the pins for
    //! the calls the oracle cannot make (`m66_nmapdb_quarantine.txt`).
    //! In-module so that Miri runs them.
    use super::*;
    use crate::nse::nmaplib::{Interface, LogTarget, NmapEnv, NmapLib, Phase};
    use crate::ports::ServiceTable;
    use piccolo::{Closure, Executor, Lua};
    use std::cell::RefCell;
    use std::rc::Rc;

    const MACS: &[u8] = b"# test\n000000 Xerox\n00000C Cisco Systems\n0055DA Wrong\n\
        0055DA0 Right\n080027 Oracle VirtualBox virtual NIC\n123456\n";
    const PROTOCOLS_FILE: &[u8] = b"hopopt 0\nicmp 1\ntcp 6 TCP\nudp 17\nraw 255\n";
    const SERVICES: &str = "tcpmux\t1/tcp\t0.001\nunknown\t4/tcp\t0.0004\n\
        http\t80/tcp\t0.48\nhttp\t80/udp\t0.001\nunknown\t80/sctp\t0.0\ndomain\t53/udp\t0.2\n";

    type Logs = Rc<RefCell<Vec<Vec<u8>>>>;

    fn env(files: Vec<(&'static str, DataFile)>, logs: &Logs) -> NmapEnv {
        let logs = logs.clone();
        NmapEnv {
            verbose: 0,
            debugging: 0,
            timing_level: 3,
            version_intensity: 7,
            ttl: -1,
            data_length: -1,
            have_ssl: false,
            privileged: false,
            ipv6: false,
            interface: None,
            dns_servers: vec![],
            excluded_ports: None,
            services: Some(ServiceTable::parse(SERVICES)),
            phase: Phase::PreScan,
            interfaces: Ok(Vec::<Interface>::new()),
            fetchfile: Box::new(|_| None),
            read_data_file: Box::new(move |name| {
                files
                    .iter()
                    .find(|(n, _)| *n == name)
                    .map_or(DataFile::NotFound, |(_, f)| f.clone())
            }),
            clock: Box::new(|| (0, 0)),
            random: Box::new(|_| false),
            log: Box::new(move |to, m| {
                assert_eq!(to, LogTarget::Error);
                logs.borrow_mut().push(m.to_vec());
            }),
        }
    }

    fn read(name: &str, bytes: &[u8]) -> DataFile {
        DataFile::Read {
            path: format!("/data/{name}").into_bytes(),
            bytes: bytes.to_vec(),
        }
    }

    fn standard() -> Vec<(&'static str, DataFile)> {
        vec![
            ("nmap-mac-prefixes", read("nmap-mac-prefixes", MACS)),
            ("nmap-protocols", read("nmap-protocols", PROTOCOLS_FILE)),
        ]
    }

    /// Run `src` with `nmapdb` registered as NSE registers it, and return
    /// what it returned, as a string.
    fn run(lib: &Shared, src: &str) -> String {
        let mut lua = Lua::core();
        let ex = lua.enter(|ctx| {
            crate::nse::stdlib::load_patterns(ctx).unwrap();
            crate::nse::stdlib::load_format(ctx).unwrap();
            let t = load_nmapdb(ctx, lib);
            ctx.set_global("nmapdb", t);
            let render = "local function r(...) \
                local t = table.pack(...) \
                local out = {} \
                for i = 1, t.n do \
                  local v = t[i] \
                  out[i] = type(v) == 'string' and ('s:' .. v) or tostring(v) \
                end \
                return table.concat(out, '|') end ";
            let f = Closure::load(ctx, Some("=t"), format!("{render}{src}").as_bytes()).unwrap();
            ctx.stash(Executor::start(ctx, f.into(), ()))
        });
        lua.finish(&ex).unwrap();
        lua.enter(|ctx| {
            ctx.fetch(&ex)
                .take_result::<piccolo::Value>(ctx)
                .unwrap()
                .unwrap()
                .display()
                .to_string()
        })
    }

    fn lib_with(files: Vec<(&'static str, DataFile)>) -> (Shared, Logs) {
        let logs = Logs::default();
        (NmapLib::new(env(files, &logs)), logs)
    }

    #[test]
    fn parse_mac_reads_raw_bytes_and_hex_pairs() {
        let want = Some([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
        for ok in [
            &b"001122334455"[..],
            b"00:11:22:33:44:55",
            b":00:11:22:33:44:55",
            b":001122334455",
            b"0011:2233:4455",
            b"00:1122:33:4455",
        ] {
            assert_eq!(parse_mac(ok), want, "{ok:?}");
        }
        assert_eq!(parse_mac(b"\x00\x11\x22\x33\x44\x55"), want);
        // Six bytes are raw bytes, even when they look like hex digits.
        assert_eq!(parse_mac(b"000000"), Some(*b"000000"));
        assert_eq!(
            parse_mac(b"aabbccddeeff"),
            Some([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff])
        );
        for bad in [
            &b""[..],
            b"0",
            b"00:11:22:33:44:55:",
            b"00:11:22:33:44:5",
            b"00::11:22:33:44:55",
            b"0:11:22:33:44:55",
            b"00-11-22-33-44-55",
            b"0011223344556",
            b"001122334455 ",
            b" 001122334455",
            b"00:11:22:33:44:55:66",
            b"00:00:0c:12:34:5g",
            b"0x0000000c12",
            b"00\x00000000000",
            b"00:00:0c:12:34:56\x00",
            b"12345678901",
        ] {
            assert_eq!(parse_mac(bad), None, "{bad:?}");
        }
    }

    /// `nmapdb-mac2corp-isxdigit-signed-char`: the C hands `isxdigit` a
    /// negative `char` for a byte of 128 or more, which ISO C leaves
    /// undefined. Such a byte is never a hex digit here.
    #[test]
    fn a_high_byte_is_never_a_hex_digit() {
        assert_eq!(parse_mac(b"00\x80000000000"), None);
        assert_eq!(parse_mac(&[0xc8; 12]), None);
        for b in 0x80..=0xffu8 {
            assert_eq!(hex_digit(b), None);
        }
        // Except as one of six raw bytes.
        assert_eq!(parse_mac(&[0x80; 6]), Some([0x80; 6]));
    }

    #[test]
    fn mac2corp_looks_up_most_specific_first() {
        let (lib, logs) = lib_with(standard());
        let out = run(
            &lib,
            "return r(nmapdb.mac2corp('00:00:0C:12:34:56'), nmapdb.mac2corp('0055da0fffff'), \
             nmapdb.mac2corp('0055DA1FFFFF'), nmapdb.mac2corp('\\0\\0\\0\\0\\0\\0'), \
             nmapdb.mac2corp('AABBCCDDEEFF'), nmapdb.mac2corp('123456000000'))",
        );
        assert_eq!(out, "s:Cisco Systems|s:Right|s:Wrong|s:Xerox|nil|nil");
        // The prefix-only line is skipped, and said to be (7.94 aborts on it).
        let logs = logs.borrow();
        assert_eq!(logs.len(), 1, "{logs:?}");
        assert!(logs[0].starts_with(b"Parse error on line #7 of /data/nmap-mac-prefixes:"));
        // Where the file was read from, for "Read data files from".
        assert_eq!(
            lib.borrow().db.loaded.get("nmap-mac-prefixes"),
            Some(&b"/data/nmap-mac-prefixes".to_vec())
        );
    }

    /// `macvendor-parse-degrade` and `protocols-parse-warning-cap`: a file of
    /// bad lines is reported in at most eleven lines, the table still loads
    /// from its good lines, and no warning is kept with the table.
    #[test]
    fn a_file_of_bad_lines_is_reported_in_a_dozen_lines() {
        let mut macs = b"x\n".repeat(1000);
        macs.extend_from_slice(b"080027 Fine\n");
        let mut protos = b"bad\n".repeat(1000);
        protos.extend_from_slice(b"tcp 6\n");
        let (lib, logs) = lib_with(vec![
            ("nmap-mac-prefixes", read("nmap-mac-prefixes", &macs)),
            ("nmap-protocols", read("nmap-protocols", &protos)),
        ]);
        let out = run(
            &lib,
            "return r(nmapdb.mac2corp('080027000000'), nmapdb.getprotbyname('tcp'))",
        );
        assert_eq!(out, "s:Fine|6");
        let logs = logs.borrow();
        assert_eq!(logs.len(), 22, "{logs:?}");
        assert_eq!(
            logs[0],
            b"Parse error on line #1 of /data/nmap-mac-prefixes: expected a 6, 7 or 9 digit \
              prefix, found 0 hex digits. Skipping it.\n"
                .to_vec()
        );
        assert_eq!(
            logs[10],
            b"... and 990 more parse errors in /data/nmap-mac-prefixes\n".to_vec()
        );
        assert_eq!(
            logs[11],
            b"Parse error in protocols file /data/nmap-protocols line 1\n".to_vec()
        );
        assert_eq!(
            logs[21],
            b"... and 990 more parse errors in /data/nmap-protocols\n".to_vec()
        );
        let l = lib.borrow();
        let mac = l.db.mac.as_ref().and_then(Option::as_ref).unwrap();
        assert!(mac.warnings.is_empty());
        let protocols = l.db.protocols.as_ref().and_then(Option::as_ref).unwrap();
        assert!(protocols.warnings.is_empty());
    }

    #[test]
    fn mac2corp_errors_as_the_c_does() {
        let (lib, logs) = lib_with(standard());
        // Called by `pcall`: no position, and the name `pushglobalfuncname`
        // finds.
        let out = run(
            &lib,
            "return r(pcall(nmapdb.mac2corp, '00:11')) .. '/' .. r(pcall(nmapdb.mac2corp)) \
             .. '/' .. r(pcall(nmapdb.mac2corp, true))",
        );
        assert_eq!(
            out,
            "false|s:Expected a 6-byte MAC address/\
             false|s:bad argument #1 to 'nmapdb.mac2corp' (string expected, got no value)/\
             false|s:bad argument #1 to 'nmapdb.mac2corp' (string expected, got boolean)"
        );
        // A bad argument does not load the table.
        assert!(logs.borrow().is_empty());
        // Called from Lua code: positioned, and named by the field.
        let out = run(
            &lib,
            "return r(pcall(function() return nmapdb.mac2corp({}) end)) .. '/' .. \
             r(pcall(function() return nmapdb.mac2corp('x') end))",
        );
        assert_eq!(
            out,
            "false|s:t:1: bad argument #1 to 'mac2corp' (string expected, got table)/\
             false|s:t:1: Expected a 6-byte MAC address"
        );
        // A number is read as its string; extra arguments are ignored; one
        // result, nil included.
        let out = run(
            &lib,
            "return r(nmapdb.mac2corp(100000000000, 'x')) .. '/' .. \
             select('#', nmapdb.mac2corp('AABBCCDDEEFF')) .. '/' .. \
             r(pcall(nmapdb.mac2corp, 000000000000))",
        );
        assert_eq!(out, "nil/1/false|s:Expected a 6-byte MAC address");
    }

    #[test]
    fn a_missing_mac_file_is_reported_once_and_every_lookup_is_nil() {
        let (lib, logs) = lib_with(vec![]);
        let out = run(
            &lib,
            "return r(nmapdb.mac2corp('000000000000'), nmapdb.mac2corp('00:00:0c:00:00:00'))",
        );
        assert_eq!(out, "nil|nil");
        assert_eq!(
            *logs.borrow(),
            vec![b"Cannot find nmap-mac-prefixes: Ethernet vendor correlation will not be performed\n".to_vec()]
        );
        let (lib, logs) = lib_with(vec![(
            "nmap-mac-prefixes",
            DataFile::Unreadable {
                path: b"/data/nmap-mac-prefixes".to_vec(),
                error: b"Permission denied (13)".to_vec(),
            },
        )]);
        assert_eq!(
            run(&lib, "return r(nmapdb.mac2corp('000000000000'))"),
            "nil"
        );
        assert_eq!(
            run(&lib, "return r(nmapdb.mac2corp('000000000000'))"),
            "nil"
        );
        assert_eq!(
            *logs.borrow(),
            vec![b"Unable to open /data/nmap-mac-prefixes.  Ethernet vendor correlation will not be performed : Permission denied (13)\n".to_vec()]
        );
        assert!(lib.borrow().db.loaded.is_empty());
    }

    #[test]
    fn getservbyport_answers_from_the_services_table_with_unknown_as_nil() {
        let (lib, _) = lib_with(standard());
        let out = run(
            &lib,
            "return r(nmapdb.getservbyport(80, 'tcp'), nmapdb.getservbyport(80, 'udp'), \
             nmapdb.getservbyport(80, 'sctp'), nmapdb.getservbyport(4, 'tcp'), \
             nmapdb.getservbyport(1, 'tcp'), nmapdb.getservbyport(1, 'udp'), \
             nmapdb.getservbyport('53', 'udp\\0junk'), nmapdb.getservbyport(80.0, 'tcp', 'extra'))",
        );
        // 4/tcp and 80/sctp are named `unknown`: C stores no name for them.
        assert_eq!(out, "s:http|s:http|nil|nil|s:tcpmux|nil|s:domain|s:http");
    }

    #[test]
    fn getservbyport_checks_in_the_cs_order() {
        let (lib, _) = lib_with(standard());
        let out = run(
            &lib,
            "return r(select(2, pcall(nmapdb.getservbyport, 'x', nil))) .. '/' .. \
             r(select(2, pcall(nmapdb.getservbyport, 70000, nil))) .. '/' .. \
             r(select(2, pcall(nmapdb.getservbyport, 70000, 'tcp'))) .. '/' .. \
             r(select(2, pcall(nmapdb.getservbyport, -1, 'udp'))) .. '/' .. \
             r(select(2, pcall(nmapdb.getservbyport, 80.5, 'udp')))",
        );
        assert_eq!(
            out,
            "s:bad argument #1 to 'nmapdb.getservbyport' (number expected, got string)/\
             s:bad argument #2 to 'nmapdb.getservbyport' (string expected, got nil)/\
             s:Port number out of range/s:Port number out of range/\
             s:bad argument #1 to 'nmapdb.getservbyport' (number has no integer representation)"
        );
    }

    /// `nmapdb-getservbyport-option-overread`: 7.94's `luaL_checkoption`
    /// reads past its unterminated list for any protocol the list does not
    /// hold, before the port is checked. Here the list is terminated, and
    /// the answer is the error `luaL_checkoption` raises at the end of a
    /// terminated list — for any port.
    #[test]
    fn an_unknown_protocol_is_a_clean_invalid_option_error() {
        let (lib, _) = lib_with(standard());
        // One state for every call: Miri runs this.
        let protos = "'foo', 'TCP', 'Tcp', '', 'ip', 'icmp', '6', 6, 'tcp ', ' tcp', 'sctp\\1', \
                      'mac2corp', 'getservbyport', 'nmapdb', 'udplite'";
        let out = run(
            &lib,
            &format!(
                "local out = {{}} \
                 for _, proto in ipairs({{{protos}}}) do \
                   for _, port in ipairs({{80, -1}}) do \
                     local want = \"false|s:bad argument #2 to 'nmapdb.getservbyport' \
                       (invalid option '\" .. tostring(proto) .. \"')\" \
                     local got = r(pcall(nmapdb.getservbyport, port, proto)) \
                     if got ~= want then out[#out + 1] = got end \
                   end \
                 end \
                 return #out .. ':' .. table.concat(out, '/')"
            ),
        );
        assert_eq!(out, "0:");
    }

    #[test]
    fn getprotbynum_and_getprotbyname_answer_from_nmap_protocols() {
        let (lib, logs) = lib_with(standard());
        let out = run(
            &lib,
            "return r(nmapdb.getprotbynum(6), nmapdb.getprotbynum(0), nmapdb.getprotbynum(2), \
             nmapdb.getprotbynum('17'), nmapdb.getprotbyname('tcp'), nmapdb.getprotbyname('TCP'), \
             nmapdb.getprotbyname('udp\\0x'), nmapdb.getprotbyname(6), nmapdb.getprotbyname(''), \
             math.type(nmapdb.getprotbyname('icmp')))",
        );
        assert_eq!(out, "s:tcp|s:hopopt|nil|s:udp|6|nil|17|nil|nil|s:integer");
        assert!(logs.borrow().is_empty(), "{:?}", logs.borrow());
        let out = run(
            &lib,
            "return r(select(2, pcall(nmapdb.getprotbynum, 256))) .. '/' .. \
             r(select(2, pcall(nmapdb.getprotbynum, -1))) .. '/' .. \
             r(select(2, pcall(nmapdb.getprotbynum, 6.5))) .. '/' .. \
             r(select(2, pcall(nmapdb.getprotbyname, true)))",
        );
        assert_eq!(
            out,
            "s:Protocol number out of range/s:Protocol number out of range/\
             s:bad argument #1 to 'nmapdb.getprotbynum' (number has no integer representation)/\
             s:bad argument #1 to 'nmapdb.getprotbyname' (string expected, got boolean)"
        );
        assert_eq!(
            lib.borrow().db.loaded.get("nmap-protocols"),
            Some(&b"/data/nmap-protocols".to_vec())
        );
    }

    /// `nmapdb-getprotbynum-255-oracle-abort`: 7.94 admits 255 and then
    /// asserts it is below 255 (`3be01efb1:protocols.cc:193`), so the oracle
    /// cannot be asked. This tree's table has a slot for 255 (`efa0dc36f`):
    /// the answer is the table's, nil when the file names no protocol 255,
    /// as the shipped file does not.
    #[test]
    fn getprotbynum_255_answers_from_the_table() {
        let (lib, _) = lib_with(standard());
        let out = run(
            &lib,
            "return r(nmapdb.getprotbynum(255), nmapdb.getprotbynum(255.0), \
             nmapdb.getprotbynum('255'), nmapdb.getprotbynum('0xff'))",
        );
        assert_eq!(out, "s:raw|s:raw|s:raw|s:raw");
        let (lib, _) = lib_with(vec![(
            "nmap-protocols",
            read("nmap-protocols", b"tcp 6\nexperimental2 254\n"),
        )]);
        let out = run(
            &lib,
            "return r(nmapdb.getprotbynum(255), nmapdb.getprotbynum(255.0), \
             nmapdb.getprotbynum('255'), nmapdb.getprotbynum('0xff'), nmapdb.getprotbynum(254))",
        );
        assert_eq!(out, "nil|nil|nil|nil|s:experimental2");
    }

    #[test]
    fn a_missing_protocols_file_is_reported_once() {
        let (lib, logs) = lib_with(vec![]);
        let out = run(
            &lib,
            "return r(nmapdb.getprotbynum(6), nmapdb.getprotbyname('tcp'), nmapdb.getprotbynum(1))",
        );
        assert_eq!(out, "nil|nil|nil");
        assert_eq!(
            *logs.borrow(),
            vec![b"Unable to find nmap-protocols!\n".to_vec()]
        );
    }

    #[test]
    fn the_module_has_its_four_functions_and_nothing_else() {
        let (lib, _) = lib_with(standard());
        let out = run(
            &lib,
            "local k = {} for name, v in pairs(nmapdb) do k[#k + 1] = name .. ':' .. type(v) end \
             table.sort(k) return table.concat(k, ',')",
        );
        assert_eq!(
            out,
            "getprotbyname:function,getprotbynum:function,getservbyport:function,mac2corp:function"
        );
    }
}
