//! The `SSL_CERT` userdata and `parse_ssl_certificate` (`nse_ssl_cert.cc`):
//! a certificate's fields as a Lua table, behind a userdata whose `__index`
//! reads that table and whose methods table holds `digest`.
//!
//! **The object** is the C's (`nse_ssl_cert.cc:690-722`):
//! - a userdata with the `SSL_CERT` metatable (`__name`, `__index`, `__gc`);
//! - `__index` checks its argument is an `SSL_CERT` and reads the
//!   certificate's attribute table, which a script can change, and every
//!   holder of the userdata sees the change;
//! - that table's metatable has `__index` = the methods table, `digest`;
//! - `__gc` is present and inert (`nse-sslcert-gc-callable`: the C's frees
//!   the certificate and its table, so a script that calls it reads freed
//!   memory).
//!
//! **The table** is `parse_ssl_cert`'s (`nse_ssl_cert.cc:560-680`), built in
//! its order, so a failure part-way surfaces as it does there:
//! `subject`, `sig_algorithm`, `issuer`, `validity`, `pem`, `extensions`
//! (absent when there are none), then the key, which when it did not decode
//! makes the call return `nil` and "Error parsing cert: ...".
//!
//! **Memory.** The certificate's bytes the userdata keeps (its re-encoding,
//! for `digest`) are accounted to the VM's heap while it lives, as a
//! `BIGNUM`'s digits are (§1.4).

use gc_arena::metrics::Metrics;
use gc_arena::{Collect, Rootable};
use piccolo::{
    Callback, CallbackReturn, Context, Execution, Singleton, Stack, Table, UserData, Value,
};

use super::bn::Bn;
use super::digest;
use super::err;
use super::ext;
use super::objects::{self, nid_of, NID_UNDEF};
use super::pubkey::{EcInfo, Kind};
use super::x509::{self, Cert, NameEntry, Time};
use super::{push_bignum, string, Failure};
use crate::nse::nmaplib::Fail;
use crate::nse::stdlib::{lua_error, lua_error_bytes, type_error, LuaArgs};

/// The metatable's name (`luaL_newmetatable(L, "SSL_CERT")`), and the type
/// name in argument errors.
pub const SSL_CERT_T: &str = "SSL_CERT";

/// What `parse_ssl_cert` returns with `nil` when the key did not decode:
/// `ERR_error_string` of `X509_PUBKEY_get0`'s `EVP_R_DECODE_ERROR`, the one
/// error a key that failed to decode leaves (`x_pubkey.c`). The C prints the
/// *oldest* queued error: the first an extension's printing raised, when one
/// did (`ext`), else this. It can also be a stale one from earlier work
/// (`nse-openssl-error-queue-stale`); the port keeps no queue across calls.
pub const KEY_ERROR: &str =
    "Error parsing cert: error:03000072:digital envelope routines::decode error";

/// What a subject or issuer key whose OID `OBJ_obj2txt` cannot render
/// raises: `obj_to_key` doubles its buffer until the allocator refuses
/// (`nse_ssl_cert.cc:165-176`), which Lua reports as this.
const OID_KEY_ERROR: &str = "not enough memory";

/// What an extension whose OID `OBJ_obj2txt` cannot render raises: the C
/// pushes `MIN(-1, 256)` bytes, a length `lua_pushlstring` refuses
/// (`nse_ssl_cert.cc:236-238`, `luaM_toobig`).
const EXT_NAME_ERROR: &str = "memory allocation error: block too big";

/// A certificate userdata: its attribute table and its re-encoding.
#[derive(Collect)]
#[collect(no_drop)]
pub struct SslCert<'gc> {
    attrs: Table<'gc>,
    der: Accounted,
}

/// Bytes accounted to the VM's heap while they live.
#[derive(Collect)]
#[collect(require_static)]
struct Accounted {
    bytes: Vec<u8>,
    held: usize,
    metrics: Metrics,
}

impl Drop for Accounted {
    fn drop(&mut self) {
        self.metrics.mark_external_deallocation(self.held);
    }
}

type SslCertRoot = Rootable![SslCert<'_>];

/// What `nse_nsock_init_ssl_cert` keeps in the registry: the `SSL_CERT`
/// metatable and the attribute tables' metatable.
#[derive(Collect, Clone, Copy)]
#[collect(no_drop)]
struct Registry<'gc> {
    metatable: Table<'gc>,
    attrs_meta: Table<'gc>,
}

impl<'gc> Singleton<'gc> for Registry<'gc> {
    fn create(ctx: Context<'gc>) -> Self {
        let metatable = Table::new(&ctx);
        metatable.set_field(ctx, "__name", SSL_CERT_T);
        metatable.set_field(ctx, "__index", callback(ctx, Func::Index));
        metatable.set_field(ctx, "__gc", callback(ctx, Func::Gc));
        let methods = Table::new(&ctx);
        methods.set_field(ctx, "digest", callback(ctx, Func::Digest));
        let attrs_meta = Table::new(&ctx);
        attrs_meta.set_field(ctx, "__index", methods);
        Registry {
            metatable,
            attrs_meta,
        }
    }
}

fn registry<'gc>(ctx: Context<'gc>) -> Registry<'gc> {
    *ctx.singleton::<Rootable![Registry<'_>]>()
}

/// The certificate `v` is, if it is one (`luaL_testudata(L, i, "SSL_CERT")`).
#[must_use]
pub fn ssl_cert<'gc>(ctx: Context<'gc>, v: Value<'gc>) -> Option<&'gc SslCert<'gc>> {
    let Value::UserData(u) = v else {
        return None;
    };
    if u.metatable() != Some(registry(ctx).metatable) {
        return None;
    }
    u.downcast::<SslCertRoot>().ok()
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Collect)]
#[collect(require_static)]
enum Func {
    Parse,
    Index,
    Gc,
    Digest,
}

impl Func {
    /// The name `luaL_argerror` gives the function: from Lua code, the name
    /// it is called by; otherwise as `pushglobalfuncname` finds it, which
    /// for `parse_ssl_certificate` is `nmap.socket.parse_ssl_certificate`
    /// and for the rest, in no table it searches, `?`.
    fn name(self, exec: &Execution<'_, '_>) -> &'static str {
        let from_lua = exec.frame_info(1).is_some_and(|f| f.lua.is_some());
        match (self, from_lua) {
            (Func::Parse, true) => "parse_ssl_certificate",
            (Func::Parse, false) => "nmap.socket.parse_ssl_certificate",
            (Func::Digest, true) => "digest",
            (Func::Index, true) => "__index",
            (Func::Gc, true) => "__gc",
            _ => "?",
        }
    }
}

fn callback<'gc>(ctx: Context<'gc>, f: Func) -> Callback<'gc> {
    Callback::from_fn_with(&ctx, f, |&f, ctx, exec, mut stack| {
        match call(ctx, &mut stack, f) {
            Ok(()) => Ok(CallbackReturn::Return),
            Err(Failure::Lua(fail)) => {
                let mut msg = exec.where_at(1);
                msg.extend_from_slice(&fail.message(f.name(&exec)));
                Err(lua_error_bytes(ctx, &msg))
            }
            Err(Failure::Refused) => Err(lua_error(ctx, super::REFUSED)),
            Err(Failure::Random) => Err(lua_error(ctx, super::REFUSED)),
        }
    })
}

/// `l_parse_ssl_certificate`, which `luaopen_nsock` puts in `nmap.socket`
/// (`nse_nsock.cc:1187`); also given to the bare states that test it.
pub fn parse_ssl_certificate<'gc>(ctx: Context<'gc>) -> Callback<'gc> {
    callback(ctx, Func::Parse)
}

fn call<'gc>(ctx: Context<'gc>, stack: &mut Stack<'gc, '_>, f: Func) -> Result<(), Failure> {
    let args = LuaArgs { ctx, stack };
    match f {
        Func::Parse => {
            let der = args.string(1).map_err(Fail::from)?;
            let out = parse(ctx, &der)?;
            stack.clear();
            stack.extend(out);
        }
        Func::Index => {
            let cert = check(&args, 1)?;
            let key = args.get(2).unwrap_or(Value::Nil);
            let v = index_attrs(ctx, cert.attrs, key);
            stack.replace(ctx, v);
        }
        Func::Gc => {
            check(&args, 1)?;
            stack.clear();
        }
        Func::Digest => {
            let cert = check(&args, 1)?;
            let name = args.string(2).map_err(Fail::from)?;
            let out = match digest::resolve(&name) {
                Some(alg) => Value::String(ctx.intern(&digest::digest(alg, &cert.der.bytes))),
                None => {
                    stack.clear();
                    return Ok(());
                }
            };
            stack.replace(ctx, out);
        }
    }
    Ok(())
}

/// `lua_gettable` on the attribute table: a raw read, then its metatable's
/// `__index` (the methods table) for a key it lacks.
fn index_attrs<'gc>(ctx: Context<'gc>, attrs: Table<'gc>, key: Value<'gc>) -> Value<'gc> {
    let v = attrs.get_value(ctx, key);
    if !v.is_nil() {
        return v;
    }
    match attrs.metatable().map(|m| m.get_value(ctx, "__index")) {
        Some(Value::Table(methods)) => methods.get_value(ctx, key),
        _ => Value::Nil,
    }
}

/// `luaL_checkudata(L, arg, "SSL_CERT")`.
fn check<'gc>(args: &LuaArgs<'_, 'gc, '_>, arg: usize) -> Result<&'gc SslCert<'gc>, Fail> {
    let v = args.get(arg);
    v.and_then(|v| ssl_cert(args.ctx, v))
        .ok_or_else(|| type_error(args.ctx, v, arg, SSL_CERT_T).into())
}

/// `l_get_ssl_certificate`'s `parse_ssl_cert` of the leaf a handshake
/// accepted (`der`, decoded by the same reader and filling its entry, so
/// parsing it again gives the `X509` the handshake had): the values it
/// returns.
pub(crate) fn peer_certificate<'gc>(
    ctx: Context<'gc>,
    der: &[u8],
) -> Result<Vec<Value<'gc>>, Fail> {
    parse(ctx, der).map_err(|e| match e {
        Failure::Lua(f) => f,
        Failure::Refused | Failure::Random => Fail::err(super::REFUSED),
    })
}

/// `l_parse_ssl_certificate` then `parse_ssl_cert`: the values it returns.
fn parse<'gc>(ctx: Context<'gc>, der: &[u8]) -> Result<Vec<Value<'gc>>, Failure> {
    let Some(cert) = x509::d2i_x509(der) else {
        return Ok(vec![Value::Nil]);
    };
    let encoded = x509::i2d_x509(&cert);
    let attrs = Table::new(&ctx);
    attrs.set_field(ctx, "subject", name_table(ctx, &cert.subject)?);
    attrs.set_field(ctx, "sig_algorithm", sig_algorithm(&cert));
    attrs.set_field(ctx, "issuer", name_table(ctx, &cert.issuer)?);
    let validity = Table::new(&ctx);
    validity.set_field(ctx, "notBefore", time_value(ctx, &cert.not_before));
    validity.set_field(ctx, "notAfter", time_value(ctx, &cert.not_after));
    attrs.set_field(ctx, "validity", validity);
    attrs.set_field(ctx, "pem", string(ctx, &x509::pem(&encoded)));
    let mut first_error = None;
    if let Some(exts) = extensions_table(ctx, &cert, &mut first_error)? {
        attrs.set_field(ctx, "extensions", exts);
    }
    let Some(key) = &cert.spki.key else {
        let msg = match first_error {
            Some(code) => format!("Error parsing cert: {}", err::error_string(code)),
            None => KEY_ERROR.to_string(),
        };
        return Ok(vec![Value::Nil, string(ctx, msg.as_bytes())]);
    };
    let pk = Table::new(&ctx);
    // Only EVP_PKEY_EC gets curve parameters and only EVP_PKEY_RSA its
    // numbers (`nse_ssl_cert.cc:617-662`): not SM2, not RSA-PSS.
    if let (Kind::Ec, Some(info)) = (key.kind, key.ec) {
        pk.set_field(ctx, "ecdhparams", ecdhparams(ctx, info));
    } else if let (Kind::Rsa, Some((n, e))) = (key.kind, &key.rsa) {
        let e = Bn::from_bin(e).map_err(|_| Failure::Refused)?;
        pk.set_field(ctx, "exponent", push_bignum(ctx, e));
        let n = Bn::from_bin(n).map_err(|_| Failure::Refused)?;
        pk.set_field(ctx, "modulus", push_bignum(ctx, n));
    }
    pk.set_field(ctx, "type", key.type_name());
    pk.set_field(ctx, "bits", i64::try_from(key.bits).unwrap_or(i64::MAX));
    attrs.set_field(ctx, "pubkey", pk);
    attrs.set_metatable(&ctx, Some(registry(ctx).attrs_meta));
    let metrics = ctx.metrics().clone();
    let held = encoded.len().saturating_add(der.len());
    metrics.mark_external_allocation(held);
    let c = SslCert {
        attrs,
        der: Accounted {
            bytes: encoded,
            held,
            metrics,
        },
    };
    let u = UserData::new::<SslCertRoot>(&ctx, c);
    u.set_metatable(&ctx, Some(registry(ctx).metatable));
    Ok(vec![Value::UserData(u)])
}

/// `x509_name_to_table`: each entry under `obj_to_key`'s key, its value the
/// string's bytes; a later entry with the same key replaces an earlier one.
fn name_table<'gc>(ctx: Context<'gc>, entries: &[NameEntry]) -> Result<Table<'gc>, Failure> {
    let t = Table::new(&ctx);
    for e in entries {
        let key = obj_to_key(ctx, &e.oid)?;
        let _ = t.set(ctx, key, string(ctx, x509::string_data(&e.value)));
    }
    Ok(t)
}

/// `obj_to_key`: the long name of an OID OpenSSL knows, else a new array of
/// its arcs as strings.
fn obj_to_key<'gc>(ctx: Context<'gc>, oid: &[u8]) -> Result<Value<'gc>, Failure> {
    let nid = nid_of(oid);
    if nid != NID_UNDEF {
        if let Some(ln) = objects::long_name(nid) {
            return Ok(string(ctx, ln.as_bytes()));
        }
    }
    let Some(text) = objects::obj2txt(oid, true) else {
        return Err(Failure::Lua(Fail::err(OID_KEY_ERROR)));
    };
    let arr = Table::new(&ctx);
    for (i, arc) in text.split('.').enumerate() {
        let _ = arr.set(
            ctx,
            i64::try_from(i.saturating_add(1)).unwrap_or(i64::MAX),
            string(ctx, arc.as_bytes()),
        );
    }
    Ok(Value::Table(arr))
}

/// `OBJ_nid2ln(X509_get_signature_nid(cert))`: the outer algorithm's long
/// name, `undefined` for an OID OpenSSL does not know.
fn sig_algorithm(cert: &Cert) -> &'static str {
    objects::long_name(nid_of(&cert.sig_alg.oid)).unwrap_or("undefined")
}

/// `asn1_time_to_obj`: a date table if 7.94's parser reads the string, else
/// the string itself.
fn time_value<'gc>(ctx: Context<'gc>, t: &Time) -> Value<'gc> {
    let Some([year, month, day, hour, min, sec]) = x509::time_to_tm(&t.data) else {
        return string(ctx, &t.data);
    };
    let tt = Table::new(&ctx);
    tt.set_field(ctx, "year", year);
    tt.set_field(ctx, "month", month);
    tt.set_field(ctx, "day", day);
    tt.set_field(ctx, "hour", hour);
    tt.set_field(ctx, "min", min);
    tt.set_field(ctx, "sec", sec);
    Value::Table(tt)
}

/// `x509_extensions_to_table`: `nil` when there are none, else an array of
/// `{name, critical = true when set, value | error = true}`. `first_error`
/// gets the first error the printing raised, which the C leaves queued.
fn extensions_table<'gc>(
    ctx: Context<'gc>,
    cert: &Cert,
    first_error: &mut Option<u32>,
) -> Result<Option<Table<'gc>>, Failure> {
    let Some(exts) = cert.extensions.as_ref().filter(|e| !e.is_empty()) else {
        return Ok(None);
    };
    let arr = Table::new(&ctx);
    for (i, e) in exts.iter().enumerate() {
        let t = Table::new(&ctx);
        let Some(name) = objects::obj2txt(&e.oid, false) else {
            return Err(Failure::Lua(Fail::err(EXT_NAME_ERROR)));
        };
        // A 256-byte buffer: a longer name is its first 255 characters and
        // the NUL `OBJ_obj2txt` ended them with, 256 bytes in all.
        let mut bytes = name.into_bytes();
        if bytes.len() >= 256 {
            bytes.truncate(255);
            bytes.push(0);
        }
        t.set_field(ctx, "name", string(ctx, &bytes));
        if e.is_critical() {
            t.set_field(ctx, "critical", true);
        }
        let printed = ext::print(&e.oid, &e.value);
        if first_error.is_none() {
            *first_error = printed.error;
        }
        match printed.value {
            Some(text) => t.set_field(ctx, "value", string(ctx, &text)),
            None => t.set_field(ctx, "error", true),
        };
        let _ = arr.set(
            ctx,
            i64::try_from(i.saturating_add(1)).unwrap_or(i64::MAX),
            t,
        );
    }
    Ok(Some(arr))
}

/// `lua_push_ecdhparams` (`nse_ssl_cert.cc:456-523`, OpenSSL 3 branch):
/// `{ curve_params = { curve = NAME, ec_curve_type = "namedcurve" } }` for a
/// group OpenSSL names, else the field type of explicit parameters.
fn ecdhparams<'gc>(ctx: Context<'gc>, info: EcInfo) -> Table<'gc> {
    let outer = Table::new(&ctx);
    let params = Table::new(&ctx);
    match info {
        EcInfo::Named(nid) => {
            if let Some(name) = super::ec::curve_name(nid) {
                params.set_field(ctx, "curve", name);
            }
            params.set_field(ctx, "ec_curve_type", "namedcurve");
        }
        EcInfo::Explicit { char2 } => {
            params.set_field(
                ctx,
                "ec_curve_type",
                if char2 {
                    "explicit_char2"
                } else {
                    "explicit_prime"
                },
            );
        }
    }
    outer.set_field(ctx, "curve_params", params);
    outer
}
