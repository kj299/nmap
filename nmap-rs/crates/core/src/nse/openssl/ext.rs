//! `X509V3_EXT_print(out, ext, 0, 0)` (OpenSSL 3.0.13, `crypto/x509/v3_prn.c`
//! and the methods `standard_exts.h` lists): an extension's value as the text
//! nmap puts under `value`, or `None` where it returns 0 and nmap sets
//! `error = true` (`nse_ssl_cert.cc:253-262`).
//!
//! **The method** is found by the OID's NID (`X509V3_EXT_get`). An extension
//! OpenSSL has no method for is an error with nothing raised
//! (`unknown_ext_print` with flag 0). Otherwise its value is decoded with
//! the method's template (`ASN1_item_d2i` over the OCTET STRING's content;
//! bytes after the item are ignored) or its own `d2i`; a value that does not
//! decode is an error, the decoder's errors left on the queue. Then the
//! method's `i2s` (`%s` of the string: up to its first NUL), `i2v` (a list
//! printed by `X509V3_EXT_val_prn`: `name:value` items joined by `, `, or by
//! newlines for a `MULTILINE` method; an empty list is `<EMPTY>` and a
//! newline; no list is an error) or `i2r` (which prints itself and may fail).
//!
//! **Errors.** The C prints the oldest error queued when the key then fails
//! (`cert`), so each print reports the first error it raised ([`Printed`]),
//! including one a printer raises and then succeeds anyway (an integer too
//! large for `ASN1_INTEGER_get`, an otherName value with a NUL).
//!
//! **Quirks kept** (each the C's, each in the corpus):
//! - the OCSP nonce, archive cutoff, invalidity date and hold instruction
//!   printers start with `BIO_printf("%*s", 0, "")`, which writes nothing,
//!   returns 0 and so fails: those extensions are always errors (after their
//!   value is decoded);
//! - `i2v_GENERAL_NAME` refuses an email, DNS or URI name with a NUL, raising
//!   "malloc failure";
//! - `i2v_AUTHORITY_KEYID` names the key id `keyid` only when an issuer or
//!   serial follows, and prints the serial's magnitude, not its sign;
//! - `ASN1_ENUMERATED_get` is `0xffffffff` past eight octets;
//! - the admission printer names an OID OpenSSL does not know `undefined`.
//!
//! **Arithmetic** is on lengths and offsets inside slices in hand (the TLS
//! encoding of SCTs is bounds-checked before each read).
#![allow(clippy::arithmetic_side_effects)]

use super::asn1::{self, bit, tag, Bad, Field, Prim, Res, CONTEXT, UNIVERSAL};
use super::err::{self, *};
use super::objects::{self, nid_of};
use super::text::{self, cstr, Int};
use super::x509::{self, explicit, mstring, seq_of, NameEntry, Seq};

/// The error queue as far as nmap reads it: the first error raised.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Errs(pub Option<u32>);

impl Errs {
    /// `ERR_raise`: kept if it is the first.
    pub fn raise(&mut self, code: u32) {
        if code != 0 && self.0.is_none() {
            self.0 = Some(code);
        }
    }
}

/// What printing one extension gives nmap.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Printed {
    /// The text, or `None` for `error = true`.
    pub value: Option<Vec<u8>>,
    /// The first error raised on the way, if any.
    pub error: Option<u32>,
}

/// `X509V3_EXT_print(out, ext, 0, 0)` on an extension's OID and value.
#[must_use]
pub fn print(oid: &[u8], value: &[u8]) -> Printed {
    let mut e = Errs::default();
    let value = print_nid(nid_of(oid), value, &mut e);
    Printed { value, error: e.0 }
}

// ---- NIDs (obj_mac.num) ----------------------------------------------------------

const NID_NETSCAPE_CERT_TYPE: u16 = 71;
const NID_NETSCAPE_BASE_URL: u16 = 72;
const NID_NETSCAPE_COMMENT: u16 = 78;
const NID_SUBJECT_KEY_IDENTIFIER: u16 = 82;
const NID_KEY_USAGE: u16 = 83;
const NID_PRIVATE_KEY_USAGE_PERIOD: u16 = 84;
const NID_SUBJECT_ALT_NAME: u16 = 85;
const NID_ISSUER_ALT_NAME: u16 = 86;
const NID_BASIC_CONSTRAINTS: u16 = 87;
const NID_CRL_NUMBER: u16 = 88;
const NID_CERTIFICATE_POLICIES: u16 = 89;
const NID_AUTHORITY_KEY_IDENTIFIER: u16 = 90;
const NID_CRL_DISTRIBUTION_POINTS: u16 = 103;
const NID_EXT_KEY_USAGE: u16 = 126;
const NID_DELTA_CRL: u16 = 140;
const NID_CRL_REASON: u16 = 141;
const NID_INVALIDITY_DATE: u16 = 142;
const NID_SXNET: u16 = 143;
const NID_ID_QT_CPS: u16 = 164;
const NID_ID_QT_UNOTICE: u16 = 165;
const NID_INFO_ACCESS: u16 = 177;
const NID_SBGP_IPADDRBLOCK: u16 = 290;
const NID_SBGP_AUTONOMOUSSYSNUM: u16 = 291;
const NID_OCSP_NONCE: u16 = 366;
const NID_OCSP_CRLID: u16 = 367;
const NID_OCSP_ACCEPTABLE_RESPONSES: u16 = 368;
const NID_OCSP_NOCHECK: u16 = 369;
const NID_OCSP_ARCHIVE_CUTOFF: u16 = 370;
const NID_OCSP_SERVICE_LOCATOR: u16 = 371;
const NID_SINFO_ACCESS: u16 = 398;
const NID_POLICY_CONSTRAINTS: u16 = 401;
const NID_HOLD_INSTRUCTION_CODE: u16 = 430;
const NID_MS_UPN: u16 = 649;
const NID_PROXY_CERT_INFO: u16 = 663;
const NID_NAME_CONSTRAINTS: u16 = 666;
const NID_SHA256_WITH_RSA: u16 = 668;
const NID_POLICY_MAPPINGS: u16 = 747;
const NID_INHIBIT_ANY_POLICY: u16 = 748;
const NID_ISSUING_DISTRIBUTION_POINT: u16 = 770;
const NID_CERTIFICATE_ISSUER: u16 = 771;
const NID_ECDSA_WITH_SHA256: u16 = 794;
const NID_FRESHEST_CRL: u16 = 857;
const NID_CT_PRECERT_SCTS: u16 = 951;
const NID_CT_PRECERT_POISON: u16 = 952;
const NID_CT_CERT_SCTS: u16 = 954;
const NID_SUBJECT_SIGN_TOOL: u16 = 1007;
const NID_ISSUER_SIGN_TOOL: u16 = 1008;
const NID_TLSFEATURE: u16 = 1020;
const NID_X509_EXT_ADMISSION: u16 = 1093;
const NID_ID_ON_SMTPUTF8MAILBOX: u16 = 1208;
const NID_XMPPADDR: u16 = 1209;
const NID_SRVNAME: u16 = 1210;
const NID_NAIREALM: u16 = 1211;

/// Decode with `f`, raising its error and giving `None` where it fails.
fn d2i<T>(e: &mut Errs, f: impl FnOnce() -> Res<T>) -> Option<T> {
    f().map_err(|b| e.raise(b.0)).ok()
}

/// The method for `nid`, run on the extension's value `p`.
fn print_nid(nid: u16, p: &[u8], e: &mut Errs) -> Option<Vec<u8>> {
    let mut out = Vec::new();
    match nid {
        NID_NETSCAPE_CERT_TYPE | NID_KEY_USAGE => {
            let (_, bits) = d2i(e, || item(bit_string(p, None, false)))?;
            let table = if nid == NID_KEY_USAGE {
                KEY_USAGE
            } else {
                NS_CERT_TYPE
            };
            let mut list = None;
            for &(n, name) in table {
                if get_bit(&bits, n) {
                    add_value(&mut list, Some(name.as_bytes()), None::<&[u8]>);
                }
            }
            val_prn(&mut out, list?, false);
        }
        NID_NETSCAPE_BASE_URL..=NID_NETSCAPE_COMMENT => {
            let s = d2i(e, || item(string(p, tag::IA5STRING, None, false)))?;
            if s.is_empty() {
                return None;
            }
            out.extend_from_slice(cstr(&s));
        }
        NID_SUBJECT_KEY_IDENTIFIER => {
            let s = d2i(e, || item(string(p, tag::OCTET_STRING, None, false)))?;
            out.extend(text::buf2hexstr(&s));
        }
        NID_PRIVATE_KEY_USAGE_PERIOD => {
            let (before, after) = d2i(e, || pkey_usage_period(p))?;
            if let Some(t) = &before {
                out.extend_from_slice(b"Not Before: ");
                text::time_print(&mut out, tag::GENERALIZEDTIME, t);
                if after.is_some() {
                    out.extend_from_slice(b", ");
                }
            }
            if let Some(t) = &after {
                out.extend_from_slice(b"Not After: ");
                text::time_print(&mut out, tag::GENERALIZEDTIME, t);
            }
        }
        NID_SUBJECT_ALT_NAME | NID_ISSUER_ALT_NAME | NID_CERTIFICATE_ISSUER => {
            let gens = d2i(e, || item(general_names(p, SEQ, false)))?;
            let list = i2v_general_names(&gens, None, e)?;
            val_prn(&mut out, list, false);
        }
        NID_BASIC_CONSTRAINTS => {
            let (ca, pathlen) = d2i(e, || basic_constraints(p))?;
            let mut list = None;
            let ca: &[u8] = if ca != 0 { b"TRUE" } else { b"FALSE" };
            add_value(&mut list, Some(b"CA"), Some(ca));
            add_value_int(&mut list, b"pathlen", pathlen.as_ref());
            val_prn(&mut out, list?, false);
        }
        NID_CRL_NUMBER | NID_DELTA_CRL | NID_INHIBIT_ANY_POLICY => {
            let v = d2i(e, || item(integer(p, None, false)))?;
            out.extend(cstr(&text::i2s_integer(&v)));
        }
        NID_CERTIFICATE_POLICIES => {
            let pols = d2i(e, || item(seq_of(p, SEQ, false, policy_info)))?;
            i2r_certpol(&mut out, &pols);
        }
        NID_AUTHORITY_KEY_IDENTIFIER => {
            let akid = d2i(e, || authority_keyid(p))?;
            let list = i2v_authority_keyid(&akid, e)?;
            val_prn(&mut out, list, true);
        }
        NID_CRL_DISTRIBUTION_POINTS | NID_FRESHEST_CRL => {
            let points = d2i(e, || item(seq_of(p, SEQ, false, dist_point)))?;
            for (i, dp) in points.iter().enumerate() {
                if i > 0 {
                    out.push(b'\n');
                }
                if let Some(dpn) = &dp.name {
                    print_distpoint(&mut out, dpn);
                }
                if let Some(r) = &dp.reasons {
                    print_reasons(&mut out, "Reasons", r);
                }
                if let Some(gens) = &dp.crl_issuer {
                    out.extend_from_slice(b"CRL Issuer:\n");
                    print_gens(&mut out, gens);
                }
            }
        }
        NID_EXT_KEY_USAGE | NID_OCSP_ACCEPTABLE_RESPONSES => {
            let oids = d2i(e, || item(seq_of(p, SEQ, false, |q| req(object(q, None, false)))))?;
            let mut list = None;
            for o in &oids {
                add_value(&mut list, None::<&[u8]>, Some(&text::i2t(o, 80)));
            }
            val_prn(&mut out, list?, false);
        }
        NID_CRL_REASON => {
            let v = d2i(e, || item(enumerated(p)))?;
            let n = text::enumerated_get(&v, e);
            match CRL_REASONS.iter().find(|&&(k, _)| k == n) {
                Some(&(_, name)) => out.extend_from_slice(name.as_bytes()),
                None => out.extend(cstr(&text::i2s_integer(&v))),
            }
        }
        NID_INVALIDITY_DATE | NID_OCSP_ARCHIVE_CUTOFF => {
            d2i(e, || item(string(p, tag::GENERALIZEDTIME, None, false)))?;
            return None;
        }
        NID_HOLD_INSTRUCTION_CODE => {
            d2i(e, || item(object(p, None, false)))?;
            return None;
        }
        NID_OCSP_NONCE => return None,
        NID_SXNET => {
            let (version, ids) = d2i(e, || sxnet(p))?;
            match text::get_int64(&version, e).filter(|&v| v != i64::MAX) {
                Some(v) => out.extend_from_slice(
                    format!("Version: {} (0x{:X})", v + 1, v as u64).as_bytes(),
                ),
                None => out.extend_from_slice(b"Version: <unsupported>"),
            }
            for (zone, user) in &ids {
                out.extend_from_slice(b"\nZone: ");
                out.extend(cstr(&text::i2s_integer(zone)));
                out.extend_from_slice(b", User: ");
                text::string_print(&mut out, user);
            }
        }
        NID_INFO_ACCESS | NID_SINFO_ACCESS => {
            let ads = d2i(e, || item(seq_of(p, SEQ, false, access_description)))?;
            let list = i2v_info_access(&ads, e)?;
            val_prn(&mut out, list, true);
        }
        NID_SBGP_IPADDRBLOCK => {
            let fams = d2i(e, || item(seq_of(p, SEQ, false, ip_address_family)))?;
            if !i2r_ip_addr_blocks(&mut out, &fams) {
                return None;
            }
        }
        NID_SBGP_AUTONOMOUSSYSNUM => {
            let (asnum, rdi) = d2i(e, || as_identifiers(p))?;
            as_id_choice(&mut out, asnum.as_ref(), "Autonomous System Numbers");
            as_id_choice(&mut out, rdi.as_ref(), "Routing Domain Identifiers");
        }
        NID_OCSP_CRLID => {
            let (url, num, time) = d2i(e, || ocsp_crlid(p))?;
            if let Some(u) = &url {
                out.extend_from_slice(b"crlUrl: ");
                text::string_print(&mut out, u);
                out.push(b'\n');
            }
            if let Some(n) = &num {
                out.extend_from_slice(b"crlNum: ");
                text::i2a_integer(&mut out, n);
                out.push(b'\n');
            }
            if let Some(t) = &time {
                out.extend_from_slice(b"crlTime: ");
                text::time_print(&mut out, tag::GENERALIZEDTIME, t);
                out.push(b'\n');
            }
        }
        NID_OCSP_NOCHECK => {
            d2i(e, || item(null(p)))?;
        }
        NID_OCSP_SERVICE_LOCATOR => {
            let (issuer, locator) = d2i(e, || ocsp_serviceloc(p))?;
            out.extend_from_slice(b"Issuer: ");
            if text::name_print_ex(&mut out, &issuer) == 0 {
                return None;
            }
            for (method, location) in locator.iter().flatten() {
                out.push(b'\n');
                text::i2a_object(&mut out, method);
                out.extend_from_slice(b" - ");
                general_name_print(&mut out, location);
            }
        }
        NID_POLICY_CONSTRAINTS => {
            let (require, inhibit) = d2i(e, || policy_constraints(p))?;
            let mut list = None;
            add_value_int(&mut list, b"Require Explicit Policy", require.as_ref());
            add_value_int(&mut list, b"Inhibit Policy Mapping", inhibit.as_ref());
            val_prn(&mut out, list?, false);
        }
        NID_PROXY_CERT_INFO => {
            let (pathlen, language, policy) = d2i(e, || proxy_cert_info(p))?;
            out.extend_from_slice(b"Path Length Constraint: ");
            match &pathlen {
                Some(n) => text::i2a_integer(&mut out, n),
                None => out.extend_from_slice(b"infinite"),
            }
            out.extend_from_slice(b"\nPolicy Language: ");
            text::i2a_object(&mut out, &language);
            if let Some(t) = &policy {
                out.extend_from_slice(b"\nPolicy Text: ");
                out.extend_from_slice(cstr(t));
            }
        }
        NID_NAME_CONSTRAINTS => {
            let (permitted, excluded) = d2i(e, || name_constraints(p))?;
            name_constraints_print(&mut out, permitted.as_deref(), "Permitted");
            if permitted.is_some() && excluded.is_some() {
                out.push(b'\n');
            }
            name_constraints_print(&mut out, excluded.as_deref(), "Excluded");
        }
        NID_POLICY_MAPPINGS => {
            let maps = d2i(e, || item(seq_of(p, SEQ, false, policy_mapping)))?;
            let mut list = None;
            for (issuer, subject) in &maps {
                add_value(
                    &mut list,
                    Some(&text::i2t(issuer, 80)),
                    Some(&text::i2t(subject, 80)),
                );
            }
            val_prn(&mut out, list?, false);
        }
        NID_ISSUING_DISTRIBUTION_POINT => {
            let idp = d2i(e, || issuing_dist_point(p))?;
            i2r_idp(&mut out, &idp);
        }
        NID_CT_PRECERT_SCTS | NID_CT_CERT_SCTS => {
            let scts = d2i(e, || d2i_sct_list(p))?;
            for (i, sct) in scts.iter().enumerate() {
                if i > 0 {
                    out.push(b'\n');
                }
                sct_print(&mut out, sct);
            }
        }
        NID_CT_PRECERT_POISON => {
            d2i(e, || item(null(p)))?;
            out.extend_from_slice(b"NULL");
        }
        NID_SUBJECT_SIGN_TOOL => {
            let s = d2i(e, || item(string(p, tag::UTF8STRING, None, false)))?;
            if s.is_empty() {
                e.raise(err::pack(LIB_X509V3, ERR_R_PASSED_NULL_PARAMETER));
                return None;
            }
            out.extend_from_slice(cstr(&s));
        }
        NID_ISSUER_SIGN_TOOL => {
            let tools = d2i(e, || issuer_sign_tool(p))?;
            let labels = ["signTool    : ", "cATool      : ", "signToolCert: ", "cAToolCert  : "];
            for (i, (label, v)) in labels.iter().zip(&tools).enumerate() {
                if i > 0 {
                    out.push(b'\n');
                }
                out.extend_from_slice(label.as_bytes());
                out.extend_from_slice(v);
            }
        }
        NID_TLSFEATURE => {
            let ints = d2i(e, || item(seq_of(p, SEQ, false, |q| req(integer(q, None, false)))))?;
            let mut list = None;
            for v in &ints {
                match text::integer_get(v, e) {
                    5 => add_value(&mut list, None::<&[u8]>, Some(b"status_request")),
                    17 => add_value(&mut list, None::<&[u8]>, Some(b"status_request_v2")),
                    _ => add_value(&mut list, None::<&[u8]>, Some(&text::i2s_integer(v))),
                }
            }
            val_prn(&mut out, list?, false);
        }
        NID_X509_EXT_ADMISSION => {
            let adm = d2i(e, || admission_syntax(p))?;
            if !i2r_admission_syntax(&mut out, &adm) {
                return None;
            }
        }
        _ => return None,
    }
    Some(out)
}

// ---- the templates -----------------------------------------------------------------

/// SEQUENCE OF's tag.
const SEQ: (u32, u8) = (tag::SEQUENCE, UNIVERSAL);

/// A required item's value (the reader never gives `None` when not
/// optional).
fn req<T>(f: Field<T>) -> Res<(T, usize)> {
    f?.ok_or(Bad(0))
}

/// A whole extension value's item (`ASN1_item_d2i`: what follows it is
/// ignored).
fn item<T>(f: Field<T>) -> Res<T> {
    req(f).map(|(v, _)| v)
}

/// A context tag `[n]`.
const fn ctx(n: u32) -> Option<(u32, u8)> {
    Some((n, CONTEXT))
}

/// A string type's content (OCTET STRING, IA5String, UTF8String,
/// GeneralizedTime ...), under an IMPLICIT tag if given.
fn string(p: &[u8], utype: u32, imp: Option<(u32, u8)>, opt: bool) -> Field<Vec<u8>> {
    Ok(asn1::primitive(p, utype, imp, opt)?.map(|(v, n)| match v {
        Prim::Str { data, .. } => (data, n),
        _ => unreachable!("a string type decodes to Prim::Str"),
    }))
}

/// An INTEGER.
fn integer(p: &[u8], imp: Option<(u32, u8)>, opt: bool) -> Field<Int> {
    Ok(asn1::primitive(p, tag::INTEGER, imp, opt)?
        .map(|(v, n)| (Int::from_prim(&v).unwrap_or_else(|| unreachable!()), n)))
}

/// An ENUMERATED.
fn enumerated(p: &[u8]) -> Field<Int> {
    Ok(asn1::primitive(p, tag::ENUMERATED, None, false)?
        .map(|(v, n)| (Int::from_prim(&v).unwrap_or_else(|| unreachable!()), n)))
}

/// An OBJECT IDENTIFIER's content octets.
fn object(p: &[u8], imp: Option<(u32, u8)>, opt: bool) -> Field<Vec<u8>> {
    Ok(asn1::primitive(p, tag::OBJECT, imp, opt)?.map(|(v, n)| match v {
        Prim::Oid(c) => (c, n),
        _ => unreachable!("OBJECT decodes to Prim::Oid"),
    }))
}

/// A BOOLEAN's octet.
fn boolean(p: &[u8], imp: Option<(u32, u8)>, opt: bool) -> Field<u8> {
    Ok(asn1::primitive(p, tag::BOOLEAN, imp, opt)?.map(|(v, n)| match v {
        Prim::Bool(b) => (b, n),
        _ => unreachable!("BOOLEAN decodes to Prim::Bool"),
    }))
}

/// A NULL.
fn null(p: &[u8]) -> Field<()> {
    Ok(asn1::primitive(p, tag::NULL, None, false)?.map(|(_, n)| ((), n)))
}

/// A BIT STRING: the unused-bits count and the masked data.
fn bit_string(p: &[u8], imp: Option<(u32, u8)>, opt: bool) -> Field<(u8, Vec<u8>)> {
    x509::bit_string(p, imp, opt)
}

/// `ASN1_BIT_STRING_get_bit`.
fn get_bit(data: &[u8], n: usize) -> bool {
    data.get(n / 8).is_some_and(|&b| b & (0x80 >> (n % 8)) != 0)
}

/// `DIRECTORYSTRING`, `DISPLAYTEXT`: a multi-string, required.
fn mstr(mask: u32) -> impl Fn(&[u8]) -> Res<(Prim, usize)> {
    move |q| req(mstring(q, mask, false))
}

/// A `GENERAL_NAME`.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Gn {
    Other { oid: Vec<u8>, value: Prim },
    Email(Vec<u8>),
    Dns(Vec<u8>),
    X400,
    Dir(Vec<NameEntry>),
    Edi,
    Uri(Vec<u8>),
    Ip(Vec<u8>),
    Rid(Vec<u8>),
}

/// The `GENERAL_NAME` CHOICE: each alternative tried in turn as OPTIONAL
/// (`asn1_item_embed_d2i`'s CHOICE case); one that matches its tag and fails
/// fails the whole; none matching is "no matching choice type" unless the
/// CHOICE itself is optional.
fn general_name(p: &[u8], opt: bool) -> Field<Gn> {
    if let Some(mut s) = Seq::open(p, ctx(0), true)? {
        let oid = s.req(false, |q, o| object(q, None, o))?;
        let value = s.req(true, |q, o| explicit(q, 0, CONTEXT, o, asn1::any))?;
        let n = s.finish()?;
        return Ok(Some((Gn::Other { oid, value }, n)));
    }
    if let Some((v, n)) = string(p, tag::IA5STRING, ctx(1), true)? {
        return Ok(Some((Gn::Email(v), n)));
    }
    if let Some((v, n)) = string(p, tag::IA5STRING, ctx(2), true)? {
        return Ok(Some((Gn::Dns(v), n)));
    }
    if let Some((_, n)) = asn1::primitive(p, tag::SEQUENCE, ctx(3), true)? {
        return Ok(Some((Gn::X400, n)));
    }
    if let Some((v, n)) = explicit(p, 4, CONTEXT, true, |q| req(x509::name(q, false)))? {
        return Ok(Some((Gn::Dir(v), n)));
    }
    if let Some(mut s) = Seq::open(p, ctx(5), true)? {
        s.field(true, false, |q, o| {
            explicit(q, 0, CONTEXT, o, mstr(bit::DIRECTORYSTRING))
        })?;
        s.req(true, |q, o| explicit(q, 1, CONTEXT, o, mstr(bit::DIRECTORYSTRING)))?;
        let n = s.finish()?;
        return Ok(Some((Gn::Edi, n)));
    }
    if let Some((v, n)) = string(p, tag::IA5STRING, ctx(6), true)? {
        return Ok(Some((Gn::Uri(v), n)));
    }
    if let Some((v, n)) = string(p, tag::OCTET_STRING, ctx(7), true)? {
        return Ok(Some((Gn::Ip(v), n)));
    }
    if let Some((v, n)) = object(p, ctx(8), true)? {
        return Ok(Some((Gn::Rid(v), n)));
    }
    if opt {
        Ok(None)
    } else {
        Err(Bad::asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE))
    }
}

/// `GENERAL_NAMES` (or an IMPLICIT SEQUENCE OF `GENERAL_NAME`).
fn general_names(p: &[u8], want: (u32, u8), opt: bool) -> Field<Vec<Gn>> {
    seq_of(p, want, opt, |q| req(general_name(q, false)))
}

/// `PKEY_USAGE_PERIOD`: `{ [0] IMPLICIT GeneralizedTime OPTIONAL, [1] ... }`.
fn pkey_usage_period(p: &[u8]) -> Res<(Option<Vec<u8>>, Option<Vec<u8>>)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let a = s.field(true, false, |q, o| string(q, tag::GENERALIZEDTIME, ctx(0), o))?;
    let b = s.field(true, true, |q, o| string(q, tag::GENERALIZEDTIME, ctx(1), o))?;
    s.finish()?;
    Ok((a, b))
}

/// `BASIC_CONSTRAINTS`: `{ BOOLEAN DEFAULT FALSE, INTEGER OPTIONAL }`.
fn basic_constraints(p: &[u8]) -> Res<(u8, Option<Int>)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let ca = s.field(true, false, |q, o| boolean(q, None, o))?;
    let pathlen = s.field(true, true, |q, o| integer(q, None, o))?;
    s.finish()?;
    Ok((ca.unwrap_or(0), pathlen))
}

/// A `POLICYQUALINFO` (`{ OBJECT, ANY DEFINED BY it }`).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Qual {
    Cps(Vec<u8>),
    Notice(Notice),
    Other(Vec<u8>),
}

/// A `USERNOTICE`: the notice reference's organization and numbers, and the
/// explicit text.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Notice {
    noticeref: Option<(Vec<u8>, Vec<Int>)>,
    exptext: Option<Vec<u8>>,
}

/// `POLICYINFO`: `{ OBJECT, SEQUENCE OF POLICYQUALINFO OPTIONAL }`.
fn policy_info(p: &[u8]) -> Res<((Vec<u8>, Option<Vec<Qual>>), usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let oid = s.req(false, |q, o| object(q, None, o))?;
    let quals = s.field(true, true, |q, o| seq_of(q, SEQ, o, policy_qual_info))?;
    Ok(((oid, quals), s.finish()?))
}

/// `POLICYQUALINFO`, its second field chosen by the first's NID (`ASN1_ADB`).
fn policy_qual_info(p: &[u8]) -> Res<(Qual, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let oid = s.req(false, |q, o| object(q, None, o))?;
    let q = match nid_of(&oid) {
        NID_ID_QT_CPS => Qual::Cps(s.req(true, |q, o| string(q, tag::IA5STRING, None, o))?),
        NID_ID_QT_UNOTICE => Qual::Notice(s.req(true, |q, o| user_notice(q, o))?),
        _ => {
            s.req(true, |q, _| asn1::any(q).map(Some))?;
            Qual::Other(oid)
        }
    };
    Ok((q, s.finish()?))
}

/// `USERNOTICE`: `{ NOTICEREF OPTIONAL, DISPLAYTEXT OPTIONAL }`.
fn user_notice(p: &[u8], opt: bool) -> Field<Notice> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let noticeref = s.field(true, false, |q, o| {
        let Some(mut r) = Seq::open(q, None, o)? else {
            return Ok(None);
        };
        let org = r.req(false, |q, o| mstring(q, bit::DISPLAYTEXT, o))?;
        let nos = r.req(true, |q, o| seq_of(q, SEQ, o, |q| req(integer(q, None, false))))?;
        let n = r.finish()?;
        Ok(Some(((x509::string_data(&org).to_vec(), nos), n)))
    })?;
    let exptext = s.field(true, true, |q, o| mstring(q, bit::DISPLAYTEXT, o))?;
    let n = s.finish()?;
    Ok(Some((
        Notice {
            noticeref,
            exptext: exptext.map(|v| x509::string_data(&v).to_vec()),
        },
        n,
    )))
}

/// `AUTHORITY_KEYID`: `{ [0] IMPLICIT OCTET STRING OPTIONAL, [1] IMPLICIT
/// SEQUENCE OF GENERAL_NAME OPTIONAL, [2] IMPLICIT INTEGER OPTIONAL }`.
type Akid = (Option<Vec<u8>>, Option<Vec<Gn>>, Option<Int>);

fn authority_keyid(p: &[u8]) -> Res<Akid> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let keyid = s.field(true, false, |q, o| string(q, tag::OCTET_STRING, ctx(0), o))?;
    let issuer = s.field(true, false, |q, o| general_names(q, (1, CONTEXT), o))?;
    let serial = s.field(true, true, |q, o| integer(q, ctx(2), o))?;
    s.finish()?;
    Ok((keyid, issuer, serial))
}

/// A `DIST_POINT_NAME`: full name, or a name relative to the issuer (its
/// entries, which `X509_NAME_ENTRY` gives set 0).
#[derive(Clone, Debug, PartialEq, Eq)]
enum Dpn {
    Full(Vec<Gn>),
    Relative(Vec<NameEntry>),
}

/// The `DIST_POINT_NAME` CHOICE: `[0] IMPLICIT SEQUENCE OF GENERAL_NAME` or
/// `[1] IMPLICIT SET OF X509_NAME_ENTRY`.
fn dist_point_name(p: &[u8]) -> Res<(Dpn, usize)> {
    if let Some((g, n)) = general_names(p, (0, CONTEXT), true)? {
        return Ok((Dpn::Full(g), n));
    }
    if let Some((ents, n)) = seq_of(p, (1, CONTEXT), true, x509::name_entry)? {
        let ents = ents
            .into_iter()
            .map(|(oid, value)| NameEntry { oid, value, set: 0 })
            .collect();
        return Ok((Dpn::Relative(ents), n));
    }
    Err(Bad::asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE))
}

/// A `DIST_POINT`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct DistPoint {
    name: Option<Dpn>,
    reasons: Option<Vec<u8>>,
    crl_issuer: Option<Vec<Gn>>,
}

/// `DIST_POINT`: `{ [0] EXPLICIT DIST_POINT_NAME OPTIONAL, [1] IMPLICIT BIT
/// STRING OPTIONAL, [2] IMPLICIT SEQUENCE OF GENERAL_NAME OPTIONAL }`.
fn dist_point(p: &[u8]) -> Res<(DistPoint, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let name = s.field(true, false, |q, o| explicit(q, 0, CONTEXT, o, dist_point_name))?;
    let reasons = s.field(true, false, |q, o| bit_string(q, ctx(1), o))?;
    let crl_issuer = s.field(true, true, |q, o| general_names(q, (2, CONTEXT), o))?;
    let n = s.finish()?;
    Ok((
        DistPoint {
            name,
            reasons: reasons.map(|(_, d)| d),
            crl_issuer,
        },
        n,
    ))
}

/// An `ISSUING_DIST_POINT`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Idp {
    name: Option<Dpn>,
    only_user: u8,
    only_ca: u8,
    only_some_reasons: Option<Vec<u8>>,
    indirect_crl: u8,
    only_attr: u8,
}

/// `ISSUING_DIST_POINT`: `{ [0] EXPLICIT DIST_POINT_NAME OPTIONAL, [1] ..
/// [5] IMPLICIT BOOLEAN DEFAULT FALSE but [3] IMPLICIT BIT STRING OPTIONAL }`.
fn issuing_dist_point(p: &[u8]) -> Res<Idp> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let name = s.field(true, false, |q, o| explicit(q, 0, CONTEXT, o, dist_point_name))?;
    let only_user = s.field(true, false, |q, o| boolean(q, ctx(1), o))?;
    let only_ca = s.field(true, false, |q, o| boolean(q, ctx(2), o))?;
    let reasons = s.field(true, false, |q, o| bit_string(q, ctx(3), o))?;
    let indirect = s.field(true, false, |q, o| boolean(q, ctx(4), o))?;
    let only_attr = s.field(true, true, |q, o| boolean(q, ctx(5), o))?;
    s.finish()?;
    Ok(Idp {
        name,
        only_user: only_user.unwrap_or(0),
        only_ca: only_ca.unwrap_or(0),
        only_some_reasons: reasons.map(|(_, d)| d),
        indirect_crl: indirect.unwrap_or(0),
        only_attr: only_attr.unwrap_or(0),
    })
}

/// `SXNET`: `{ INTEGER, SEQUENCE OF { INTEGER zone, OCTET STRING user } }`.
fn sxnet(p: &[u8]) -> Res<(Int, Vec<(Int, Vec<u8>)>)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let version = s.req(false, |q, o| integer(q, None, o))?;
    let ids = s.req(true, |q, o| {
        seq_of(q, SEQ, o, |q| {
            let mut s = Seq::open(q, None, false)?.ok_or(Bad(0))?;
            let zone = s.req(false, |q, o| integer(q, None, o))?;
            let user = s.req(true, |q, o| string(q, tag::OCTET_STRING, None, o))?;
            Ok(((zone, user), s.finish()?))
        })
    })?;
    s.finish()?;
    Ok((version, ids))
}

/// `ACCESS_DESCRIPTION`: `{ OBJECT, GENERAL_NAME }`.
fn access_description(p: &[u8]) -> Res<((Vec<u8>, Gn), usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let method = s.req(false, |q, o| object(q, None, o))?;
    let location = s.req(true, general_name)?;
    Ok(((method, location), s.finish()?))
}

/// An `IPAddressOrRange`: a prefix, or a range's ends (each a BIT STRING's
/// unused bits and data).
#[derive(Clone, Debug, PartialEq, Eq)]
enum AddrOrRange {
    Prefix((u8, Vec<u8>)),
    Range((u8, Vec<u8>), (u8, Vec<u8>)),
}

/// An `IPAddressFamily`: the family octets, and `None` for `inherit` or the
/// addresses.
type AddrFamily = (Vec<u8>, Option<Vec<AddrOrRange>>);

/// `IPAddressFamily`: `{ OCTET STRING, CHOICE { NULL, SEQUENCE OF CHOICE {
/// BIT STRING, SEQUENCE { BIT STRING, BIT STRING } } } }`.
fn ip_address_family(p: &[u8]) -> Res<(AddrFamily, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let afi = s.req(false, |q, o| string(q, tag::OCTET_STRING, None, o))?;
    let choice = s.req(true, |q, _| {
        if let Some((_, n)) = asn1::primitive(q, tag::NULL, None, true)? {
            return Ok(Some((None, n)));
        }
        if let Some((v, n)) = seq_of(q, SEQ, true, address_or_range)? {
            return Ok(Some((Some(v), n)));
        }
        Err(Bad::asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE))
    })?;
    Ok(((afi, choice), s.finish()?))
}

/// The `IPAddressOrRange` CHOICE.
fn address_or_range(p: &[u8]) -> Res<(AddrOrRange, usize)> {
    if let Some((b, n)) = bit_string(p, None, true)? {
        return Ok((AddrOrRange::Prefix(b), n));
    }
    if let Some(mut s) = Seq::open(p, None, true)? {
        let min = s.req(false, |q, o| bit_string(q, None, o))?;
        let max = s.req(true, |q, o| bit_string(q, None, o))?;
        let n = s.finish()?;
        return Ok((AddrOrRange::Range(min, max), n));
    }
    Err(Bad::asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE))
}

/// An `ASIdOrRange`: an id or a range's ends.
#[derive(Clone, Debug, PartialEq, Eq)]
enum AsIdOrRange {
    Id(Int),
    Range(Int, Int),
}

/// `ASIdentifiers`: `{ [0] EXPLICIT ASIdentifierChoice OPTIONAL, [1] ... }`,
/// each `None` inside for `inherit`.
type AsIds = (Option<Option<Vec<AsIdOrRange>>>, Option<Option<Vec<AsIdOrRange>>>);

fn as_identifiers(p: &[u8]) -> Res<AsIds> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let asnum = s.field(true, false, |q, o| explicit(q, 0, CONTEXT, o, as_id_choice_d2i))?;
    let rdi = s.field(true, true, |q, o| explicit(q, 1, CONTEXT, o, as_id_choice_d2i))?;
    s.finish()?;
    Ok((asnum, rdi))
}

/// The `ASIdentifierChoice` CHOICE: `NULL` or `SEQUENCE OF ASIdOrRange`.
fn as_id_choice_d2i(p: &[u8]) -> Res<(Option<Vec<AsIdOrRange>>, usize)> {
    if let Some((_, n)) = asn1::primitive(p, tag::NULL, None, true)? {
        return Ok((None, n));
    }
    if let Some((v, n)) = seq_of(p, SEQ, true, |q| {
        if let Some((i, n)) = integer(q, None, true)? {
            return Ok((AsIdOrRange::Id(i), n));
        }
        if let Some(mut s) = Seq::open(q, None, true)? {
            let min = s.req(false, |q, o| integer(q, None, o))?;
            let max = s.req(true, |q, o| integer(q, None, o))?;
            let n = s.finish()?;
            return Ok((AsIdOrRange::Range(min, max), n));
        }
        Err(Bad::asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE))
    })? {
        return Ok((Some(v), n));
    }
    Err(Bad::asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE))
}

/// `OCSP_CRLID`: `{ [0] EXPLICIT IA5String OPTIONAL, [1] EXPLICIT INTEGER
/// OPTIONAL, [2] EXPLICIT GeneralizedTime OPTIONAL }`.
type CrlId = (Option<Vec<u8>>, Option<Int>, Option<Vec<u8>>);

fn ocsp_crlid(p: &[u8]) -> Res<CrlId> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let url = s.field(true, false, |q, o| {
        explicit(q, 0, CONTEXT, o, |r| req(string(r, tag::IA5STRING, None, false)))
    })?;
    let num = s.field(true, false, |q, o| {
        explicit(q, 1, CONTEXT, o, |r| req(integer(r, None, false)))
    })?;
    let time = s.field(true, true, |q, o| {
        explicit(q, 2, CONTEXT, o, |r| {
            req(string(r, tag::GENERALIZEDTIME, None, false))
        })
    })?;
    s.finish()?;
    Ok((url, num, time))
}

/// `OCSP_SERVICELOC`: `{ X509_NAME, SEQUENCE OF ACCESS_DESCRIPTION OPTIONAL }`.
type ServiceLoc = (Vec<NameEntry>, Option<Vec<(Vec<u8>, Gn)>>);

fn ocsp_serviceloc(p: &[u8]) -> Res<ServiceLoc> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let issuer = s.req(false, x509::name)?;
    let locator = s.field(true, true, |q, o| seq_of(q, SEQ, o, access_description))?;
    s.finish()?;
    Ok((issuer, locator))
}

/// `POLICY_CONSTRAINTS`: `{ [0] IMPLICIT INTEGER OPTIONAL, [1] ... }`.
fn policy_constraints(p: &[u8]) -> Res<(Option<Int>, Option<Int>)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let a = s.field(true, false, |q, o| integer(q, ctx(0), o))?;
    let b = s.field(true, true, |q, o| integer(q, ctx(1), o))?;
    s.finish()?;
    Ok((a, b))
}

/// `PROXY_CERT_INFO_EXTENSION`: `{ INTEGER OPTIONAL, PROXY_POLICY { OBJECT,
/// OCTET STRING OPTIONAL } }`.
type ProxyCertInfo = (Option<Int>, Vec<u8>, Option<Vec<u8>>);

fn proxy_cert_info(p: &[u8]) -> Res<ProxyCertInfo> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let pathlen = s.field(true, false, |q, o| integer(q, None, o))?;
    let (language, policy) = s.req(true, |q, o| {
        let Some(mut r) = Seq::open(q, None, o)? else {
            return Ok(None);
        };
        let language = r.req(false, |q, o| object(q, None, o))?;
        let policy = r.field(true, true, |q, o| string(q, tag::OCTET_STRING, None, o))?;
        let n = r.finish()?;
        Ok(Some(((language, policy), n)))
    })?;
    s.finish()?;
    Ok((pathlen, language, policy))
}

/// `NAME_CONSTRAINTS`: `{ [0] IMPLICIT SEQUENCE OF GENERAL_SUBTREE OPTIONAL,
/// [1] ... }`; of each subtree, only the base is printed.
type NameConstraints = (Option<Vec<Gn>>, Option<Vec<Gn>>);

fn name_constraints(p: &[u8]) -> Res<NameConstraints> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let a = s.field(true, false, |q, o| seq_of(q, (0, CONTEXT), o, general_subtree))?;
    let b = s.field(true, true, |q, o| seq_of(q, (1, CONTEXT), o, general_subtree))?;
    s.finish()?;
    Ok((a, b))
}

/// `GENERAL_SUBTREE`: `{ GENERAL_NAME, [0] IMPLICIT INTEGER OPTIONAL, [1]
/// IMPLICIT INTEGER OPTIONAL }`.
fn general_subtree(p: &[u8]) -> Res<(Gn, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let base = s.req(false, general_name)?;
    s.field(true, false, |q, o| integer(q, ctx(0), o))?;
    s.field(true, true, |q, o| integer(q, ctx(1), o))?;
    Ok((base, s.finish()?))
}

/// `POLICY_MAPPING`: `{ OBJECT, OBJECT }`.
fn policy_mapping(p: &[u8]) -> Res<((Vec<u8>, Vec<u8>), usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let a = s.req(false, |q, o| object(q, None, o))?;
    let b = s.req(true, |q, o| object(q, None, o))?;
    Ok(((a, b), s.finish()?))
}

/// `ISSUER_SIGN_TOOL`: four UTF8Strings.
fn issuer_sign_tool(p: &[u8]) -> Res<[Vec<u8>; 4]> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let utf8 = |q: &[u8], o| string(q, tag::UTF8STRING, None, o);
    let a = s.req(false, utf8)?;
    let b = s.req(false, utf8)?;
    let c = s.req(false, utf8)?;
    let d = s.req(true, utf8)?;
    s.finish()?;
    Ok([a, b, c, d])
}

/// A `NAMING_AUTHORITY`: id, URL, text (`DIRECTORYSTRING`).
type NamingAuthority = (Option<Vec<u8>>, Option<Vec<u8>>, Option<Vec<u8>>);

/// `NAMING_AUTHORITY`: `{ OBJECT OPTIONAL, IA5String OPTIONAL,
/// DIRECTORYSTRING OPTIONAL }`.
fn naming_authority(p: &[u8], opt: bool) -> Field<NamingAuthority> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let id = s.field(true, false, |q, o| object(q, None, o))?;
    let url = s.field(true, false, |q, o| string(q, tag::IA5STRING, None, o))?;
    let text = s.field(true, true, |q, o| mstring(q, bit::DIRECTORYSTRING, o))?;
    let n = s.finish()?;
    Ok(Some((
        (id, url, text.map(|v| x509::string_data(&v).to_vec())),
        n,
    )))
}

/// A `PROFESSION_INFO`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ProfessionInfo {
    naming_authority: Option<NamingAuthority>,
    items: Vec<Vec<u8>>,
    oids: Option<Vec<Vec<u8>>>,
    registration_number: Option<Vec<u8>>,
}

/// `PROFESSION_INFO`: `{ [0] EXPLICIT NAMING_AUTHORITY OPTIONAL, SEQUENCE OF
/// DIRECTORYSTRING, SEQUENCE OF OBJECT OPTIONAL, PrintableString OPTIONAL,
/// OCTET STRING OPTIONAL }`.
fn profession_info(p: &[u8]) -> Res<(ProfessionInfo, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let naming_authority = s.field(true, false, |q, o| {
        explicit(q, 0, CONTEXT, o, |r| req(naming_authority(r, false)))
    })?;
    let items = s.req(false, |q, o| {
        seq_of(q, SEQ, o, |r| {
            mstr(bit::DIRECTORYSTRING)(r).map(|(v, n)| (x509::string_data(&v).to_vec(), n))
        })
    })?;
    let oids = s.field(true, false, |q, o| {
        seq_of(q, SEQ, o, |r| req(object(r, None, false)))
    })?;
    let registration_number =
        s.field(true, false, |q, o| string(q, tag::PRINTABLESTRING, None, o))?;
    s.field(true, true, |q, o| string(q, tag::OCTET_STRING, None, o))?;
    let n = s.finish()?;
    Ok((
        ProfessionInfo {
            naming_authority,
            items,
            oids,
            registration_number,
        },
        n,
    ))
}

/// An `ADMISSIONS`.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Admissions {
    authority: Option<Gn>,
    naming_authority: Option<NamingAuthority>,
    infos: Vec<ProfessionInfo>,
}

/// `ADMISSION_SYNTAX`: `{ GENERAL_NAME OPTIONAL, SEQUENCE OF ADMISSIONS {
/// [0] EXPLICIT GENERAL_NAME OPTIONAL, [1] EXPLICIT NAMING_AUTHORITY
/// OPTIONAL, SEQUENCE OF PROFESSION_INFO } }`.
fn admission_syntax(p: &[u8]) -> Res<(Option<Gn>, Vec<Admissions>)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let authority = s.field(true, false, general_name)?;
    let contents = s.req(true, |q, o| {
        seq_of(q, SEQ, o, |r| {
            let mut s = Seq::open(r, None, false)?.ok_or(Bad(0))?;
            let authority = s.field(true, false, |q, o| {
                explicit(q, 0, CONTEXT, o, |r| req(general_name(r, false)))
            })?;
            let naming_authority = s.field(true, false, |q, o| {
                explicit(q, 1, CONTEXT, o, |r| req(naming_authority(r, false)))
            })?;
            let infos = s.req(true, |q, o| seq_of(q, SEQ, o, profession_info))?;
            let n = s.finish()?;
            Ok((
                Admissions {
                    authority,
                    naming_authority,
                    infos,
                },
                n,
            ))
        })
    })?;
    s.finish()?;
    Ok((authority, contents))
}

// ---- CONF_VALUE lists ------------------------------------------------------------

/// A `CONF_VALUE`: a name, a value, either absent.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Cv {
    name: Option<Vec<u8>>,
    value: Option<Vec<u8>>,
}

/// A `STACK_OF(CONF_VALUE) *`: `None` is NULL.
type List = Option<Vec<Cv>>;

/// `X509V3_add_value` (`x509v3_add_len_value` with the value's `strlen`):
/// always succeeds here.
fn add_value<N: AsRef<[u8]>, V: AsRef<[u8]>>(list: &mut List, name: Option<N>, value: Option<V>) {
    list.get_or_insert_with(Vec::new).push(Cv {
        name: name.map(|n| n.as_ref().to_vec()),
        value: value.map(|v| cstr(v.as_ref()).to_vec()),
    });
}

/// `x509v3_add_len_value` with a counted value: a NUL in it fails with
/// "malloc failure" raised, and frees a list it would have created.
fn add_len_value(list: &mut List, name: &[u8], value: &[u8], e: &mut Errs) -> bool {
    if value.contains(&0) {
        e.raise(err::pack(LIB_X509V3, ERR_R_MALLOC_FAILURE));
        return false;
    }
    add_value(list, Some(name), Some(value));
    true
}

/// `X509V3_add_value_int`: nothing for an absent integer.
fn add_value_int(list: &mut List, name: &[u8], v: Option<&Int>) {
    if let Some(v) = v {
        add_value(list, Some(name), Some(&text::i2s_integer(v)));
    }
}

/// `X509V3_EXT_val_prn` at indent 0.
fn val_prn(out: &mut Vec<u8>, list: Vec<Cv>, multiline: bool) {
    if list.is_empty() {
        out.extend_from_slice(b"<EMPTY>\n");
    }
    for (i, cv) in list.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(if multiline { &b"\n"[..] } else { b", " });
        }
        match (&cv.name, &cv.value) {
            (None, v) => out.extend_from_slice(v.as_deref().unwrap_or_default()),
            (Some(n), None) => out.extend_from_slice(n),
            (Some(n), Some(v)) => {
                out.extend_from_slice(n);
                out.push(b':');
                out.extend_from_slice(v);
            }
        }
    }
}

/// The type of an otherName's value (`ASN1_TYPE`'s `type`).
fn any_type(v: &Prim) -> u32 {
    match v {
        Prim::Str { utype, .. } | Prim::Int { utype, .. } => *utype,
        Prim::Bits { .. } => tag::BIT_STRING,
        Prim::Encoded {
            utype: asn1::Utype::Sequence,
            ..
        } => tag::SEQUENCE,
        Prim::Encoded {
            utype: asn1::Utype::Set,
            ..
        } => tag::SET,
        Prim::Encoded { .. } => u32::MAX,
        Prim::Oid(_) => tag::OBJECT,
        Prim::Null => tag::NULL,
        Prim::Bool(_) => tag::BOOLEAN,
    }
}

/// `i2v_GENERAL_NAME`: one item added, or `false` (the list then as the C
/// leaves it does not matter: the caller fails).
fn i2v_general_name(gn: &Gn, list: &mut List, e: &mut Errs) -> bool {
    match gn {
        Gn::Other { oid, value } => {
            let data = x509::string_data(value);
            let ty = any_type(value);
            let known = match nid_of(oid) {
                NID_ID_ON_SMTPUTF8MAILBOX => Some(("othername: SmtpUTF8Mailbox:", tag::UTF8STRING)),
                NID_XMPPADDR => Some(("othername: XmppAddr:", tag::UTF8STRING)),
                NID_SRVNAME => Some(("othername: SRVName:", tag::IA5STRING)),
                NID_MS_UPN => Some(("othername: UPN:", tag::UTF8STRING)),
                NID_NAIREALM => Some(("othername: NAIRealm:", tag::UTF8STRING)),
                _ => None,
            };
            if let Some((name, want)) = known {
                return ty == want && add_len_value(list, name.as_bytes(), data, e);
            }
            let txt = objects::obj2txt(oid, false).filter(|t| !t.is_empty());
            let name = match txt {
                Some(t) => {
                    let mut n = b"othername: ".to_vec();
                    n.extend_from_slice(&t.as_bytes()[..t.len().min(255)]);
                    n.push(b':');
                    n
                }
                None => b"othername:".to_vec(),
            };
            if (ty == tag::IA5STRING || ty == tag::UTF8STRING)
                && add_len_value(list, &name, data, e)
            {
                return true;
            }
            add_value(list, Some(&name), Some(b"<unsupported>"));
            true
        }
        Gn::X400 => {
            add_value(list, Some(b"X400Name"), Some(b"<unsupported>"));
            true
        }
        Gn::Edi => {
            add_value(list, Some(b"EdiPartyName"), Some(b"<unsupported>"));
            true
        }
        Gn::Email(v) => add_len_value(list, b"email", v, e),
        Gn::Dns(v) => add_len_value(list, b"DNS", v, e),
        Gn::Uri(v) => add_len_value(list, b"URI", v, e),
        Gn::Dir(name) => match text::name_oneline(name, 256, e) {
            Some(s) => {
                add_value(list, Some(b"DirName"), Some(&s));
                true
            }
            None => false,
        },
        Gn::Ip(v) => {
            add_value(list, Some(b"IP Address"), Some(&text::ipaddr_to_asc(v)));
            true
        }
        Gn::Rid(oid) => {
            add_value(list, Some(b"Registered ID"), Some(&text::i2t(oid, 256)));
            true
        }
    }
}

/// `i2v_GENERAL_NAMES` onto `list`: `None` where a name fails; an empty list
/// where there were none and no list was given.
fn i2v_general_names(gens: &[Gn], mut list: List, e: &mut Errs) -> Option<Vec<Cv>> {
    for g in gens {
        if !i2v_general_name(g, &mut list, e) {
            return None;
        }
    }
    Some(list.unwrap_or_default())
}

/// `i2v_AUTHORITY_KEYID`.
fn i2v_authority_keyid(akid: &Akid, e: &mut Errs) -> Option<Vec<Cv>> {
    let (keyid, issuer, serial) = akid;
    let mut list = None;
    if let Some(k) = keyid {
        let name: Option<&[u8]> = if issuer.is_some() || serial.is_some() {
            Some(&b"keyid"[..])
        } else {
            None
        };
        add_value(&mut list, name, Some(&text::buf2hexstr(k)));
    }
    if let Some(gens) = issuer {
        let Some(l) = i2v_general_names(gens, list.take(), e) else {
            e.raise(err::pack(LIB_X509V3, ERR_R_X509_LIB));
            return None;
        };
        list = Some(l);
    }
    if let Some(s) = serial {
        add_value(&mut list, Some(b"serial"), Some(&text::buf2hexstr(&s.mag)));
    }
    list
}

/// `i2v_AUTHORITY_INFO_ACCESS`: each location's item renamed `method -
/// name` (the method in 79 characters at most).
fn i2v_info_access(ads: &[(Vec<u8>, Gn)], e: &mut Errs) -> Option<Vec<Cv>> {
    let mut list = None;
    for (method, location) in ads {
        if !i2v_general_name(location, &mut list, e) {
            e.raise(err::pack(LIB_X509V3, ERR_R_MALLOC_FAILURE));
            return None;
        }
        let cv = list.as_mut().and_then(|l| l.last_mut())?;
        let mut name = text::i2t(method, 80);
        name.extend_from_slice(b" - ");
        name.extend_from_slice(cv.name.as_deref().unwrap_or_default());
        cv.name = Some(name);
    }
    Some(list.unwrap_or_default())
}

// ---- the printers ---------------------------------------------------------------

/// `ns_cert_type_table`.
const NS_CERT_TYPE: &[(usize, &str)] = &[
    (0, "SSL Client"),
    (1, "SSL Server"),
    (2, "S/MIME"),
    (3, "Object Signing"),
    (4, "Unused"),
    (5, "SSL CA"),
    (6, "S/MIME CA"),
    (7, "Object Signing CA"),
];

/// `key_usage_type_table`.
const KEY_USAGE: &[(usize, &str)] = &[
    (0, "Digital Signature"),
    (1, "Non Repudiation"),
    (2, "Key Encipherment"),
    (3, "Data Encipherment"),
    (4, "Key Agreement"),
    (5, "Certificate Sign"),
    (6, "CRL Sign"),
    (7, "Encipher Only"),
    (8, "Decipher Only"),
];

/// `reason_flags` (`v3_crld.c`).
const REASON_FLAGS: &[(usize, &str)] = &[
    (0, "Unused"),
    (1, "Key Compromise"),
    (2, "CA Compromise"),
    (3, "Affiliation Changed"),
    (4, "Superseded"),
    (5, "Cessation Of Operation"),
    (6, "Certificate Hold"),
    (7, "Privilege Withdrawn"),
    (8, "AA Compromise"),
];

/// `crl_reasons` (`v3_enum.c`).
const CRL_REASONS: &[(i64, &str)] = &[
    (0, "Unspecified"),
    (1, "Key Compromise"),
    (2, "CA Compromise"),
    (3, "Affiliation Changed"),
    (4, "Superseded"),
    (5, "Cessation Of Operation"),
    (6, "Certificate Hold"),
    (8, "Remove From CRL"),
    (9, "Privilege Withdrawn"),
    (10, "AA Compromise"),
];

/// `GENERAL_NAME_print`.
fn general_name_print(out: &mut Vec<u8>, gn: &Gn) {
    match gn {
        Gn::Other { oid, value } => {
            let nid = nid_of(oid);
            let ty = any_type(value);
            let want = if nid == NID_SRVNAME {
                tag::IA5STRING
            } else {
                tag::UTF8STRING
            };
            let label = match nid {
                NID_ID_ON_SMTPUTF8MAILBOX => Some("othername:SmtpUTF8Mailbox:"),
                NID_XMPPADDR => Some("othername:XmppAddr:"),
                NID_SRVNAME => Some("othername:SRVName:"),
                NID_MS_UPN => Some("othername:UPN:"),
                NID_NAIREALM => Some("othername:NAIRealm:"),
                _ => None,
            };
            match label.filter(|_| ty == want) {
                Some(l) => {
                    out.extend_from_slice(l.as_bytes());
                    out.extend_from_slice(cstr(x509::string_data(value)));
                }
                None => out.extend_from_slice(b"othername:<unsupported>"),
            }
        }
        Gn::X400 => out.extend_from_slice(b"X400Name:<unsupported>"),
        Gn::Edi => out.extend_from_slice(b"EdiPartyName:<unsupported>"),
        Gn::Email(v) => {
            out.extend_from_slice(b"email:");
            text::string_print(out, v);
        }
        Gn::Dns(v) => {
            out.extend_from_slice(b"DNS:");
            text::string_print(out, v);
        }
        Gn::Uri(v) => {
            out.extend_from_slice(b"URI:");
            text::string_print(out, v);
        }
        Gn::Dir(name) => {
            out.extend_from_slice(b"DirName:");
            text::name_print_ex(out, name);
        }
        Gn::Ip(v) => {
            out.extend_from_slice(b"IP Address:");
            out.extend(text::ipaddr_to_asc(v));
        }
        Gn::Rid(oid) => {
            out.extend_from_slice(b"Registered ID:");
            text::i2a_object(out, oid);
        }
    }
}

/// `print_gens` (`v3_crld.c`) at indent 0.
fn print_gens(out: &mut Vec<u8>, gens: &[Gn]) {
    for (i, g) in gens.iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(b"  ");
        general_name_print(out, g);
    }
}

/// `print_distpoint` at indent 0.
fn print_distpoint(out: &mut Vec<u8>, dpn: &Dpn) {
    match dpn {
        Dpn::Full(gens) => {
            out.extend_from_slice(b"Full Name:\n");
            print_gens(out, gens);
        }
        Dpn::Relative(ents) => {
            out.extend_from_slice(b"Relative Name:\n  ");
            text::name_print_ex(out, ents);
            out.push(b'\n');
        }
    }
}

/// `print_reasons` at indent 0.
fn print_reasons(out: &mut Vec<u8>, rname: &str, bits: &[u8]) {
    out.extend_from_slice(format!("{rname}:\n  ").as_bytes());
    let mut first = true;
    for &(n, name) in REASON_FLAGS {
        if get_bit(bits, n) {
            if !first {
                out.extend_from_slice(b", ");
            }
            first = false;
            out.extend_from_slice(name.as_bytes());
        }
    }
    out.extend_from_slice(if first { &b"<EMPTY>\n"[..] } else { b"\n" });
}

/// `i2r_idp` at indent 0.
fn i2r_idp(out: &mut Vec<u8>, idp: &Idp) {
    if let Some(dpn) = &idp.name {
        print_distpoint(out, dpn);
    }
    if idp.only_user > 0 {
        out.extend_from_slice(b"Only User Certificates\n");
    }
    if idp.only_ca > 0 {
        out.extend_from_slice(b"Only CA Certificates\n");
    }
    if idp.indirect_crl > 0 {
        out.extend_from_slice(b"Indirect CRL\n");
    }
    if let Some(r) = &idp.only_some_reasons {
        print_reasons(out, "Only Some Reasons", r);
    }
    if idp.only_attr > 0 {
        out.extend_from_slice(b"Only Attribute Certificates\n");
    }
    if idp.name.is_none()
        && idp.only_user == 0
        && idp.only_ca == 0
        && idp.indirect_crl == 0
        && idp.only_some_reasons.is_none()
        && idp.only_attr == 0
    {
        out.extend_from_slice(b"<EMPTY>\n");
    }
}

/// `i2r_certpol` at indent 0.
fn i2r_certpol(out: &mut Vec<u8>, pols: &[(Vec<u8>, Option<Vec<Qual>>)]) {
    for (i, (oid, quals)) in pols.iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(b"Policy: ");
        text::i2a_object(out, oid);
        if let Some(quals) = quals {
            out.push(b'\n');
            for (j, q) in quals.iter().enumerate() {
                if j > 0 {
                    out.push(b'\n');
                }
                match q {
                    Qual::Cps(uri) => {
                        out.extend_from_slice(b"  CPS: ");
                        out.extend_from_slice(cstr(uri));
                    }
                    Qual::Notice(n) => {
                        out.extend_from_slice(b"  User Notice:\n");
                        print_notice(out, n);
                    }
                    Qual::Other(oid) => {
                        out.extend_from_slice(b"    Unknown Qualifier: ");
                        text::i2a_object(out, oid);
                    }
                }
            }
        }
    }
}

/// `print_notice` at indent 4.
fn print_notice(out: &mut Vec<u8>, n: &Notice) {
    if let Some((org, nos)) = &n.noticeref {
        out.extend_from_slice(b"    Organization: ");
        out.extend_from_slice(cstr(org));
        out.extend_from_slice(b"\n    Number");
        if nos.len() > 1 {
            out.push(b's');
        }
        out.extend_from_slice(b": ");
        for (i, num) in nos.iter().enumerate() {
            if i > 0 {
                out.extend_from_slice(b", ");
            }
            out.extend(cstr(&text::i2s_integer(num)));
        }
        if n.exptext.is_some() {
            out.push(b'\n');
        }
    }
    if let Some(t) = &n.exptext {
        out.extend_from_slice(b"    Explicit Text: ");
        out.extend_from_slice(cstr(t));
    }
}

/// `do_i2r_name_constraints` at indent 0: the IP bases as address/mask.
fn name_constraints_print(out: &mut Vec<u8>, trees: Option<&[Gn]>, name: &str) {
    let Some(trees) = trees.filter(|t| !t.is_empty()) else {
        return;
    };
    out.extend_from_slice(format!("{name}:\n").as_bytes());
    for (i, g) in trees.iter().enumerate() {
        if i > 0 {
            out.push(b'\n');
        }
        out.extend_from_slice(b"  ");
        match g {
            Gn::Ip(ip) => {
                let len1 = if ip.len() >= 16 {
                    16
                } else if ip.len() >= 4 {
                    4
                } else {
                    ip.len()
                };
                out.extend_from_slice(b"IP:");
                out.extend(text::ipaddr_to_asc(&ip[..len1]));
                out.push(b'/');
                out.extend(text::ipaddr_to_asc(&ip[len1..]));
            }
            _ => general_name_print(out, g),
        }
    }
}

/// `X509v3_addr_get_afi`.
fn addr_afi(f: &[u8]) -> u32 {
    if f.len() < 2 {
        0
    } else {
        u32::from(f[0]) << 8 | u32::from(f[1])
    }
}

/// `addr_expand`: the address padded to `len` with `fill`, the unused bits
/// set to it; `None` where it is longer.
fn addr_expand(bs: &(u8, Vec<u8>), len: usize, fill: u8) -> Option<Vec<u8>> {
    let (unused, data) = bs;
    if data.len() > len {
        return None;
    }
    let mut a = data.clone();
    if *unused != 0 {
        if let Some(last) = a.last_mut() {
            let mask = 0xffu8 >> (8 - unused);
            if fill == 0 {
                *last &= !mask;
            } else {
                *last |= mask;
            }
        }
    }
    a.resize(len, fill);
    Some(a)
}

/// `i2r_address`.
fn i2r_address(out: &mut Vec<u8>, afi: u32, fill: u8, bs: &(u8, Vec<u8>)) -> bool {
    match afi {
        1 => {
            let Some(a) = addr_expand(bs, 4, fill) else {
                return false;
            };
            out.extend_from_slice(format!("{}.{}.{}.{}", a[0], a[1], a[2], a[3]).as_bytes());
        }
        2 => {
            let Some(a) = addr_expand(bs, 16, fill) else {
                return false;
            };
            let mut n = 16;
            while n > 1 && a[n - 1] == 0 && a[n - 2] == 0 {
                n -= 2;
            }
            let mut i = 0;
            while i < n {
                let v = u16::from_be_bytes([a[i], a[i + 1]]);
                out.extend_from_slice(format!("{v:x}").as_bytes());
                if i < 14 {
                    out.push(b':');
                }
                i += 2;
            }
            if i < 16 {
                out.push(b':');
            }
            if i == 0 {
                out.push(b':');
            }
        }
        _ => {
            for (i, b) in bs.1.iter().enumerate() {
                if i > 0 {
                    out.push(b':');
                }
                out.extend_from_slice(format!("{b:02x}").as_bytes());
            }
            out.extend_from_slice(format!("[{}]", bs.0).as_bytes());
        }
    }
    true
}

/// `i2r_IPAddrBlocks` at indent 0.
fn i2r_ip_addr_blocks(out: &mut Vec<u8>, fams: &[AddrFamily]) -> bool {
    for (fam, choice) in fams {
        let afi = addr_afi(fam);
        match afi {
            1 => out.extend_from_slice(b"IPv4"),
            2 => out.extend_from_slice(b"IPv6"),
            _ => out.extend_from_slice(format!("Unknown AFI {afi}").as_bytes()),
        }
        if let Some(&safi) = fam.get(2) {
            match safi {
                1 => out.extend_from_slice(b" (Unicast)"),
                2 => out.extend_from_slice(b" (Multicast)"),
                3 => out.extend_from_slice(b" (Unicast/Multicast)"),
                4 => out.extend_from_slice(b" (MPLS)"),
                64 => out.extend_from_slice(b" (Tunnel)"),
                65 => out.extend_from_slice(b" (VPLS)"),
                66 => out.extend_from_slice(b" (BGP MDT)"),
                128 => out.extend_from_slice(b" (MPLS-labeled VPN)"),
                n => out.extend_from_slice(format!(" (Unknown SAFI {n})").as_bytes()),
            }
        }
        match choice {
            None => out.extend_from_slice(b": inherit\n"),
            Some(aors) => {
                out.extend_from_slice(b":\n");
                for aor in aors {
                    out.extend_from_slice(b"  ");
                    match aor {
                        AddrOrRange::Prefix(bs) => {
                            if !i2r_address(out, afi, 0, bs) {
                                return false;
                            }
                            let plen = i64::try_from(bs.1.len()).unwrap_or(i64::MAX) * 8
                                - i64::from(bs.0);
                            out.extend_from_slice(format!("/{plen}\n").as_bytes());
                        }
                        AddrOrRange::Range(min, max) => {
                            if !i2r_address(out, afi, 0, min) {
                                return false;
                            }
                            out.push(b'-');
                            if !i2r_address(out, afi, 0xff, max) {
                                return false;
                            }
                            out.push(b'\n');
                        }
                    }
                }
            }
        }
    }
    true
}

/// `i2r_ASIdentifierChoice` at indent 0.
fn as_id_choice(out: &mut Vec<u8>, choice: Option<&Option<Vec<AsIdOrRange>>>, msg: &str) {
    let Some(choice) = choice else {
        return;
    };
    out.extend_from_slice(format!("{msg}:\n").as_bytes());
    match choice {
        None => out.extend_from_slice(b"  inherit\n"),
        Some(ids) => {
            for id in ids {
                out.extend_from_slice(b"  ");
                match id {
                    AsIdOrRange::Id(v) => out.extend(cstr(&text::i2s_integer(v))),
                    AsIdOrRange::Range(a, b) => {
                        out.extend(cstr(&text::i2s_integer(a)));
                        out.push(b'-');
                        out.extend(cstr(&text::i2s_integer(b)));
                    }
                }
                out.push(b'\n');
            }
        }
    }
}

/// `i2r_NAMING_AUTHORITY` at indent `ind`: `false` (the print fails) when
/// all three fields are absent.
fn i2r_naming_authority(out: &mut Vec<u8>, na: &NamingAuthority, ind: usize) -> bool {
    let (id, url, txt) = na;
    if id.is_none() && txt.is_none() && url.is_none() {
        return false;
    }
    let pad = " ".repeat(ind);
    out.extend_from_slice(format!("{pad}namingAuthority: ").as_bytes());
    if let Some(oid) = id {
        out.extend_from_slice(format!("{pad}  admissionAuthorityId: ").as_bytes());
        let ln = text::nid2ln(oid);
        out.extend_from_slice(format!("{ln} (").as_bytes());
        out.extend(text::obj2txt_buf(oid, 128, true));
        out.extend_from_slice(b")\n");
    }
    if let Some(t) = txt {
        out.extend_from_slice(format!("{pad}  namingAuthorityText: ").as_bytes());
        text::string_print(out, t);
        out.push(b'\n');
    }
    if let Some(u) = url {
        out.extend_from_slice(format!("{pad}  namingAuthorityUrl: ").as_bytes());
        text::string_print(out, u);
        out.push(b'\n');
    }
    true
}

/// `i2r_ADMISSION_SYNTAX` at indent 0.
fn i2r_admission_syntax(out: &mut Vec<u8>, adm: &(Option<Gn>, Vec<Admissions>)) -> bool {
    let (authority, contents) = adm;
    if let Some(g) = authority {
        out.extend_from_slice(b"admissionAuthority:\n  ");
        general_name_print(out, g);
        out.push(b'\n');
    }
    for (i, entry) in contents.iter().enumerate() {
        out.extend_from_slice(format!("Entry {}:\n", i + 1).as_bytes());
        if let Some(g) = &entry.authority {
            out.extend_from_slice(b"  admissionAuthority:\n    ");
            general_name_print(out, g);
            out.push(b'\n');
        }
        if let Some(na) = &entry.naming_authority {
            if !i2r_naming_authority(out, na, 0) {
                return false;
            }
        }
        for (j, pinfo) in entry.infos.iter().enumerate() {
            out.extend_from_slice(format!("  Profession Info Entry {}:\n", j + 1).as_bytes());
            if let Some(r) = &pinfo.registration_number {
                out.extend_from_slice(b"    registrationNumber: ");
                text::string_print(out, r);
                out.push(b'\n');
            }
            if let Some(na) = &pinfo.naming_authority {
                if !i2r_naming_authority(out, na, 2) {
                    return false;
                }
            }
            out.extend_from_slice(b"    Info Entries:\n");
            for item in &pinfo.items {
                out.extend_from_slice(b"      ");
                text::string_print(out, item);
                out.push(b'\n');
            }
            if let Some(oids) = &pinfo.oids {
                out.extend_from_slice(b"    Profession OIDs:\n");
                for oid in oids {
                    out.extend_from_slice(format!("      {} (", text::nid2ln(oid)).as_bytes());
                    out.extend(text::obj2txt_buf(oid, 128, true));
                    out.extend_from_slice(b")\n");
                }
            }
        }
    }
    true
}

// ---- Certificate Transparency ------------------------------------------------------

/// An `SCT` as `o2i_SCT` reads one.
#[derive(Clone, Debug, PartialEq, Eq)]
enum Sct {
    V1 {
        log_id: Vec<u8>,
        timestamp: u64,
        ext: Vec<u8>,
        hash_alg: u8,
        sig_alg: u8,
        sig: Vec<u8>,
    },
    /// Another version: its encoding, kept whole.
    Unknown(Vec<u8>),
}

/// `CT_R_SCT_LIST_INVALID` and its siblings, packed.
fn ct(reason: u32) -> Bad {
    Bad(err::pack(LIB_CT, reason))
}

/// Two octets, big-endian (`n2s`).
fn n2s(p: &[u8]) -> usize {
    usize::from(u16::from_be_bytes([p[0], p[1]]))
}

/// `d2i_SCT_LIST`: an OCTET STRING (`d2i_ASN1_OCTET_STRING`) holding
/// `o2i_SCT_LIST`'s TLS encoding.
fn d2i_sct_list(p: &[u8]) -> Res<Vec<Sct>> {
    let (oct, _) = req(string(p, tag::OCTET_STRING, None, false))?;
    let len = oct.len();
    if !(2..=65535).contains(&len) || n2s(&oct) != len - 2 {
        return Err(ct(CT_R_SCT_LIST_INVALID));
    }
    let mut rest = &oct[2..];
    let mut out = Vec::new();
    while !rest.is_empty() {
        if rest.len() < 2 {
            return Err(ct(CT_R_SCT_LIST_INVALID));
        }
        let sct_len = n2s(rest);
        rest = &rest[2..];
        if sct_len == 0 || sct_len > rest.len() {
            return Err(ct(CT_R_SCT_LIST_INVALID));
        }
        out.push(o2i_sct(&rest[..sct_len])?);
        rest = &rest[sct_len..];
    }
    Ok(out)
}

/// `o2i_SCT` on one SCT's `len` (at least one) octets: a v1 SCT's fields,
/// bytes after the signature ignored; another version kept whole.
fn o2i_sct(p: &[u8]) -> Res<Sct> {
    if p[0] != 0 {
        return Ok(Sct::Unknown(p.to_vec()));
    }
    if p.len() < 43 {
        return Err(ct(CT_R_SCT_INVALID));
    }
    let mut len = p.len() - 43;
    let log_id = p[1..33].to_vec();
    let timestamp = u64::from_be_bytes(p[33..41].try_into().unwrap_or_default());
    let ext_len = n2s(&p[41..]);
    if len < ext_len {
        return Err(ct(CT_R_SCT_INVALID));
    }
    let ext = p[43..43 + ext_len].to_vec();
    len -= ext_len;
    let s = &p[43 + ext_len..];
    // o2i_SCT_signature: hash and signature algorithms, two length octets,
    // the signature; then "invalid signature" is followed by "SCT invalid".
    if len <= 4 {
        return Err(ct(CT_R_SCT_INVALID_SIGNATURE));
    }
    let (hash_alg, sig_alg) = (s[0], s[1]);
    if hash_alg != 4 || !matches!(sig_alg, 1 | 3) {
        return Err(ct(CT_R_SCT_INVALID_SIGNATURE));
    }
    let sig_len = n2s(&s[2..]);
    if sig_len > len - 4 {
        return Err(ct(CT_R_SCT_INVALID_SIGNATURE));
    }
    Ok(Sct::V1 {
        log_id,
        timestamp,
        ext,
        hash_alg,
        sig_alg,
        sig: s[4..4 + sig_len].to_vec(),
    })
}

/// `SCT_print` at indent 0, with no log store.
fn sct_print(out: &mut Vec<u8>, sct: &Sct) {
    out.extend_from_slice(b"Signed Certificate Timestamp:\n    Version   : ");
    match sct {
        Sct::Unknown(raw) => {
            out.extend_from_slice(b"unknown\n");
            out.resize(out.len() + 16, b' ');
            text::hex_string(out, 16, 16, raw);
        }
        Sct::V1 {
            log_id,
            timestamp,
            ext,
            hash_alg,
            sig_alg,
            sig,
        } => {
            out.extend_from_slice(b"v1 (0x0)\n    Log ID    : ");
            text::hex_string(out, 16, 16, log_id);
            out.extend_from_slice(b"\n    Timestamp : ");
            text::ct_timestamp_print(out, *timestamp);
            out.extend_from_slice(b"\n    Extensions: ");
            if ext.is_empty() {
                out.extend_from_slice(b"none");
            } else {
                text::hex_string(out, 16, 16, ext);
            }
            out.extend_from_slice(b"\n    Signature : ");
            let nid = match (hash_alg, sig_alg) {
                (4, 3) => Some(NID_ECDSA_WITH_SHA256),
                (4, 1) => Some(NID_SHA256_WITH_RSA),
                _ => None,
            };
            match nid.and_then(objects::long_name) {
                Some(ln) => out.extend_from_slice(ln.as_bytes()),
                None => out.extend_from_slice(format!("{hash_alg:02X}{sig_alg:02X}").as_bytes()),
            }
            out.extend_from_slice(b"\n                ");
            text::hex_string(out, 16, 16, sig);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tlv(t: u8, c: &[u8]) -> Vec<u8> {
        let mut v = vec![t];
        if c.len() < 128 {
            v.push(u8::try_from(c.len()).unwrap());
        } else {
            v.push(0x82);
            v.extend_from_slice(&u16::try_from(c.len()).unwrap().to_be_bytes());
        }
        v.extend_from_slice(c);
        v
    }

    fn show(nid: u16, value: &[u8]) -> (Option<String>, Option<String>) {
        let mut e = Errs::default();
        let v = print_nid(nid, value, &mut e);
        (
            v.map(|b| String::from_utf8_lossy(&b).into_owned()),
            e.0.map(err::error_string),
        )
    }

    #[test]
    fn subject_alt_names() {
        let san = tlv(
            0x30,
            &[
                tlv(0x82, b"a.example"),
                tlv(0x87, &[10, 0, 0, 1]),
                tlv(0x81, b"x@y"),
                tlv(0x86, b"http://u"),
            ]
            .concat(),
        );
        assert_eq!(
            show(NID_SUBJECT_ALT_NAME, &san).0.as_deref(),
            Some("DNS:a.example, IP Address:10.0.0.1, email:x@y, URI:http://u")
        );
        let nul = tlv(0x30, &tlv(0x82, b"a\0b"));
        assert_eq!(
            show(NID_SUBJECT_ALT_NAME, &nul),
            (
                None,
                Some("error:110C0100:X509 V3 routines::malloc failure".into())
            )
        );
        let bad = tlv(0x30, &tlv(0x89, b"x"));
        assert_eq!(
            show(NID_SUBJECT_ALT_NAME, &bad).1.as_deref(),
            Some("error:0680008F:asn1 encoding routines::no matching choice type")
        );
    }

    #[test]
    fn always_failing_printers_still_decode() {
        assert_eq!(show(NID_OCSP_NONCE, b"anything"), (None, None));
        assert_eq!(
            show(NID_INVALIDITY_DATE, &tlv(0x18, b"20200101000000Z")),
            (None, None)
        );
        assert_eq!(
            show(NID_INVALIDITY_DATE, &tlv(0x17, b"200101000000Z")).1.as_deref(),
            Some("error:068000A8:asn1 encoding routines::wrong tag")
        );
        assert_eq!(show(NID_OCSP_NOCHECK, &[5, 0]), (Some(String::new()), None));
        assert_eq!(show(1, &[5, 0]), (None, None));
    }

    #[test]
    fn bit_strings_and_integers() {
        assert_eq!(
            show(NID_KEY_USAGE, &[3, 2, 1, 0x86]).0.as_deref(),
            Some("Digital Signature, Certificate Sign, CRL Sign")
        );
        assert_eq!(show(NID_KEY_USAGE, &[3, 1, 0]).0, None);
        assert_eq!(
            show(NID_BASIC_CONSTRAINTS, &[0x30, 6, 1, 1, 0xff, 2, 1, 3]).0.as_deref(),
            Some("CA:TRUE, pathlen:3")
        );
        assert_eq!(
            show(NID_BASIC_CONSTRAINTS, &[0x30, 0]).0.as_deref(),
            Some("CA:FALSE")
        );
        let (v, err) = show(NID_TLSFEATURE, &tlv(0x30, &[tlv(2, &[5]), tlv(2, &[1; 17])].concat()));
        assert_eq!(v.as_deref(), Some("status_request, 0x0101010101010101010101010101010101"));
        assert_eq!(err.as_deref(), Some("error:068000DF:asn1 encoding routines::too large"));
        assert_eq!(show(NID_CRL_REASON, &[10, 1, 8]).0.as_deref(), Some("Remove From CRL"));
    }

    #[test]
    fn scts() {
        let mut sct = vec![0u8];
        sct.extend_from_slice(&[0xab; 32]);
        sct.extend_from_slice(&1_577_836_800_000u64.to_be_bytes());
        sct.extend_from_slice(&[0, 0, 4, 3, 0, 2, 0xde, 0xad]);
        let mut list = u16::try_from(sct.len() + 2).unwrap().to_be_bytes().to_vec();
        list.extend_from_slice(&u16::try_from(sct.len()).unwrap().to_be_bytes());
        list.extend_from_slice(&sct);
        let v = show(NID_CT_PRECERT_SCTS, &tlv(4, &list)).0.unwrap();
        assert!(v.starts_with("Signed Certificate Timestamp:\n    Version   : v1 (0x0)\n"));
        assert!(v.contains("Timestamp : Jan  1 00:00:00.000 2020 GMT"));
        assert!(v.ends_with("Signature : ecdsa-with-SHA256\n                DE:AD"));
        list[0] ^= 1;
        assert_eq!(
            show(NID_CT_PRECERT_SCTS, &tlv(4, &list)).1.as_deref(),
            Some("error:19000069:CT routines::sct list invalid")
        );
    }
}
