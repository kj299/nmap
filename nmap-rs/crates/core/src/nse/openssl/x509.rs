//! A certificate as `d2i_X509` reads it and `i2d_X509` writes it back
//! (OpenSSL 3.0.13, `crypto/x509/x_x509.c` and the templates it names), the
//! reader `parse_ssl_certificate` stands on (`nse_ssl_cert.cc:530-541`; E5,
//! `spikes/m65-x509/RESULT.md` §10). Pure and total.
//!
//! Each template is walked as [`asn1`]'s generic decoder walks it: a SEQUENCE
//! through [`Seq`], whose fields are tried in order with the C's rule for
//! OPTIONAL (never for the last field while data remains), an EXPLICIT tag
//! through [`explicit`], SEQUENCE OF and SET OF through [`seq_of`], the Name
//! and public-key EXTERN types through their own functions. The certificate
//! keeps what nmap reads and what re-encoding needs:
//!
//! - `tbsCertificate` as received (`ASN1_SEQUENCE_enc`: OpenSSL caches it
//!   and `i2d` replays it byte for byte, indefinite lengths and all);
//! - the outer `signatureAlgorithm` and `signature`, which `i2d` encodes
//!   afresh (a minimal header, a BIT STRING's padding masked);
//! - the Names, validity, key and extensions, decoded.
//!
//! Trailing bytes after the outer SEQUENCE are not read: nmap never checks
//! how far `d2i_X509` advanced (`nse_ssl_cert.cc:538`).
//!
//! **Arithmetic** is on offsets inside the input, bounded as in [`asn1`]:
//! a field's reader returns how much of the window it used, never more.
#![allow(clippy::arithmetic_side_effects)]

use super::asn1::{
    self, bit, check_eoc, check_tlen, i2d_any, primitive, tag, tlv, Bad, Prim, Res, CONTEXT,
    UNIVERSAL,
};
use super::err::*;
use super::pubkey::{self, PubKey};

/// `X509_NAME_MAX`: a Name's encoding is read from at most this many bytes
/// (`x509_name_ex_d2i`), so a longer one does not fit.
pub const X509_NAME_MAX: usize = 1024 * 1024;

/// An `X509_ALGOR`: the OID's content octets and the parameter, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Algor {
    pub oid: Vec<u8>,
    pub param: Option<Prim>,
}

/// An `X509_NAME_ENTRY`: the attribute type, its value as decoded (a string,
/// a BIT STRING, or a SEQUENCE kept encoded), and the RDN it came from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NameEntry {
    pub oid: Vec<u8>,
    pub value: Prim,
    pub set: usize,
}

/// An `ASN1_TIME`: UTCTime or GeneralizedTime, its content unvalidated.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Time {
    pub utype: u32,
    pub data: Vec<u8>,
}

/// An `X509_EXTENSION`: the OID, the BOOLEAN's octet if present
/// (`ASN1_BOOLEAN`, -1 when absent; critical is its being non-zero), and
/// the OCTET STRING's content.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Extension {
    pub oid: Vec<u8>,
    pub critical: Option<u8>,
    pub value: Vec<u8>,
}

impl Extension {
    /// `X509_EXTENSION_get_critical`: `critical > 0`.
    #[must_use]
    pub fn is_critical(&self) -> bool {
        self.critical.is_some_and(|b| b != 0)
    }
}

/// A `SubjectPublicKeyInfo`: the algorithm, the BIT STRING (its padding
/// masked), and the key `X509_PUBKEY`'s decode made of it, if any.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Spki {
    pub algor: Algor,
    pub unused: u8,
    pub bits: Vec<u8>,
    pub key: Option<PubKey>,
}

/// A decoded certificate.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cert {
    /// `cert_info`'s cached encoding, from its tag through its end.
    pub tbs: Vec<u8>,
    pub tbs_sig: Algor,
    pub issuer: Vec<NameEntry>,
    pub not_before: Time,
    pub not_after: Time,
    pub subject: Vec<NameEntry>,
    pub spki: Spki,
    /// `None` when the `[3]` field is absent; `Some` with no entries when it
    /// is an empty SEQUENCE.
    pub extensions: Option<Vec<Extension>>,
    pub sig_alg: Algor,
    pub sig_unused: u8,
    pub sig_data: Vec<u8>,
}

/// `d2i_X509` on `der`: the certificate, or `None` where OpenSSL returns
/// NULL.
#[must_use]
pub fn d2i_x509(der: &[u8]) -> Option<Cert> {
    x509(der).ok().map(|(c, _)| c)
}

/// `d2i_X509` as the TLS client calls it, with how far it read: OpenSSL's
/// client refuses a certificate entry the certificate does not fill
/// (`statem_clnt.c:1813-1816`), where `parse_ssl_certificate` ignores what
/// follows.
#[must_use]
pub fn d2i_x509_len(der: &[u8]) -> Option<(Cert, usize)> {
    x509(der).ok()
}

// ---- the generic shapes ---------------------------------------------------------

/// A SEQUENCE being read field by field (`asn1_item_embed_d2i`, the
/// `ASN1_ITYPE_SEQUENCE` case).
pub struct Seq<'a> {
    p: &'a [u8],
    hdr: usize,
    off: usize,
    len: usize,
    eoc: bool,
    nolen: bool,
    ended: bool,
}

impl<'a> Seq<'a> {
    /// Read the SEQUENCE header (`tag` and `class` for an IMPLICIT tag);
    /// `None` for an absent OPTIONAL.
    pub fn open(p: &'a [u8], imp: Option<(u32, u8)>, opt: bool) -> Res<Option<Seq<'a>>> {
        let want = imp.unwrap_or((tag::SEQUENCE, UNIVERSAL));
        let Some(h) = check_tlen(p, Some(want), opt)? else {
            return Ok(None);
        };
        if !h.cons {
            return Err(Bad::asn1(ASN1_R_SEQUENCE_NOT_CONSTRUCTED));
        }
        Ok(Some(Seq {
            p,
            hdr: h.hdr_len,
            off: h.hdr_len,
            len: h.len,
            eoc: h.inf,
            nolen: h.inf,
            ended: false,
        }))
    }

    /// The next field. `optional` is the template's OPTIONAL flag; `last`
    /// says it is the template's last field, which is never treated as
    /// absent while data remains. `f` reads the field from the bytes left,
    /// given whether it may be absent, and returns the value and the bytes
    /// it used, or `None` for absent.
    pub fn field<T>(
        &mut self,
        optional: bool,
        last: bool,
        f: impl FnOnce(&'a [u8], bool) -> Res<Option<(T, usize)>>,
    ) -> Res<Option<T>> {
        // A required field after the data ran out: the C finishes the
        // SEQUENCE first, so an indefinite one still owed its EOC raises
        // "missing EOC" before "field missing".
        let missing = |optional: bool, eoc: bool| {
            if optional {
                Ok(None)
            } else if eoc {
                Err(Bad::asn1(ASN1_R_MISSING_EOC))
            } else {
                Err(Bad::asn1(ASN1_R_FIELD_MISSING))
            }
        };
        if self.ended {
            return missing(optional, self.eoc);
        }
        if self.len == 0 {
            self.ended = true;
            return missing(optional, self.eoc);
        }
        let window = &self.p[self.off..self.off + self.len];
        if check_eoc(window) {
            if !self.eoc {
                return Err(Bad::asn1(ASN1_R_UNEXPECTED_EOC));
            }
            self.off += 2;
            self.len -= 2;
            self.eoc = false;
            self.ended = true;
            return missing(optional, false);
        }
        let isopt = !last && optional;
        match f(window, isopt)? {
            None => Ok(None),
            Some((v, used)) => {
                self.off += used;
                self.len -= used;
                Ok(Some(v))
            }
        }
    }

    /// A required field.
    pub fn req<T>(
        &mut self,
        last: bool,
        f: impl FnOnce(&'a [u8], bool) -> Res<Option<(T, usize)>>,
    ) -> Res<T> {
        self.field(false, last, f)?.ok_or(Bad(0))
    }

    /// The end of the SEQUENCE: its EOC if indefinite, nothing left if
    /// definite. Returns the bytes the SEQUENCE used, header included.
    pub fn finish(mut self) -> Res<usize> {
        if self.eoc {
            if !check_eoc(&self.p[self.off..self.off + self.len]) {
                return Err(Bad::asn1(ASN1_R_MISSING_EOC));
            }
            self.off += 2;
            self.len -= 2;
        }
        if !self.nolen && self.len != 0 {
            return Err(Bad::asn1(ASN1_R_SEQUENCE_LENGTH_MISMATCH));
        }
        let _ = self.hdr;
        Ok(self.off)
    }
}

/// An EXPLICIT tag around a field (`asn1_template_ex_d2i`). `inner` reads
/// the field, which is no longer optional once the tag matched.
pub fn explicit<'a, T>(
    p: &'a [u8],
    t: u32,
    class: u8,
    opt: bool,
    inner: impl FnOnce(&'a [u8]) -> Res<(T, usize)>,
) -> Res<Option<(T, usize)>> {
    let Some(h) = check_tlen(p, Some((t, class)), opt)? else {
        return Ok(None);
    };
    if !h.cons {
        return Err(Bad::asn1(ASN1_R_EXPLICIT_TAG_NOT_CONSTRUCTED));
    }
    let body = &p[h.hdr_len..h.hdr_len + h.len];
    let (v, used) = inner(body)?;
    let mut used = used;
    if h.inf {
        if !check_eoc(&body[used..]) {
            return Err(Bad::asn1(ASN1_R_MISSING_EOC));
        }
        used += 2;
    } else if h.len - used != 0 {
        return Err(Bad::asn1(ASN1_R_EXPLICIT_LENGTH_MISMATCH));
    }
    Ok(Some((v, h.hdr_len + used)))
}

/// SEQUENCE OF or SET OF (`asn1_template_noexp_d2i`, the `SK` case): the
/// header is not required to be constructed (the C passes no `cst`), the
/// items are read until the length or the EOC.
pub fn seq_of<'a, T>(
    p: &'a [u8],
    want: (u32, u8),
    opt: bool,
    mut item: impl FnMut(&'a [u8]) -> Res<(T, usize)>,
) -> Res<Option<(Vec<T>, usize)>> {
    let Some(h) = check_tlen(p, Some(want), opt)? else {
        return Ok(None);
    };
    let mut eoc = h.inf;
    let mut off = h.hdr_len;
    let mut len = h.len;
    let mut out = Vec::new();
    while len > 0 {
        if check_eoc(&p[off..off + len]) {
            if !eoc {
                return Err(Bad::asn1(ASN1_R_UNEXPECTED_EOC));
            }
            off += 2;
            eoc = false;
            break;
        }
        let (v, used) = item(&p[off..off + len])?;
        out.push(v);
        off += used;
        len -= used;
    }
    if eoc {
        return Err(Bad::asn1(ASN1_R_MISSING_EOC));
    }
    Ok(Some((out, off)))
}

/// A multi-string (`ASN1_ITYPE_MSTRING`): any universal tag whose bit is in
/// `mask`, decoded as that type.
pub fn mstring(p: &[u8], mask: u32, opt: bool) -> Res<Option<(Prim, usize)>> {
    let h = check_tlen(p, None, true)?.ok_or(Bad(0))?;
    if h.class != UNIVERSAL {
        return if opt {
            Ok(None)
        } else {
            Err(Bad::asn1(ASN1_R_MSTRING_NOT_UNIVERSAL))
        };
    }
    if asn1::tag2bit(h.tag) & mask == 0 {
        return if opt {
            Ok(None)
        } else {
            Err(Bad::asn1(ASN1_R_MSTRING_WRONG_TAG))
        };
    }
    primitive(p, h.tag, None, false)
}

/// A field of a fixed universal type.
fn prim(p: &[u8], utype: u32, opt: bool) -> Res<Option<(Prim, usize)>> {
    primitive(p, utype, None, opt)
}

// ---- the X509 templates ---------------------------------------------------------

fn x509(p: &[u8]) -> Res<(Cert, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let (tbs, cinf) = s.req(false, |q, _| {
        x509_cinf(q).map(|(t, c, n)| Some(((t, c), n)))
    })?;
    let sig_alg = s.req(false, algor)?;
    let (sig_unused, sig_data) = s.req(true, |q, opt| bit_string(q, None, opt))?;
    let used = s.finish()?;
    let Cinf {
        tbs_sig,
        issuer,
        not_before,
        not_after,
        subject,
        spki,
        extensions,
    } = cinf;
    let cert = Cert {
        tbs,
        tbs_sig,
        issuer,
        not_before,
        not_after,
        subject,
        spki,
        extensions,
        sig_alg,
        sig_unused,
        sig_data,
    };
    Ok((cert, used))
}

struct Cinf {
    tbs_sig: Algor,
    issuer: Vec<NameEntry>,
    not_before: Time,
    not_after: Time,
    subject: Vec<NameEntry>,
    spki: Spki,
    extensions: Option<Vec<Extension>>,
}

/// `X509_CINF` (`ASN1_SEQUENCE_enc`): the fields, and the encoding cached.
fn x509_cinf(p: &[u8]) -> Res<(Vec<u8>, Cinf, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    // version [0] EXPLICIT INTEGER OPTIONAL: any integer.
    s.field(true, false, |q, opt| {
        explicit(q, 0, CONTEXT, opt, |r| {
            prim(r, tag::INTEGER, false)?.ok_or(Bad(0))
        })
    })?;
    s.req(false, |q, opt| prim(q, tag::INTEGER, opt))?;
    let tbs_sig = s.req(false, algor)?;
    let issuer = s.req(false, name)?;
    let (not_before, not_after) = s.req(false, validity)?;
    let subject = s.req(false, name)?;
    let spki = s.req(false, x509_pubkey)?;
    s.field(true, false, |q, opt| bit_string(q, Some((1, CONTEXT)), opt))?;
    s.field(true, false, |q, opt| bit_string(q, Some((2, CONTEXT)), opt))?;
    let extensions = s.field(true, true, |q, opt| {
        explicit(q, 3, CONTEXT, opt, |r| {
            seq_of(r, (tag::SEQUENCE, UNIVERSAL), false, extension)?.ok_or(Bad(0))
        })
    })?;
    let used = s.finish()?;
    Ok((
        p[..used].to_vec(),
        Cinf {
            tbs_sig,
            issuer,
            not_before,
            not_after,
            subject,
            spki,
            extensions,
        },
        used,
    ))
}

/// `X509_ALGOR`: `{ algorithm OBJECT, parameter ANY OPTIONAL }`.
pub fn algor(p: &[u8], opt: bool) -> Res<Option<(Algor, usize)>> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let oid = s.req(false, oid)?;
    let param = s.field(true, true, |q, _| asn1::any(q).map(Some))?;
    let used = s.finish()?;
    Ok(Some((Algor { oid, param }, used)))
}

/// An OBJECT IDENTIFIER's content octets.
pub fn oid(p: &[u8], opt: bool) -> Res<Option<(Vec<u8>, usize)>> {
    Ok(prim(p, tag::OBJECT, opt)?.map(|(v, n)| match v {
        Prim::Oid(c) => (c, n),
        _ => unreachable!("primitive OBJECT decodes to Prim::Oid"),
    }))
}

/// A BIT STRING (under an IMPLICIT tag if given): the unused-bits octet and
/// the masked data.
pub fn bit_string(p: &[u8], imp: Option<(u32, u8)>, opt: bool) -> asn1::Field<(u8, Vec<u8>)> {
    Ok(
        primitive(p, tag::BIT_STRING, imp, opt)?.map(|(v, n)| match v {
            Prim::Bits { unused, data } => ((unused, data), n),
            _ => unreachable!("primitive BIT STRING decodes to Prim::Bits"),
        }),
    )
}

/// An OCTET STRING's content (constructed segments concatenated).
pub fn octet_string(p: &[u8], opt: bool) -> Res<Option<(Vec<u8>, usize)>> {
    Ok(prim(p, tag::OCTET_STRING, opt)?.map(|(v, n)| match v {
        Prim::Str { data, .. } => (data, n),
        _ => unreachable!("primitive OCTET STRING decodes to Prim::Str"),
    }))
}

/// `X509_VAL`: `{ notBefore Time, notAfter Time }`.
fn validity(p: &[u8], opt: bool) -> Res<Option<((Time, Time), usize)>> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let a = s.req(false, time)?;
    let b = s.req(true, time)?;
    let used = s.finish()?;
    Ok(Some(((a, b), used)))
}

/// `ASN1_TIME`: an MSTRING of UTCTime or GeneralizedTime, unvalidated.
fn time(p: &[u8], opt: bool) -> Res<Option<(Time, usize)>> {
    Ok(mstring(p, bit::TIME, opt)?.map(|(v, n)| match v {
        Prim::Str { utype, data } => (Time { utype, data }, n),
        _ => unreachable!("a time tag decodes to Prim::Str"),
    }))
}

/// `X509_EXTENSION`: `{ OBJECT, BOOLEAN OPTIONAL, OCTET STRING }`.
fn extension(p: &[u8]) -> Res<(Extension, usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let oid = s.req(false, oid)?;
    let critical = s.field(true, false, |q, opt| {
        Ok(prim(q, tag::BOOLEAN, opt)?.map(|(v, n)| match v {
            Prim::Bool(b) => (b, n),
            _ => unreachable!("primitive BOOLEAN decodes to Prim::Bool"),
        }))
    })?;
    let value = s.req(true, octet_string)?;
    let used = s.finish()?;
    Ok((
        Extension {
            oid,
            critical,
            value,
        },
        used,
    ))
}

/// `X509_NAME` (`x509_name_ex_d2i`): a SEQUENCE OF SET OF entries, read from
/// at most [`X509_NAME_MAX`] bytes, flattened with each entry's set index,
/// then canonicalised, which refuses a string `ASN1_STRING_to_UTF8` cannot
/// convert ([`canon_ok`]).
pub fn name(p: &[u8], opt: bool) -> Res<Option<(Vec<NameEntry>, usize)>> {
    let p = &p[..p.len().min(X509_NAME_MAX)];
    let Some((rdns, used)) = seq_of(p, (tag::SEQUENCE, UNIVERSAL), opt, |q| {
        seq_of(q, (tag::SET, UNIVERSAL), false, name_entry)?.ok_or(Bad(0))
    })?
    else {
        return Ok(None);
    };
    let mut out = Vec::new();
    for (set, rdn) in rdns.into_iter().enumerate() {
        for (oid, value) in rdn {
            canon(&value)?;
            out.push(NameEntry { oid, value, set });
        }
    }
    Ok(Some((out, used)))
}

/// `X509_NAME_ENTRY`: `{ OBJECT, ASN1_PRINTABLE }`.
pub fn name_entry(p: &[u8]) -> Res<((Vec<u8>, Prim), usize)> {
    let mut s = Seq::open(p, None, false)?.ok_or(Bad(0))?;
    let oid = s.req(false, oid)?;
    let value = s.req(true, |q, opt| mstring(q, bit::PRINTABLE, opt))?;
    let used = s.finish()?;
    Ok(((oid, value), used))
}

/// Whether `asn1_string_canon` succeeds on an entry's value: the string
/// types it canonicalises (`ASN1_MASK_CANON`) must convert to UTF-8
/// (`ASN1_STRING_to_UTF8`, `ASN1_mbstring_ncopy`): valid UTF-8 ("invalid
/// utf8string"), and code points that are valid Unicode in a BMPString or
/// UniversalString ("illegal characters"). Every other type is copied.
pub fn canon(v: &Prim) -> Res<()> {
    let Prim::Str { utype, data } = v else {
        return Ok(());
    };
    let ok = match *utype {
        tag::UTF8STRING => {
            return utf8_chars(data)
                .map(|_| ())
                .ok_or(Bad::asn1(ASN1_R_INVALID_UTF8STRING));
        }
        tag::BMPSTRING => data
            .chunks(2)
            .all(|c| is_unicode_valid(u32::from(c[0]) << 8 | u32::from(c[1]))),
        tag::UNIVERSALSTRING => data
            .chunks(4)
            .all(|c| is_unicode_valid(u32::from_be_bytes([c[0], c[1], c[2], c[3]]))),
        _ => true,
    };
    if ok {
        Ok(())
    } else {
        Err(Bad::asn1(ASN1_R_ILLEGAL_CHARACTERS))
    }
}

/// `is_unicode_valid`: at most U+10FFFF and not a surrogate.
#[must_use]
pub fn is_unicode_valid(v: u32) -> bool {
    v <= 0x10ffff && !(0xd800..=0xdfff).contains(&v)
}

/// `UTF8_getc` over the whole string with `in_utf8`'s check: the code
/// points, or `None` for a malformed sequence or an invalid code point.
#[must_use]
pub fn utf8_chars(s: &[u8]) -> Option<Vec<u32>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < s.len() {
        let (v, n) = utf8_getc(&s[i..])?;
        if !is_unicode_valid(v) {
            return None;
        }
        out.push(v);
        i += n;
    }
    Some(out)
}

/// `UTF8_getc`: one code point and its length, or `None` for any of its
/// negative returns.
#[must_use]
pub fn utf8_getc(p: &[u8]) -> Option<(u32, usize)> {
    let b0 = *p.first()?;
    let cont = |i: usize| p.get(i).is_some_and(|&b| b & 0xc0 == 0x80);
    if b0 & 0x80 == 0 {
        Some((u32::from(b0), 1))
    } else if b0 & 0xe0 == 0xc0 {
        if p.len() < 2 || !cont(1) {
            return None;
        }
        let v = (u32::from(b0 & 0x1f) << 6) | u32::from(p[1] & 0x3f);
        (v >= 0x80).then_some((v, 2))
    } else if b0 & 0xf0 == 0xe0 {
        if p.len() < 3 || !cont(1) || !cont(2) {
            return None;
        }
        let v =
            (u32::from(b0 & 0x0f) << 12) | (u32::from(p[1] & 0x3f) << 6) | u32::from(p[2] & 0x3f);
        if v < 0x800 || (0xd800..=0xdfff).contains(&v) {
            return None;
        }
        Some((v, 3))
    } else if b0 & 0xf8 == 0xf0 {
        if p.len() < 4 || !cont(1) || !cont(2) || !cont(3) {
            return None;
        }
        let v = (u32::from(b0 & 0x07) << 18)
            | (u32::from(p[1] & 0x3f) << 12)
            | (u32::from(p[2] & 0x3f) << 6)
            | u32::from(p[3] & 0x3f);
        (v >= 0x10000).then_some((v, 4))
    } else {
        None
    }
}

/// `X509_PUBKEY` (`x509_pubkey_ex_d2i_ex`): `{ X509_ALGOR, BIT STRING }`,
/// then the key decoded opportunistically ([`pubkey::decode`]): a key that
/// does not decode leaves no key, not a failed certificate.
fn x509_pubkey(p: &[u8], opt: bool) -> Res<Option<(Spki, usize)>> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let algor = s.req(false, algor)?;
    let (unused, bits) = s.req(true, |q, opt| bit_string(q, None, opt))?;
    let used = s.finish()?;
    let key = pubkey::decode(&algor, &bits);
    Ok(Some((
        Spki {
            algor,
            unused,
            bits,
            key,
        },
        used,
    )))
}

// ---- re-encoding ------------------------------------------------------------------

/// `i2d_X509`: the outer SEQUENCE with a minimal header, `cert_info`'s cached
/// bytes, the signature algorithm and the signature encoded afresh.
#[must_use]
pub fn i2d_x509(c: &Cert) -> Vec<u8> {
    let mut body = Vec::with_capacity(c.tbs.len() + c.sig_data.len() + 64);
    body.extend_from_slice(&c.tbs);
    body.extend_from_slice(&i2d_algor(&c.sig_alg));
    body.extend_from_slice(&tlv(
        tag::BIT_STRING,
        UNIVERSAL,
        false,
        &asn1::bit_content(c.sig_unused, &c.sig_data),
    ));
    tlv(tag::SEQUENCE, UNIVERSAL, true, &body)
}

/// `i2d_X509_ALGOR`.
#[must_use]
pub fn i2d_algor(a: &Algor) -> Vec<u8> {
    let mut body = tlv(tag::OBJECT, UNIVERSAL, false, &a.oid);
    if let Some(p) = &a.param {
        body.extend_from_slice(&i2d_any(p));
    }
    tlv(tag::SEQUENCE, UNIVERSAL, true, &body)
}

/// `PEM_write_bio_X509`: the re-encoding in base64, 64 characters a line,
/// between the CERTIFICATE lines.
#[must_use]
pub fn pem(der: &[u8]) -> Vec<u8> {
    const B64: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = b"-----BEGIN CERTIFICATE-----\n".to_vec();
    for line in der.chunks(48) {
        for c in line.chunks(3) {
            let b = [c[0], *c.get(1).unwrap_or(&0), *c.get(2).unwrap_or(&0)];
            let n = (u32::from(b[0]) << 16) | (u32::from(b[1]) << 8) | u32::from(b[2]);
            for (i, shift) in [18u32, 12, 6, 0].into_iter().enumerate() {
                if i <= c.len() {
                    out.push(B64[((n >> shift) & 63) as usize]);
                } else {
                    out.push(b'=');
                }
            }
        }
        out.push(b'\n');
    }
    out.extend_from_slice(b"-----END CERTIFICATE-----\n");
    out
}

// ---- what nmap reads ---------------------------------------------------------------

/// The bytes `ASN1_STRING_get0_data` gives for a Name entry's value: the
/// string's data, a BIT STRING's data without its unused-bits octet, a
/// SEQUENCE's whole encoding.
#[must_use]
pub fn string_data(v: &Prim) -> &[u8] {
    match v {
        Prim::Str { data, .. } | Prim::Bits { data, .. } => data,
        Prim::Encoded { raw, .. } => raw,
        Prim::Int { content, .. } => content,
        Prim::Oid(c) => c,
        Prim::Null | Prim::Bool(_) => &[],
    }
}

/// A date as nmap 7.94's `time_to_tm` reads one (`3be01efb1:nse_ssl_cert.cc:
/// 290-342`, D1 (c): 7.94's parser, not this tree's `ASN1_TIME_to_tm`):
/// thirteen characters ending `Z` (a two-digit year, 2000 + YY below 50,
/// else 1900 + YY) or fifteen (a four-digit year), then month, day, hour,
/// minute and second, two digits each. The month must not be zero; nothing
/// else is range-checked, and the type tag is not looked at. `[year, month,
/// day, hour, min, sec]`, the year in full.
#[must_use]
pub fn time_to_tm(data: &[u8]) -> Option<[i64; 6]> {
    let n = data.len();
    if n == 0 || data[n - 1] != b'Z' {
        return None;
    }
    let (year, rest) = if n == 13 {
        let y = parse_int(&data[..2])?;
        (if y < 50 { 2000 + y } else { 1900 + y }, &data[2..])
    } else if n == 15 {
        (parse_int(&data[..4])?, &data[4..])
    } else {
        return None;
    };
    let mon = parse_int(&rest[..2]);
    if mon == Some(0) {
        return None;
    }
    let f = |i: usize| parse_int(&rest[i..i + 2]);
    let (mon, day, hour, min, sec) = (mon?, f(2)?, f(4)?, f(6)?, f(8)?);
    Some([year, mon, day, hour, min, sec])
}

/// `parse_int` (`3be01efb1:nse_ssl_cert.cc:274-296`): the first character a
/// digit, then `strtol` in base 10 over the bytes copied to a C string,
/// which must consume all of it, so a NUL ends the number and what follows
/// it is ignored.
fn parse_int(s: &[u8]) -> Option<i64> {
    if !s.first()?.is_ascii_digit() {
        return None;
    }
    let s = &s[..s.iter().position(|&b| b == 0).unwrap_or(s.len())];
    if !s.iter().all(u8::is_ascii_digit) {
        return None;
    }
    s.iter().try_fold(0i64, |acc, &d| {
        acc.checked_mul(10)?.checked_add(i64::from(d - b'0'))
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn times_are_794s() {
        assert_eq!(time_to_tm(b"200101000000Z"), Some([2020, 1, 1, 0, 0, 0]));
        assert_eq!(time_to_tm(b"500101000000Z"), Some([1950, 1, 1, 0, 0, 0]));
        assert_eq!(time_to_tm(b"21231208000000Z"), Some([2123, 12, 8, 0, 0, 0]));
        assert_eq!(
            time_to_tm(b"201399999999Z"),
            Some([2020, 13, 99, 99, 99, 99])
        );
        assert_eq!(time_to_tm(b"200001000000Z"), None);
        assert_eq!(time_to_tm(b"2001010000Z"), None);
        assert_eq!(time_to_tm(b"200101000000z"), None);
        assert_eq!(time_to_tm(b"2001010000+1Z"), None);
        // A NUL ends a field's number.
        assert_eq!(time_to_tm(b"2\x000101000000Z"), Some([2002, 1, 1, 0, 0, 0]));
        assert_eq!(time_to_tm(b"\x00\x000101000000Z"), None);
    }

    #[test]
    fn pem_wraps_at_64() {
        let p = pem(&[0u8; 49]);
        let text = String::from_utf8(p).unwrap();
        let lines: Vec<&str> = text.lines().collect();
        assert_eq!(lines[1].len(), 64);
        assert_eq!(lines[2], "AA==");
        assert_eq!(
            pem(b"ab"),
            b"-----BEGIN CERTIFICATE-----\nYWI=\n-----END CERTIFICATE-----\n"
        );
    }

    #[test]
    fn utf8_is_utf8_getc() {
        assert_eq!(utf8_chars("Ünï".as_bytes()), Some(vec![0xdc, 0x6e, 0xef]));
        assert_eq!(utf8_chars(&[0xc0, 0x80]), None); // overlong
        assert_eq!(utf8_chars(&[0xed, 0xa0, 0x80]), None); // surrogate
        assert_eq!(utf8_chars(&[0xf4, 0x90, 0x80, 0x80]), None); // past U+10FFFF
        assert_eq!(utf8_chars(&[0xf8]), None);
        assert_eq!(utf8_chars(&[0xe2, 0x82]), None);
    }
}
