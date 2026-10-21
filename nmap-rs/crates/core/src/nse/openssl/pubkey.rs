//! A certificate's public key as OpenSSL 3.0.13 decodes it when it reads the
//! certificate (`x509_pubkey_ex_d2i_ex`, `crypto/x509/x_pubkey.c`), and what
//! `parse_ssl_certificate` reports of it: `EVP_PKEY_base_id`'s type, the
//! size `EVP_PKEY_bits` gives, an RSA key's exponent and modulus, an EC key's
//! curve (`nse_ssl_cert.cc:608-669`). Pure.
//!
//! **Which decoder runs.** The algorithm OID's long name (`OBJ_obj2txt` with
//! names) is looked up among the provider key types' names, which OpenSSL's
//! name map extends with every legacy method's short name, long name, dotted
//! OID and PEM name, case-insensitively (`get_legacy_pkey_meth_names`,
//! `crypto/core_namemap.c`). Sixteen OIDs reach a decoder that way
//! ([`key_type`]); any other leaves no key, and `X509_get_pubkey` fails with
//! "decode error" (`X509_PUBKEY_get0`).
//!
//! **How each type decodes.** The provider decoder calls `d2i_*_PUBKEY`,
//! which runs the legacy method's `pub_decode` (`rsa_ameth.c`,
//! `dsa_ameth.c`, `dh_ameth.c`, `ec_ameth.c`, `ecx_meth.c`), then the
//! decoder's type check (`decode_der2key.c`: RSA against RSA-PSS, EC against
//! SM2). Each step's rules are its C's: `x_bignum`'s integers are unsigned
//! and unchecked, a key's integer is `d2i_ASN1_INTEGER`'s, bytes after a key
//! are ignored, parameters must have the types the C accepts.
//!
//! **Arithmetic** is on bit counts of numbers already decoded (at most a
//! certificate's size times eight) and on `BigUint`s, which do not
//! overflow.
#![allow(clippy::arithmetic_side_effects)]

use num_bigint::BigUint;

use super::asn1::{self, check_tlen, tag, Bad, Prim, Res, CONTEXT, UNIVERSAL};
use super::err::{pack, EVP_R_DECODE_ERROR, LIB_EVP};

/// What a key's own checks raise. `x509_pubkey_ex_d2i_ex` pops every error
/// its decode raised (`ERR_pop_to_mark`), so the reason is never seen: a key
/// that did not decode leaves only `X509_PUBKEY_get0`'s "decode error".
const DECODE: Bad = Bad(pack(LIB_EVP, EVP_R_DECODE_ERROR));
use super::ec::{self, Group};
use super::objects::nid_of;
use super::x509::{algor, explicit, Algor, Seq};

/// The key types the default provider decodes from a SubjectPublicKeyInfo.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Rsa,
    RsaPss,
    Dsa,
    Dh,
    Dhx,
    Ec,
    Sm2,
    X25519,
    X448,
    Ed25519,
    Ed448,
}

/// A decoded public key, as much as nmap reads of it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PubKey {
    pub kind: Kind,
    /// `EVP_PKEY_bits` (a negative size is 0).
    pub bits: u64,
    /// RSA's modulus and exponent, big-endian magnitudes.
    pub rsa: Option<(Vec<u8>, Vec<u8>)>,
    /// An EC key's group.
    pub ec: Option<EcInfo>,
}

/// What `lua_push_ecdhparams` can say of a group.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EcInfo {
    /// A built-in curve, by NID: named, or explicit parameters that match one.
    Named(u16),
    /// Explicit parameters that match no built-in curve, over a prime field
    /// or a binary one.
    Explicit { char2: bool },
}

impl PubKey {
    /// `pkey_type_to_string(EVP_PKEY_base_id(pubkey))`.
    #[must_use]
    pub fn type_name(&self) -> &'static str {
        match self.kind {
            Kind::Rsa => "rsa",
            Kind::Dsa => "dsa",
            Kind::Dh => "dh",
            Kind::Ec => "ec",
            _ => "unknown",
        }
    }
}

/// The key type an SPKI algorithm OID reaches, if any.
#[must_use]
pub fn key_type(oid: &[u8]) -> Option<Kind> {
    Some(match nid_of(oid) {
        6 | 19 => Kind::Rsa,
        912 => Kind::RsaPss,
        116 | 67 | 66 | 113 | 70 => Kind::Dsa,
        28 => Kind::Dh,
        920 => Kind::Dhx,
        408 => Kind::Ec,
        1172 => Kind::Sm2,
        1034 => Kind::X25519,
        1035 => Kind::X448,
        1087 => Kind::Ed25519,
        1088 => Kind::Ed448,
        _ => return None,
    })
}

/// The key `x509_pubkey_ex_d2i_ex` decodes from an SPKI's algorithm and
/// BIT STRING data, or `None`.
#[must_use]
pub fn decode(alg: &Algor, key: &[u8]) -> Option<PubKey> {
    let kind = key_type(&alg.oid)?;
    let r = match kind {
        Kind::Rsa | Kind::RsaPss => rsa(kind, alg, key),
        Kind::Dsa => dsa(alg, key),
        Kind::Dh | Kind::Dhx => dh(kind, alg, key),
        Kind::Ec | Kind::Sm2 => ec_key(kind, alg, key),
        Kind::X25519 | Kind::X448 | Kind::Ed25519 | Kind::Ed448 => ecx(kind, alg, key),
    };
    r.ok()
}

// ---- the integer types ---------------------------------------------------------

/// A field of `x_bignum`'s BIGNUM type: an INTEGER whose content is read by
/// `BN_bin2bn`, unsigned, with no checks on padding or emptiness.
fn bignum(p: &[u8], opt: bool) -> Res<Option<(BigUint, usize)>> {
    let Some(h) = check_tlen(p, Some((tag::INTEGER, UNIVERSAL)), opt)? else {
        return Ok(None);
    };
    if h.cons {
        return Err(DECODE);
    }
    let end = h.hdr_len + h.len;
    Ok(Some((BigUint::from_bytes_be(&p[h.hdr_len..end]), end)))
}

/// `d2i_ASN1_INTEGER` then `ASN1_INTEGER_to_BN`: a signed integer, checked as
/// `c2i_ibuf` checks; its magnitude (the sign does not change a size).
fn asn1_integer(p: &[u8]) -> Res<BigUint> {
    match asn1::primitive(p, tag::INTEGER, None, false)?.ok_or(DECODE)? {
        (Prim::Int { content, .. }, _) => {
            Ok(BigUint::from_bytes_be(&asn1::int_magnitude(&content)))
        }
        _ => Err(DECODE),
    }
}

/// `X509_ALGOR_get0`'s parameter type: `V_ASN1_UNDEF` (`None`) when absent.
fn ptype(alg: &Algor) -> Option<u32> {
    alg.param.as_ref().map(|p| match p {
        Prim::Encoded {
            utype: asn1::Utype::Sequence,
            ..
        } => tag::SEQUENCE,
        Prim::Encoded {
            utype: asn1::Utype::Set,
            ..
        } => tag::SET,
        Prim::Encoded { .. } => u32::MAX,
        Prim::Str { utype, .. } => *utype,
        Prim::Bits { .. } => tag::BIT_STRING,
        Prim::Int { utype, .. } => *utype,
        Prim::Oid(_) => tag::OBJECT,
        Prim::Null => tag::NULL,
        Prim::Bool(_) => tag::BOOLEAN,
    })
}

/// A SEQUENCE parameter's encoding (`pstr->data`): the whole element.
fn seq_param(alg: &Algor) -> Option<&[u8]> {
    match &alg.param {
        Some(Prim::Encoded {
            utype: asn1::Utype::Sequence,
            raw,
        }) => Some(raw),
        _ => None,
    }
}

// ---- RSA -----------------------------------------------------------------------

/// `rsa_pub_decode`: `RSAPublicKey` `{ n, e }` from the BIT STRING, then the
/// parameters (`ossl_rsa_param_decode`: only RSA-PSS's are read).
fn rsa(kind: Kind, alg: &Algor, key: &[u8]) -> Res<PubKey> {
    let mut s = Seq::open(key, None, false)?.ok_or(DECODE)?;
    let n = s.req(false, bignum)?;
    let e = s.req(true, bignum)?;
    s.finish()?;
    if kind == Kind::RsaPss && alg.param.is_some() {
        let raw = seq_param(alg).ok_or(DECODE)?;
        pss_params(raw)?;
    }
    Ok(PubKey {
        kind,
        bits: n.bits(),
        rsa: Some((n.to_bytes_be(), e.to_bytes_be())),
        ec: None,
    })
}

/// The digests `ossl_x509_algor_get_md` finds (`EVP_get_digestbyobj`), by
/// NID: measured on the oracle's libcrypto 3.0.13 over every OID it knows.
const PSS_DIGESTS: [u16; 36] = [
    4, 8, 64, 65, 115, 117, 119, 257, 396, 668, 669, 670, 671, 672, 673, 674, 675, 804, 1056, 1057,
    1094, 1095, 1096, 1097, 1098, 1099, 1100, 1101, 1116, 1117, 1118, 1119, 1143, 1144, 1145, 1146,
];

/// `NID_mgf1`.
const NID_MGF1: u16 = 911;

/// `ossl_rsa_pss_decode` then `ossl_rsa_sync_to_pss_params_30`:
/// `RSA_PSS_PARAMS` (four EXPLICIT optional fields), the mask generation
/// MGF1 with a SEQUENCE `X509_ALGOR` for its hash, and both hashes digests
/// OpenSSL knows. Salt length and trailer are not checked here.
fn pss_params(raw: &[u8]) -> Res<()> {
    let mut s = Seq::open(raw, None, false)?.ok_or(DECODE)?;
    let hash = s.field(true, false, |q, opt| {
        explicit(q, 0, CONTEXT, opt, |r| algor(r, false)?.ok_or(DECODE))
    })?;
    let mgf = s.field(true, false, |q, opt| {
        explicit(q, 1, CONTEXT, opt, |r| algor(r, false)?.ok_or(DECODE))
    })?;
    for t in [2, 3] {
        s.field(true, t == 3, |q, opt| {
            explicit(q, t, CONTEXT, opt, |r| {
                asn1::primitive(r, tag::INTEGER, None, false)?.ok_or(DECODE)
            })
        })?;
    }
    s.finish()?;
    let known = |a: &Algor| PSS_DIGESTS.contains(&nid_of(&a.oid));
    if let Some(mgf) = &mgf {
        if nid_of(&mgf.oid) != NID_MGF1 {
            return Err(DECODE);
        }
        let inner = seq_param(mgf).ok_or(DECODE)?;
        let (mask_hash, _) = algor(inner, false)?.ok_or(DECODE)?;
        if !known(&mask_hash) {
            return Err(DECODE);
        }
    }
    if let Some(h) = &hash {
        if !known(h) {
            return Err(DECODE);
        }
    }
    Ok(())
}

// ---- DSA and DH ----------------------------------------------------------------

/// `dsa_pub_decode`: parameters a SEQUENCE (`DSAparams` `{ p, q, g }`),
/// NULL or absent; the key an INTEGER. Then the provider's
/// `ossl_d2i_DSA_PUBKEY` refuses a key without `p`, `q` and `g`, so only the
/// SEQUENCE decodes (measured: the `k-dsa` rows). Bits are `p`'s.
fn dsa(alg: &Algor, key: &[u8]) -> Res<PubKey> {
    let p = match ptype(alg) {
        Some(tag::SEQUENCE) => {
            let raw = seq_param(alg).ok_or(DECODE)?;
            let mut s = Seq::open(raw, None, false)?.ok_or(DECODE)?;
            let p = s.req(false, bignum)?;
            s.req(false, bignum)?;
            s.req(true, bignum)?;
            s.finish()?;
            p
        }
        _ => return Err(DECODE),
    };
    asn1_integer(key)?;
    Ok(PubKey {
        kind: Kind::Dsa,
        bits: p.bits(),
        rsa: None,
        ec: None,
    })
}

/// `dh_pub_decode`: parameters a SEQUENCE, `DHparams` `{ p, g, length
/// INTEGER OPTIONAL }` for DH or `DHxparams` `{ p, g, q, j OPTIONAL,
/// vparams OPTIONAL }` for DHX; the key an INTEGER. Bits are `p`'s.
fn dh(kind: Kind, alg: &Algor, key: &[u8]) -> Res<PubKey> {
    let raw = match ptype(alg) {
        Some(tag::SEQUENCE) => seq_param(alg).ok_or(DECODE)?,
        _ => return Err(DECODE),
    };
    let mut s = Seq::open(raw, None, false)?.ok_or(DECODE)?;
    let p = s.req(false, bignum)?;
    if kind == Kind::Dh {
        s.req(false, bignum)?;
        s.field(true, true, zint32)?;
    } else {
        s.req(false, bignum)?;
        s.req(false, bignum)?;
        s.field(true, false, bignum)?;
        s.field(true, true, dh_vparams)?;
    }
    s.finish()?;
    asn1_integer(key)?;
    Ok(PubKey {
        kind,
        bits: p.bits(),
        rsa: None,
        ec: None,
    })
}

/// `ZINT32`: [`int32`] (its zero default only changes encoding).
fn zint32(p: &[u8], opt: bool) -> Res<Option<((), usize)>> {
    Ok(int32(p, opt)?.map(|(_, n)| ((), n)))
}

/// `DHvparams`: `{ seed BIT STRING, counter BIGNUM }`.
fn dh_vparams(p: &[u8], opt: bool) -> Res<Option<((), usize)>> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    s.req(false, |q, opt| super::x509::bit_string(q, None, opt))?;
    s.req(true, bignum)?;
    Ok(Some(((), s.finish()?)))
}

// ---- EC, SM2 and the ECX keys ----------------------------------------------------

/// `NID_sm2`.
const NID_SM2: u16 = 1172;

/// `eckey_pub_decode`: the group from the parameters
/// (`ossl_ec_key_param_from_x509_algor`: an OID naming a built-in curve, or
/// explicit parameters), then the point (`o2i_ECPublicKey`). A key on the
/// SM2 curve is an SM2 key whichever OID carried it (`EVP_PKEY_assign`:
/// "the SM2 curve must be SM2 type"), and the SM2 OID with any other curve
/// is no key (`ec_check`); measured on the `k-sm2` and `k-ec` rows.
fn ec_key(kind: Kind, alg: &Algor, key: &[u8]) -> Res<PubKey> {
    let (group, info) = match &alg.param {
        Some(Prim::Oid(c)) => {
            let nid = nid_of(c);
            let curve = ec::curve(nid).ok_or(DECODE)?;
            (Group::builtin(curve), EcInfo::Named(nid))
        }
        Some(Prim::Encoded {
            utype: asn1::Utype::Sequence,
            raw,
        }) => ec_parameters(raw)?,
        _ => return Err(DECODE),
    };
    if !group.point_ok(key) {
        return Err(DECODE);
    }
    let sm2 = info == EcInfo::Named(NID_SM2);
    if kind == Kind::Sm2 && !sm2 {
        return Err(DECODE);
    }
    Ok(PubKey {
        kind: if sm2 { Kind::Sm2 } else { kind },
        bits: group.order_bits(),
        rsa: None,
        ec: Some(info),
    })
}

/// `NID_X9_62_prime_field`, `NID_X9_62_characteristic_two_field` and the
/// three bases.
const NID_PRIME_FIELD: u16 = 406;
const NID_CHAR2_FIELD: u16 = 407;
const NID_TP_BASIS: u16 = 682;
const NID_PP_BASIS: u16 = 683;
/// `OPENSSL_ECC_MAX_FIELD_BITS`.
const MAX_FIELD_BITS: u64 = 661;

/// `d2i_ECParameters` on a SEQUENCE parameter: `ECPKPARAMETERS`, which for
/// a SEQUENCE is its explicit `ECPARAMETERS` arm, then
/// `EC_GROUP_new_from_ecparameters` (`crypto/ec/ec_asn1.c`): the field (an
/// odd prime of at least 3 bits, or a trinomial or pentanomial of degree at
/// most 661), the coefficients reduced, the base point decoded on that
/// curve, the order within the Hasse bound, a cofactor not negative. A
/// group whose numbers equal a built-in curve's becomes that curve
/// (`ossl_ec_curve_nid_from_params`, the seed ignored and the cofactor
/// guessed); any other is explicit.
fn ec_parameters(raw: &[u8]) -> Res<(Group, EcInfo)> {
    let mut s = Seq::open(raw, None, false)?.ok_or(DECODE)?;
    s.req(false, int32)?;
    let (char2, field) = s.req(false, field_id)?;
    let (a, b) = s.req(false, x962_curve)?;
    let base = s.req(false, super::x509::octet_string)?;
    let order = s.req(false, signed_integer)?;
    let cofactor = s.field(true, true, signed_integer)?;
    s.finish()?;
    let (p, field_bits) = match field {
        Field::Prime((neg, p)) => {
            if neg || p.bits() == 0 {
                return Err(DECODE);
            }
            let bits = p.bits();
            if bits > MAX_FIELD_BITS {
                return Err(DECODE);
            }
            // EC_GROUP_new_curve_GFp: Montgomery needs an odd modulus, and
            // ec_GFp_simple_group_set_curve a prime "> 3".
            if bits <= 2 || !p.bit(0) {
                return Err(DECODE);
            }
            (p, bits)
        }
        Field::Char2(m, poly) => (poly, m),
    };
    let reduce = |v: &BigUint| {
        if char2 {
            ec::Gf2m::new(&p).elem(v)
        } else {
            v % &p
        }
    };
    let (a, b) = (
        reduce(&BigUint::from_bytes_be(&a)),
        reduce(&BigUint::from_bytes_be(&b)),
    );
    let mut group = Group {
        char2,
        p: p.clone(),
        a: a.clone(),
        b: b.clone(),
        order: BigUint::default(),
    };
    if base.is_empty() {
        return Err(DECODE);
    }
    let (gx, gy) = group.decode_point(&base).ok_or(DECODE)?;
    let (oneg, order) = order;
    if oneg || order.bits() == 0 || order.bits() > field_bits + 1 {
        return Err(DECODE);
    }
    // EC_GROUP_set_generator's own bound is against the field's bits, which
    // for a binary field is the polynomial's, one more than m.
    if order.bits() > p.bits() + 1 {
        return Err(DECODE);
    }
    if let Some((cneg, c)) = &cofactor {
        if *cneg && c.bits() != 0 {
            return Err(DECODE);
        }
    }
    group.order = order;
    // ossl_ec_curve_nid_from_params on the copy: no seed, the cofactor
    // guessed. A generator at infinity has no affine coordinates: the
    // lookup fails, and so does the decode.
    let (gx, gy) = match (gx, gy) {
        (Some(x), Some(y)) => (x, y),
        _ => return Err(DECODE),
    };
    let guessed = guess_cofactor(&group);
    let param_len = byte_len(&group.order).max(byte_len(&group.p));
    // BN_bn2binpad: big-endian, zero-padded to param_len (zero is all
    // padding: to_bytes_be gives it one octet).
    let pad = |v: &BigUint| {
        let bytes = if v.bits() == 0 {
            Vec::new()
        } else {
            v.to_bytes_be()
        };
        let mut out = vec![0u8; param_len.saturating_sub(bytes.len())];
        out.extend_from_slice(&bytes);
        out
    };
    let mine: Vec<u8> = [&group.p, &group.a, &group.b, &gx, &gy, &group.order]
        .iter()
        .flat_map(|v| pad(v))
        .collect();
    for c in ec::curves() {
        if c.char2 != char2 || c.p.len() != param_len {
            continue;
        }
        if guessed.bits() != 0 && guessed != BigUint::from(c.cofactor) {
            continue;
        }
        let theirs: Vec<u8> = [c.p, c.a, c.b, c.x, c.y, c.order].concat();
        if theirs == mine {
            return Ok((group, EcInfo::Named(c.nid)));
        }
    }
    Ok((group, EcInfo::Explicit { char2 }))
}

fn byte_len(v: &BigUint) -> usize {
    usize::try_from(v.bits().div_ceil(8)).unwrap_or(usize::MAX)
}

/// `ec_guess_cofactor`: 0 when the order is too small to guess from, else
/// `(q + 1 + n/2) / n` with `q` the field's size.
fn guess_cofactor(g: &Group) -> BigUint {
    if g.order.bits() <= g.p.bits().div_ceil(2) + 3 {
        return BigUint::default();
    }
    let q = if g.char2 {
        BigUint::from(1u8) << (g.p.bits() - 1)
    } else {
        g.p.clone()
    };
    (q + 1u8 + (&g.order >> 1u8)) / &g.order
}

/// An `X9_62_FIELDID`'s field: a prime (sign and magnitude), or a binary
/// field's degree and reduction polynomial.
enum Field {
    Prime((bool, BigUint)),
    Char2(u64, BigUint),
}

/// `X9_62_FIELDID`: `{ fieldType OBJECT, ANY DEFINED BY fieldType }`, a
/// prime field's INTEGER or a binary field's `X9_62_CHARACTERISTIC_TWO`;
/// any other type reads its parameter as ANY and is then refused.
fn field_id(p: &[u8], opt: bool) -> Res<Option<((bool, Field), usize)>> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let t = s.req(false, super::x509::oid)?;
    let out = match nid_of(&t) {
        NID_PRIME_FIELD => (false, Field::Prime(s.req(true, signed_integer)?)),
        NID_CHAR2_FIELD => {
            let (m, poly) = s.req(true, char_two)?;
            (true, Field::Char2(m, poly))
        }
        _ => {
            s.req(true, |q, _| asn1::any(q).map(Some))?;
            return Err(DECODE);
        }
    };
    Ok(Some((out, s.finish()?)))
}

/// `X9_62_CHARACTERISTIC_TWO`: `{ m INT32, type OBJECT, ANY DEFINED BY type }`
/// with `EC_GROUP_new_from_ecparameters`' checks: `m` at most 661, a
/// trinomial basis `0 < k < m` or a pentanomial `0 < k1 < k2 < k3 < m`; the
/// normal basis is not implemented, any other refused. Then
/// `ossl_ec_GF2m_simple_group_set_curve` takes the polynomial.
fn char_two(p: &[u8], opt: bool) -> Res<Option<((u64, BigUint), usize)>> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let m = s.req(false, int32)?;
    let t = s.req(false, super::x509::oid)?;
    let mut poly = BigUint::default();
    let set = |poly: &mut BigUint, k: i64| poly.set_bit(u64::try_from(k).unwrap_or(0), true);
    match nid_of(&t) {
        NID_TP_BASIS => {
            let (neg, k) = s.req(true, signed_integer)?;
            let k = asn1_integer_get(neg, &k);
            if m > MAX_FIELD_BITS as i64 || !(m > k && k > 0) {
                return Err(DECODE);
            }
            for e in [m, k, 0] {
                set(&mut poly, e);
            }
        }
        NID_PP_BASIS => {
            let (k1, k2, k3) = s.req(true, pentanomial)?;
            if m > MAX_FIELD_BITS as i64 || !(m > k3 && k3 > k2 && k2 > k1 && k1 > 0) {
                return Err(DECODE);
            }
            for e in [m, k1, k2, k3, 0] {
                set(&mut poly, e);
            }
        }
        _ => {
            s.req(true, |q, _| asn1::any(q).map(Some))?;
            return Err(DECODE);
        }
    }
    let used = s.finish()?;
    Ok(Some(((u64::try_from(m).unwrap_or(0), poly), used)))
}

/// `X9_62_PENTANOMIAL`: three INT32s.
fn pentanomial(p: &[u8], opt: bool) -> asn1::Field<(i64, i64, i64)> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let k1 = s.req(false, int32)?;
    let k2 = s.req(false, int32)?;
    let k3 = s.req(true, int32)?;
    Ok(Some(((k1, k2, k3), s.finish()?)))
}

/// `X9_62_CURVE`: `{ a OCTET STRING, b OCTET STRING, seed BIT STRING
/// OPTIONAL }`; a seed present must not be empty.
fn x962_curve(p: &[u8], opt: bool) -> asn1::Field<(Vec<u8>, Vec<u8>)> {
    let Some(mut s) = Seq::open(p, None, opt)? else {
        return Ok(None);
    };
    let a = s.req(false, super::x509::octet_string)?;
    let b = s.req(false, super::x509::octet_string)?;
    let seed = s.field(true, true, |q, opt| super::x509::bit_string(q, None, opt))?;
    let used = s.finish()?;
    if seed.is_some_and(|(_, d)| d.is_empty()) {
        return Err(DECODE);
    }
    Ok(Some(((a, b), used)))
}

/// An `ASN1_INTEGER` field, as `ASN1_INTEGER_to_BN` reads it: sign and
/// magnitude.
fn signed_integer(p: &[u8], opt: bool) -> Res<Option<((bool, BigUint), usize)>> {
    Ok(match asn1::primitive(p, tag::INTEGER, None, opt)? {
        Some((Prim::Int { content, neg, .. }, n)) => Some((
            (neg, BigUint::from_bytes_be(&asn1::int_magnitude(&content))),
            n,
        )),
        Some(_) => return Err(DECODE),
        None => None,
    })
}

/// `ASN1_INTEGER_get`: the value as a `long`, -1 for one that does not fit.
fn asn1_integer_get(neg: bool, mag: &BigUint) -> i64 {
    let Ok(v) = u64::try_from(mag) else {
        return -1;
    };
    match (neg, i64::try_from(v)) {
        (false, Ok(v)) => v,
        (true, Ok(v)) => -v,
        (true, Err(_)) if v == 1 << 63 => i64::MIN,
        _ => -1,
    }
}

/// `INT32` (`x_int64.c`): empty content is 0; otherwise `c2i_ibuf`'s
/// checks, at most 8 octets, and in `i32`'s range.
fn int32(p: &[u8], opt: bool) -> Res<Option<(i64, usize)>> {
    let Some(h) = check_tlen(p, Some((tag::INTEGER, UNIVERSAL)), opt)? else {
        return Ok(None);
    };
    if h.cons {
        return Err(DECODE);
    }
    let end = h.hdr_len + h.len;
    let c = &p[h.hdr_len..end];
    if c.is_empty() {
        return Ok(Some((0, end)));
    }
    let neg = asn1::c2i_ibuf_check(c)?;
    let mag = asn1::int_magnitude(c);
    if mag.len() > 8 {
        return Err(DECODE);
    }
    let v = mag.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
    let v = if neg {
        if v > 1 << 31 {
            return Err(DECODE);
        }
        -(i64::try_from(v).unwrap_or(0))
    } else {
        if v > (1 << 31) - 1 {
            return Err(DECODE);
        }
        i64::try_from(v).unwrap_or(0)
    };
    Ok(Some((v, end)))
}

/// `ecx_pub_decode` (`ossl_ecx_key_op`): no parameters at all, and a key of
/// exactly the type's length. Bits are fixed: 253, 448, 256, 456.
fn ecx(kind: Kind, alg: &Algor, key: &[u8]) -> Res<PubKey> {
    if alg.param.is_some() {
        return Err(DECODE);
    }
    let (len, bits) = match kind {
        Kind::X25519 => (32, 253),
        Kind::X448 => (56, 448),
        Kind::Ed25519 => (32, 256),
        _ => (57, 456),
    };
    if key.len() != len {
        return Err(DECODE);
    }
    Ok(PubKey {
        kind,
        bits,
        rsa: None,
        ec: None,
    })
}
