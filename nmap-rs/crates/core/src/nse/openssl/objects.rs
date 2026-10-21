//! OpenSSL's object table and how it names an OID (`crypto/objects/obj_dat.c`),
//! over the table `crates/vendor/openssl-data/gen.py` generates from
//! OpenSSL 3.0.13's `objects.txt` (D11): `OBJ_obj2nid`, `OBJ_nid2sn`,
//! `OBJ_nid2ln` and `OBJ_obj2txt`. Pure; the certificate code (step e) names
//! subject keys, signature algorithms, curves and extensions with it.
//!
//! **Arithmetic** is on `BigUint`s, which do not overflow.
#![allow(clippy::arithmetic_side_effects)]

use num_bigint::BigUint;

use super::objects_table::{BY_DER, OBJECTS};

/// One entry of `nid_objs`: the names, and the OID's DER content octets
/// (empty for an object with no OID).
pub struct Object {
    pub sn: &'static str,
    pub ln: &'static str,
    pub der: &'static [u8],
}

/// `NID_undef`.
pub const NID_UNDEF: u16 = 0;

/// `OBJ_obj2nid` on an OID's content octets: the NID OpenSSL knows it by, or
/// [`NID_UNDEF`].
pub fn nid_of(der: &[u8]) -> u16 {
    match BY_DER.binary_search_by(|&n| OBJECTS[usize::from(n)].der.cmp(der)) {
        Ok(i) => BY_DER[i],
        Err(_) => NID_UNDEF,
    }
}

/// `OBJ_nid2sn`: `None` for a NID OpenSSL leaves unassigned or never had.
pub fn short_name(nid: u16) -> Option<&'static str> {
    let o = OBJECTS.get(usize::from(nid))?;
    (nid == NID_UNDEF || !o.sn.is_empty()).then_some(o.sn)
}

/// `OBJ_nid2ln`, as [`short_name`].
pub fn long_name(nid: u16) -> Option<&'static str> {
    let o = OBJECTS.get(usize::from(nid))?;
    (nid == NID_UNDEF || !o.ln.is_empty()).then_some(o.ln)
}

/// A NID's OID content octets (`OBJ_nid2obj(nid)->data`), empty if it has
/// none.
pub fn der_of(nid: u16) -> &'static [u8] {
    OBJECTS.get(usize::from(nid)).map_or(&[], |o| o.der)
}

/// The longest OID content `OBJ_obj2txt` renders as numbers: RFC 2578's 128
/// sub-identifiers of 32 bits (`obj_dat.c`); longer is an error.
pub const OBJ_TXT_MAX_CONTENT: usize = 586;

/// `OBJ_obj2txt(NULL, 0, obj, no_name)`'s text, whole: the long name (else
/// the short name) of an OID OpenSSL knows when `no_name` is false, otherwise
/// the dotted numbers, the first two arcs from the first sub-identifier as
/// X.690 packs them (`2.` and the rest past 80). `None` where it returns -1:
/// content over [`OBJ_TXT_MAX_CONTENT`] bytes, or a last octet with the
/// continuation bit set. A caller with a fixed buffer keeps a prefix of this
/// (`OBJ_obj2txt` always writes one, NUL-terminated) and is told this length.
pub fn obj2txt(der: &[u8], no_name: bool) -> Option<String> {
    if !no_name {
        let nid = nid_of(der);
        if nid != NID_UNDEF {
            if let Some(s) = long_name(nid).or_else(|| short_name(nid)) {
                return Some(s.to_string());
            }
        }
    }
    if der.len() > OBJ_TXT_MAX_CONTENT {
        return None;
    }
    let mut out = String::new();
    let mut first = true;
    let mut p = der;
    while !p.is_empty() {
        // One sub-identifier, at most 586 bytes of 7 bits, so a BigUint
        // where it outgrows a u64 (the C's switch to a BIGNUM).
        let mut v = BigUint::default();
        loop {
            let (&c, rest) = p.split_first()?;
            p = rest;
            if p.is_empty() && c & 0x80 != 0 {
                return None;
            }
            v = (v << 7u8) | BigUint::from(c & 0x7f);
            if c & 0x80 == 0 {
                break;
            }
        }
        if first {
            first = false;
            let eighty = BigUint::from(80u8);
            if v >= eighty {
                out.push('2');
                v -= eighty;
            } else {
                let small = u8::try_from(&v).unwrap_or(0);
                out.push(char::from(b'0' + small / 40));
                v = BigUint::from(small % 40);
            }
        }
        out.push('.');
        out.push_str(&v.to_str_radix(10));
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn der(text: &str) -> Vec<u8> {
        let arcs: Vec<u64> = text.split('.').map(|a| a.parse().unwrap()).collect();
        let mut out = vec![u8::try_from(arcs[0] * 40 + arcs[1]).unwrap()];
        for &a in &arcs[2..] {
            let mut r = vec![u8::try_from(a & 0x7f).unwrap()];
            let mut v = a >> 7;
            while v != 0 {
                r.push(0x80 | u8::try_from(v & 0x7f).unwrap());
                v >>= 7;
            }
            out.extend(r.iter().rev());
        }
        out
    }

    #[test]
    fn names_are_openssls() {
        let cn = nid_of(&der("2.5.4.3"));
        assert_eq!(
            (short_name(cn), long_name(cn)),
            (Some("CN"), Some("commonName"))
        );
        let rsa = nid_of(&der("1.2.840.113549.1.1.1"));
        assert_eq!(long_name(rsa), Some("rsaEncryption"));
        // An !Alias obj_mac.num numbers is "NULL" twice (obj_dat.pl).
        assert_eq!(
            (short_name(404), long_name(404)),
            (Some("NULL"), Some("NULL"))
        );
        assert_eq!(
            (short_name(0), long_name(0)),
            (Some("UNDEF"), Some("undefined"))
        );
        // 1.3 is both org (379) and identified-organization (676).
        assert_eq!(nid_of(&der("1.3")), 379);
        assert_eq!(nid_of(&der("1.2.3.4")), NID_UNDEF);
        assert_eq!(short_name(1247), Some("id-ct-signedChecklist"));
        assert_eq!(short_name(1248), None);
    }

    #[test]
    fn obj2txt_is_openssls() {
        assert_eq!(
            obj2txt(&der("2.5.4.3"), false).as_deref(),
            Some("commonName")
        );
        assert_eq!(obj2txt(&der("2.5.4.3"), true).as_deref(), Some("2.5.4.3"));
        assert_eq!(obj2txt(&der("1.2.3.4"), false).as_deref(), Some("1.2.3.4"));
        assert_eq!(
            obj2txt(&[0x88, 0x37, 0x01], true).as_deref(),
            Some("2.999.1")
        );
        assert_eq!(obj2txt(&[0x7f], true).as_deref(), Some("2.47"));
        assert_eq!(obj2txt(&[0x27], true).as_deref(), Some("0.39"));
        // A sub-identifier past 2^64 goes through the BIGNUM path.
        let big = [
            0x2a, 0x82, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x80, 0x00,
        ];
        assert_eq!(
            obj2txt(&big, true).as_deref(),
            Some("1.2.18446744073709551616")
        );
        assert_eq!(obj2txt(&[0x2a, 0x86], true), None);
        assert_eq!(obj2txt(&[0x2a; OBJ_TXT_MAX_CONTENT + 1], true), None);
        assert!(obj2txt(&[0x2a; OBJ_TXT_MAX_CONTENT], true).is_some());
    }
}
