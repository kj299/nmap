//! What the handshake needs from a peer certificate: the subject public key
//! and its type, read with a first-party DER walker, not webpki's certificate
//! rules (which reject what `d2i_X509` accepts: v1 certificates, unknown
//! extensions, odd names). This walker is the spike's stand-in for step e's
//! reader: definite lengths only, non-minimal ones tolerated as `d2i` tolerates
//! them; an indefinite length is reported, not handled.

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum KeyType {
    Rsa,
    RsaPss,
    EcP256,
    EcP384,
    EcP521,
    EcOther(Vec<u8>),
    Ed25519,
    Ed448,
    X25519,
    X448,
    Dsa,
    Dh,
    Unknown(Vec<u8>),
}

#[derive(Debug, Clone)]
pub struct Spki {
    pub key_type: KeyType,
    /// The subjectPublicKey BIT STRING's bytes after the unused-bits byte.
    pub public_key: Vec<u8>,
    /// What the outer SEQUENCE spans: a certificate entry with more bytes than
    /// this is rejected, as OpenSSL rejects it (`statem_clnt.c:1813-1816`).
    pub consumed: usize,
}

/// A DER element: tag, content range, and where the next element starts.
fn tlv(buf: &[u8], at: usize) -> Result<(u8, usize, usize, usize), &'static str> {
    let tag = *buf.get(at).ok_or("truncated")?;
    let first = *buf.get(at + 1).ok_or("truncated")?;
    let (len, body) = if first < 0x80 {
        (first as usize, at + 2)
    } else if first == 0x80 {
        return Err("indefinite length");
    } else {
        let n = (first & 0x7f) as usize;
        if n > 4 {
            return Err("length too long");
        }
        let mut len = 0usize;
        for i in 0..n {
            len = (len << 8) | *buf.get(at + 2 + i).ok_or("truncated")? as usize;
        }
        (len, at + 2 + n)
    };
    let end = body.checked_add(len).ok_or("overflow")?;
    if end > buf.len() {
        return Err("truncated");
    }
    Ok((tag, body, end, end))
}

fn expect(buf: &[u8], at: usize, tag: u8) -> Result<(usize, usize, usize), &'static str> {
    let (t, body, end, next) = tlv(buf, at)?;
    if t != tag {
        return Err("unexpected tag");
    }
    Ok((body, end, next))
}

pub fn parse_certificate(der: &[u8]) -> Result<Spki, &'static str> {
    let (cert_body, _cert_end, consumed) = expect(der, 0, 0x30)?;
    let (tbs, tbs_end, _) = expect(der, cert_body, 0x30)?;
    let mut at = tbs;
    // [0] EXPLICIT Version OPTIONAL
    if der.get(at) == Some(&0xa0) {
        at = tlv(der, at)?.3;
    }
    at = expect(der, at, 0x02)?.2; // serialNumber
    at = expect(der, at, 0x30)?.2; // signature AlgorithmIdentifier
    at = expect(der, at, 0x30)?.2; // issuer
    at = expect(der, at, 0x30)?.2; // validity
    at = expect(der, at, 0x30)?.2; // subject
    let (spki, spki_end, _) = expect(der, at, 0x30)?;
    if spki_end > tbs_end {
        return Err("spki past tbs");
    }
    let (alg, alg_end, after_alg) = expect(der, spki, 0x30)?;
    let (oid, oid_end, after_oid) = expect(der, alg, 0x06)?;
    let oid = &der[oid..oid_end];
    let params = if after_oid < alg_end {
        Some(tlv(der, after_oid)?)
    } else {
        None
    };
    let (bits, bits_end, _) = expect(der, after_alg, 0x03)?;
    if bits_end > spki_end {
        return Err("key past spki");
    }
    let unused = *der.get(bits).ok_or("empty bit string")?;
    if unused != 0 {
        return Err("key bit string has unused bits");
    }
    let public_key = der[bits + 1..bits_end].to_vec();
    let key_type = match oid {
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01] => KeyType::Rsa,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a] => KeyType::RsaPss,
        [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01] => match params {
            Some((0x06, b, e, _)) => match &der[b..e] {
                [0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07] => KeyType::EcP256,
                [0x2b, 0x81, 0x04, 0x00, 0x22] => KeyType::EcP384,
                [0x2b, 0x81, 0x04, 0x00, 0x23] => KeyType::EcP521,
                other => KeyType::EcOther(other.to_vec()),
            },
            _ => KeyType::EcOther(Vec::new()),
        },
        [0x2b, 0x65, 0x70] => KeyType::Ed25519,
        [0x2b, 0x65, 0x71] => KeyType::Ed448,
        [0x2b, 0x65, 0x6e] => KeyType::X25519,
        [0x2b, 0x65, 0x6f] => KeyType::X448,
        [0x2a, 0x86, 0x48, 0xce, 0x38, 0x04, 0x01] => KeyType::Dsa,
        [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x03, 0x01]
        | [0x2a, 0x86, 0x48, 0xce, 0x3e, 0x02, 0x01] => KeyType::Dh,
        other => KeyType::Unknown(other.to_vec()),
    };
    Ok(Spki {
        key_type,
        public_key,
        consumed,
    })
}

/// An ECDSA signature `SEQUENCE { INTEGER r, INTEGER s }` as `r || s`, each
/// left-padded to `n` bytes.
pub fn ecdsa_sig_to_fixed(der: &[u8], n: usize) -> Result<Vec<u8>, &'static str> {
    let (body, end, next) = expect(der, 0, 0x30)?;
    if next != der.len() {
        return Err("trailing bytes");
    }
    let (r, r_end, after_r) = expect(der, body, 0x02)?;
    let (s, s_end, after_s) = expect(der, after_r, 0x02)?;
    if after_s != end {
        return Err("trailing bytes in signature");
    }
    let mut out = Vec::with_capacity(2 * n);
    for int in [&der[r..r_end], &der[s..s_end]] {
        let int = int.strip_prefix(&[0u8][..]).unwrap_or(int);
        if int.len() > n || int.is_empty() {
            return Err("integer out of range");
        }
        out.extend(std::iter::repeat(0u8).take(n - int.len()));
        out.extend_from_slice(int);
    }
    Ok(out)
}
