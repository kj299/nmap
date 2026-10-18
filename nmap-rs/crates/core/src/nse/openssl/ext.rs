//! `X509V3_EXT_print` (OpenSSL 3.0.13, `crypto/x509/v3_prn.c` and the
//! methods of `standard_exts.h`): an extension's value as text, or `None`
//! where it returns 0 and nmap sets `error = true`. Step e2 ports the
//! printers; until then every extension is an error.

/// `X509V3_EXT_print(out, ext, 0, 0)` on an extension's OID and value.
#[must_use]
pub fn print(_oid: &[u8], _value: &[u8]) -> Option<Vec<u8>> {
    None
}
