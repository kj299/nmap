//! OpenSSL's error codes, as far as the certificate code raises them: the
//! packed code `ERR_PACK(lib, 0, reason)` and the text `ERR_error_string`
//! makes of it, over the table `crates/vendor/openssl-data/gen.py` generates
//! from OpenSSL 3.0.13's `openssl.txt` and `err.c` (checked against libcrypto
//! for every entry).
//!
//! nmap prints one of these: when a certificate's key did not decode,
//! `parse_ssl_cert` returns "Error parsing cert: " and `ERR_error_string` of
//! `ERR_get_error()`, the *oldest* error queued (`nse_ssl_cert.cc:608-612`).
//! Within one call, that is the first error an extension's printing raised,
//! else the key's "decode error" (`cert`).

pub use super::errors_table::*;
use super::errors_table::{LIBS, REASONS};

/// `ERR_PACK(lib, 0, reason)`.
#[must_use]
pub const fn pack(lib: u32, reason: u32) -> u32 {
    (lib << 23) | (reason & 0x7f_ffff)
}

/// `ERR_error_string`: `error:%08lX:LIB::REASON`, the library and reason
/// named where OpenSSL names them, `lib(N)` and `reason(N)` where not. A
/// reason is looked up under its library, then under library 0, where the
/// reasons every library shares are (`ERR_reason_error_string`).
#[must_use]
pub fn error_string(code: u32) -> String {
    let lib = code >> 23;
    let reason = code & 0x7f_ffff;
    let lname = LIBS
        .iter()
        .find(|&&(l, _)| l == lib)
        .map_or_else(|| format!("lib({lib})"), |&(_, n)| n.to_string());
    let find = |lib: u32| REASONS.binary_search_by(|&(l, r, _)| (l, r).cmp(&(lib, reason)));
    let rname = find(lib).or_else(|_| find(0)).map_or_else(
        |_| format!("reason({reason})"),
        |i| REASONS[i].2.to_string(),
    );
    format!("error:{code:08X}:{lname}::{rname}")
}

/// An ASN.1 reason, packed.
#[must_use]
pub const fn asn1(reason: u32) -> u32 {
    pack(LIB_ASN1, reason)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn strings_are_err_error_strings() {
        assert_eq!(
            error_string(asn1(ASN1_R_HEADER_TOO_LONG)),
            "error:0680007B:asn1 encoding routines::header too long"
        );
        assert_eq!(
            error_string(pack(LIB_EVP, EVP_R_DECODE_ERROR)),
            "error:03000072:digital envelope routines::decode error"
        );
        assert_eq!(
            error_string(asn1(ASN1_R_NO_MATCHING_CHOICE_TYPE)),
            "error:0680008F:asn1 encoding routines::no matching choice type"
        );
        assert_eq!(
            error_string(pack(LIB_X509V3, ERR_R_MALLOC_FAILURE)),
            "error:110C0100:X509 V3 routines::malloc failure"
        );
    }
}
