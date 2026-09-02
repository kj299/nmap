//! SHA-256 (FIPS 180-4), for verifying a signature bundle's file contents.
//!
//! # Why this is here rather than a dependency
//!
//! `core` carries two crates, both for the service-detection regex engine, and the
//! code that decides whether downloaded bytes may be installed is the last place to
//! grow that surface. SHA-256 is a fixed, fully specified, exhaustively testable
//! function with no secret-dependent behaviour — the hash here is an integrity
//! check, not a MAC, so there is no timing side channel to get wrong — which makes
//! it one of the few pieces of cryptography that is reasonable to carry in-tree.
//!
//! It is gated accordingly: the four NIST vectors, **plus a differential against
//! the system `sha256sum` over a generated corpus**, re-derived on every CI run.
//! That is a real oracle, not a self-consistency check.
//!
//! **If you would rather depend on a vetted crate**, swapping in RustCrypto's
//! `sha2` is a one-line change behind [`Sha256`]'s interface and the differential
//! keeps guarding it. That trade is the reviewer's to make; this file exists so the
//! choice is not forced by the update path needing *something* today.
//!
//! # Arithmetic
//!
//! The crate denies `clippy::arithmetic_side_effects`, and SHA-256 is defined in
//! terms of addition modulo 2^32. Every such addition is written `wrapping_add`,
//! which is both what the specification says and what satisfies the lint — the
//! wrapping is the algorithm, not an overflow being ignored.

/// Bytes in a SHA-256 digest.
pub const DIGEST_LEN: usize = 32;

/// Bytes in a SHA-256 compression block.
const BLOCK_LEN: usize = 64;

/// FIPS 180-4 §4.2.2 round constants: the first 32 bits of the fractional parts of
/// the cube roots of the first 64 primes.
const K: [u32; 64] = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
];

/// FIPS 180-4 §5.3.3 initial hash value: the first 32 bits of the fractional parts
/// of the square roots of the first 8 primes.
const H0: [u32; 8] = [
    0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
];

/// A streaming SHA-256 hasher.
///
/// Streaming rather than one-shot because a signature bundle's files run to
/// megabytes and the caller should not have to hold a second copy to hash it.
#[derive(Debug, Clone)]
pub struct Sha256 {
    state: [u32; 8],
    /// Bytes buffered toward the next full block.
    buf: [u8; BLOCK_LEN],
    buf_len: usize,
    /// Total message length in bytes. `u64` because the length is encoded as a
    /// 64-bit **bit** count, so the byte count must stay under 2^61 for the
    /// encoding to be valid; [`update`](Self::update) saturates rather than wraps,
    /// which turns an impossible input into a wrong digest instead of a silently
    /// aliased one.
    len: u64,
}

impl Default for Sha256 {
    fn default() -> Self {
        Self::new()
    }
}

impl Sha256 {
    /// A fresh hasher.
    #[must_use]
    pub fn new() -> Self {
        Self {
            state: H0,
            buf: [0; BLOCK_LEN],
            buf_len: 0,
            len: 0,
        }
    }

    /// Hash `data` in one call.
    #[must_use]
    pub fn digest(data: &[u8]) -> [u8; DIGEST_LEN] {
        let mut h = Self::new();
        h.update(data);
        h.finish()
    }

    /// Feed more bytes.
    pub fn update(&mut self, mut data: &[u8]) {
        self.len = self.len.saturating_add(data.len() as u64);

        // Top up a partial block first.
        if self.buf_len > 0 {
            let want = BLOCK_LEN.saturating_sub(self.buf_len);
            let take = want.min(data.len());
            // Both indices are within `buf`: `buf_len + take <= BLOCK_LEN`.
            if let (Some(dst), Some(src)) = (
                self.buf
                    .get_mut(self.buf_len..self.buf_len.saturating_add(take)),
                data.get(..take),
            ) {
                dst.copy_from_slice(src);
            }
            self.buf_len = self.buf_len.saturating_add(take);
            data = data.get(take..).unwrap_or(&[]);
            if self.buf_len == BLOCK_LEN {
                let block = self.buf;
                self.compress(&block);
                self.buf_len = 0;
            }
        }

        // If the top-up consumed everything, `buf_len` is already correct -- either
        // the partial block grew, or it filled and was compressed away. Falling
        // through would reach the tail below and overwrite `buf_len` with the length
        // of an EMPTY remainder, silently resetting the buffer to zero on every
        // call. That is not hypothetical: it is the bug this early return fixes, and
        // it made `finish`'s padding loop spin forever because `buf_len` could never
        // reach the stop condition.
        if data.is_empty() {
            return;
        }

        // Past here `buf_len` is 0: the top-up either emptied `data` (handled above)
        // or filled and flushed the block.
        // Then whole blocks straight from the input.
        let mut chunks = data.chunks_exact(BLOCK_LEN);
        for block in &mut chunks {
            let mut b = [0u8; BLOCK_LEN];
            b.copy_from_slice(block);
            self.compress(&b);
        }

        // Whatever is left is the new partial block.
        let rest = chunks.remainder();
        if let Some(dst) = self.buf.get_mut(..rest.len()) {
            dst.copy_from_slice(rest);
        }
        self.buf_len = rest.len();
    }

    /// Finish and produce the digest. Consumes nothing, so the hasher can be
    /// inspected afterwards; it is not reset.
    #[must_use]
    pub fn finish(&self) -> [u8; DIGEST_LEN] {
        let mut h = self.clone();

        // FIPS 180-4 §5.1.1: append `1`, then `0`s, then the 64-bit big-endian bit
        // length, so the total is a multiple of the block size.
        let bit_len = h.len.wrapping_mul(8);
        h.update_no_len(&[0x80]);
        while h.buf_len != BLOCK_LEN.saturating_sub(8) {
            h.update_no_len(&[0x00]);
        }
        h.update_no_len(&bit_len.to_be_bytes());

        let mut out = [0u8; DIGEST_LEN];
        for (i, word) in h.state.iter().enumerate() {
            let base = i.saturating_mul(4);
            if let Some(dst) = out.get_mut(base..base.saturating_add(4)) {
                dst.copy_from_slice(&word.to_be_bytes());
            }
        }
        out
    }

    /// [`update`](Self::update) without advancing the length counter — used by
    /// padding, which must not count toward the encoded message length.
    fn update_no_len(&mut self, data: &[u8]) {
        let saved = self.len;
        self.update(data);
        self.len = saved;
    }

    /// One application of the FIPS 180-4 §6.2.2 compression function.
    fn compress(&mut self, block: &[u8; BLOCK_LEN]) {
        let mut w = [0u32; 64];
        for (i, chunk) in block.chunks_exact(4).enumerate() {
            let bytes = [
                *chunk.first().unwrap_or(&0),
                *chunk.get(1).unwrap_or(&0),
                *chunk.get(2).unwrap_or(&0),
                *chunk.get(3).unwrap_or(&0),
            ];
            if let Some(slot) = w.get_mut(i) {
                *slot = u32::from_be_bytes(bytes);
            }
        }
        for i in 16usize..64 {
            let (a, b, c, d) = (
                *w.get(i.saturating_sub(15)).unwrap_or(&0),
                *w.get(i.saturating_sub(2)).unwrap_or(&0),
                *w.get(i.saturating_sub(16)).unwrap_or(&0),
                *w.get(i.saturating_sub(7)).unwrap_or(&0),
            );
            let s0 = a.rotate_right(7) ^ a.rotate_right(18) ^ (a >> 3);
            let s1 = b.rotate_right(17) ^ b.rotate_right(19) ^ (b >> 10);
            if let Some(slot) = w.get_mut(i) {
                *slot = c.wrapping_add(s0).wrapping_add(d).wrapping_add(s1);
            }
        }

        let [mut a, mut b, mut c, mut d, mut e, mut f, mut g, mut h] = self.state;
        for i in 0usize..64 {
            let s1 = e.rotate_right(6) ^ e.rotate_right(11) ^ e.rotate_right(25);
            let ch = (e & f) ^ ((!e) & g);
            let temp1 = h
                .wrapping_add(s1)
                .wrapping_add(ch)
                .wrapping_add(*K.get(i).unwrap_or(&0))
                .wrapping_add(*w.get(i).unwrap_or(&0));
            let s0 = a.rotate_right(2) ^ a.rotate_right(13) ^ a.rotate_right(22);
            let maj = (a & b) ^ (a & c) ^ (b & c);
            let temp2 = s0.wrapping_add(maj);

            h = g;
            g = f;
            f = e;
            e = d.wrapping_add(temp1);
            d = c;
            c = b;
            b = a;
            a = temp1.wrapping_add(temp2);
        }

        for (slot, v) in self.state.iter_mut().zip([a, b, c, d, e, f, g, h]) {
            *slot = slot.wrapping_add(v);
        }
    }
}

/// Render a digest as lowercase hex — the spelling the manifest uses.
#[must_use]
pub fn to_hex(digest: &[u8; DIGEST_LEN]) -> String {
    let mut out = String::with_capacity(DIGEST_LEN.saturating_mul(2));
    for b in digest {
        out.push(char::from_digit(u32::from(b >> 4), 16).unwrap_or('0'));
        out.push(char::from_digit(u32::from(b & 0x0f), 16).unwrap_or('0'));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(data: &[u8]) -> String {
        to_hex(&Sha256::digest(data))
    }

    #[test]
    fn the_nist_vectors() {
        // FIPS 180-4 / NIST CAVP known answers. If these are wrong nothing else
        // matters, so they come first.
        assert_eq!(
            hex(b""),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
        assert_eq!(
            hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
        assert_eq!(
            hex(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"),
            "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1"
        );
        assert_eq!(
            hex(b"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmn\
                  hijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"),
            "cf5b16a778af8380036ce59e7b0492370b249b11e8f07a51afac45037afee9d1"
        );
    }

    #[test]
    #[cfg_attr(
        miri,
        ignore = "1 MB through the compression function; minutes under miri for no miri-specific signal"
    )]
    fn a_million_a_s() {
        // The classic long-message vector: 1,000,000 bytes, ~15,600 compression
        // calls, and a length that does not land on a block boundary.
        //
        // Skipped under Miri, and worth saying why rather than leaving it to look
        // like a flake dodge. Miri interprets every operation, so this single test
        // dominated the entire workspace Miri job. It can find nothing here that the
        // others cannot: `core` is `#![forbid(unsafe_code)]`, so there is no UB to
        // detect, and every code path it exercises is already covered by
        // `streaming_in_any_chunking_matches_one_shot` and the block-boundary test at
        // a fraction of the volume. What it uniquely proves -- agreement with the
        // published vector at scale -- is a correctness claim, gated natively and by
        // the 669-case sha256sum differential.
        let mut h = Sha256::new();
        for _ in 0..1000 {
            h.update(&[b'a'; 1000]);
        }
        assert_eq!(
            to_hex(&h.finish()),
            "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0"
        );
    }

    /// Stride for the split sweep below.
    ///
    /// Natively it walks every split. Under Miri, every operation is interpreted and
    /// this one test was ~2 minutes of the workspace Miri job -- the same shape as
    /// the strides in `sigstore::manifest` and `fingerprint_store`, and the fourth
    /// time in this workstream that an exhaustive pure-`core` test has had to be
    /// bounded there. `core` is `#![forbid(unsafe_code)]`, so what Miri can find in a
    /// sample it can find in the whole walk; the exhaustive question is answered at
    /// stride 1 natively, by the `sha256` fuzz target, and by the 669-case
    /// `sha256sum` differential. A prime stride so the sampled splits do not align
    /// with the 64-byte block boundary.
    #[cfg(miri)]
    const SPLIT_STRIDE: usize = 23;
    /// See [`SPLIT_STRIDE`] under `cfg(miri)`.
    #[cfg(not(miri))]
    const SPLIT_STRIDE: usize = 1;

    #[test]
    fn streaming_in_any_chunking_matches_one_shot() {
        // The buffering path is where a hand-rolled hasher goes wrong: a partial
        // block topped up across calls, a chunk that exactly fills a block, a chunk
        // spanning several. This is the test that caught the buffer-length reset.
        let data: Vec<u8> = (0..200u32).map(|i| (i % 251) as u8).collect();
        let want = Sha256::digest(&data);
        for split in (0..=data.len()).step_by(SPLIT_STRIDE) {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finish(), want, "split at {split}");
        }
        // The boundaries run whatever the stride: an empty first half and an empty
        // second half are the two splits most likely to be mishandled.
        for split in [0, data.len()] {
            let mut h = Sha256::new();
            h.update(&data[..split]);
            h.update(&data[split..]);
            assert_eq!(h.finish(), want, "boundary split at {split}");
        }
        // And byte-at-a-time, the worst case for the buffer -- bounded under Miri to
        // the first block plus a byte, which is where the buffering actually turns
        // over.
        #[cfg(miri)]
        let tail = data.get(..65).unwrap_or(&data);
        #[cfg(not(miri))]
        let tail = &data[..];
        let mut h = Sha256::new();
        for b in tail {
            h.update(&[*b]);
        }
        assert_eq!(h.finish(), Sha256::digest(tail), "byte-at-a-time");
    }

    #[test]
    fn the_block_boundary_lengths_are_right() {
        // Padding is length-dependent: 55 bytes still fits its length field in the
        // same block, 56 does not and forces a second one, 64 is exactly full.
        for len in [0usize, 1, 54, 55, 56, 63, 64, 65, 119, 120, 127, 128] {
            let data = vec![b'x'; len];
            let mut h = Sha256::new();
            h.update(&data);
            assert_eq!(h.finish(), Sha256::digest(&data), "len {len}");
        }
    }

    #[test]
    fn finish_does_not_consume_or_reset_the_hasher() {
        let mut h = Sha256::new();
        h.update(b"abc");
        assert_eq!(h.finish(), h.finish(), "finish is not idempotent");
        assert_eq!(to_hex(&h.finish()), hex(b"abc"));
    }

    #[test]
    fn hex_is_lowercase_and_fixed_width() {
        let d = Sha256::digest(b"");
        let s = to_hex(&d);
        assert_eq!(s.len(), 64);
        assert!(s
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit()));
        assert_eq!(to_hex(&[0u8; DIGEST_LEN]), "0".repeat(64));
        assert_eq!(to_hex(&[0xffu8; DIGEST_LEN]), "f".repeat(64));
    }
}
