//! `core::bytes` — a checked, panic-free cursor over `&[u8]`.
//!
//! This is the M4 leaf every packet parser is built on. nmap's C reads wire bytes
//! by overlaying a `__packed__` struct on a buffer and advancing a pointer by a
//! length that a separate `validate()` *promised* was in range (`PacketParser.cc`);
//! the safety of every field read is an emergent property spread across nine
//! `validate()` implementations, and a single dishonest one is an out-of-bounds
//! read. This cursor makes "advance by N" a **bounds check by construction**: every
//! read either returns the bytes or a [`Error::Truncated`] — it can never index out
//! of range and never panics, so a hostile/truncated packet degrades to a parse
//! error instead of UB (the M4 threat-model requirement).
//!
//! All multi-byte integer reads are **big-endian** (network byte order). There is no
//! `&str`/UTF-8 anywhere here: wire data is bytes (LESSONS #12), and this type is the
//! reason a downstream parser never needs to reach for pointer math or `chars()`.

use core::fmt;

/// A read failed because too few bytes remained.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Error {
    /// Wanted `needed` bytes but only `remaining` were left in the buffer.
    Truncated { needed: usize, remaining: usize },
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Truncated { needed, remaining } => {
                write!(f, "truncated: need {needed} byte(s), {remaining} remaining")
            }
        }
    }
}

impl std::error::Error for Error {}

/// Result alias for cursor reads.
pub type Result<T> = core::result::Result<T, Error>;

/// A forward-only cursor over a byte slice. Cheap to copy; borrows the buffer.
///
/// Invariant: `pos <= buf.len()` always holds — every method that advances checks
/// first, so `pos` can never run past the end.
#[derive(Debug, Clone, Copy)]
pub struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    /// Wrap a byte slice. The cursor starts at offset 0.
    #[must_use]
    pub const fn new(buf: &'a [u8]) -> Self {
        Cursor { buf, pos: 0 }
    }

    /// Bytes not yet consumed.
    #[must_use]
    pub fn remaining(&self) -> usize {
        // pos <= buf.len() by invariant, so this never wraps.
        self.buf.len().saturating_sub(self.pos)
    }

    /// Current offset from the start of the original buffer.
    #[must_use]
    pub const fn position(&self) -> usize {
        self.pos
    }

    /// Whether all bytes have been consumed.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.remaining() == 0
    }

    /// The as-yet-unconsumed bytes, without advancing.
    #[must_use]
    pub fn rest(&self) -> &'a [u8] {
        // pos <= len by invariant; slicing at pos is always valid.
        &self.buf[self.pos..]
    }

    /// End offset of a read of `n` bytes at the current position, or `Err` if it
    /// would run past the end. Centralizes the one bounds check the whole type
    /// relies on.
    fn end_of(&self, n: usize) -> Result<usize> {
        match self.pos.checked_add(n) {
            Some(end) if end <= self.buf.len() => Ok(end),
            _ => Err(Error::Truncated {
                needed: n,
                remaining: self.remaining(),
            }),
        }
    }

    /// Borrow the next `n` bytes and advance past them.
    pub fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        let end = self.end_of(n)?;
        let out = &self.buf[self.pos..end];
        self.pos = end;
        Ok(out)
    }

    /// Borrow the next `n` bytes **without** advancing.
    pub fn peek(&self, n: usize) -> Result<&'a [u8]> {
        let end = self.end_of(n)?;
        Ok(&self.buf[self.pos..end])
    }

    /// Advance past `n` bytes, discarding them.
    pub fn skip(&mut self, n: usize) -> Result<()> {
        let end = self.end_of(n)?;
        self.pos = end;
        Ok(())
    }

    /// Read a fixed `N`-byte array and advance. The array size is checked at compile
    /// time, so callers get `[u8; N]` with no runtime length ambiguity.
    pub fn read_array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let slice = self.take(N)?;
        let mut out = [0u8; N];
        out.copy_from_slice(slice);
        Ok(out)
    }

    /// Read one byte and advance.
    pub fn read_u8(&mut self) -> Result<u8> {
        Ok(self.read_array::<1>()?[0])
    }

    /// Read a big-endian `u16` and advance.
    pub fn read_be_u16(&mut self) -> Result<u16> {
        Ok(u16::from_be_bytes(self.read_array::<2>()?))
    }

    /// Read a big-endian `u32` and advance.
    pub fn read_be_u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.read_array::<4>()?))
    }

    /// Read a big-endian `u64` and advance.
    pub fn read_be_u64(&mut self) -> Result<u64> {
        Ok(u64::from_be_bytes(self.read_array::<8>()?))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn new_cursor_is_at_zero_and_reports_full_remaining() {
        let c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.position(), 0);
        assert_eq!(c.remaining(), 3);
        assert!(!c.is_empty());
    }

    #[test]
    fn empty_buffer_is_empty() {
        let c = Cursor::new(&[]);
        assert!(c.is_empty());
        assert_eq!(c.remaining(), 0);
        assert_eq!(c.rest(), &[] as &[u8]);
    }

    #[test]
    fn read_u8_advances_one() {
        let mut c = Cursor::new(&[0xAB, 0xCD]);
        assert_eq!(c.read_u8().unwrap(), 0xAB);
        assert_eq!(c.position(), 1);
        assert_eq!(c.remaining(), 1);
        assert_eq!(c.read_u8().unwrap(), 0xCD);
        assert!(c.is_empty());
    }

    #[test]
    fn read_be_integers_are_network_order() {
        let mut c = Cursor::new(&[0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0]);
        assert_eq!(c.read_be_u16().unwrap(), 0x1234);
        assert_eq!(c.read_be_u16().unwrap(), 0x5678);
        c = Cursor::new(&[0x12, 0x34, 0x56, 0x78]);
        assert_eq!(c.read_be_u32().unwrap(), 0x1234_5678);
        c = Cursor::new(&[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(c.read_be_u64().unwrap(), 0x0102_0304_0506_0708);
    }

    #[test]
    fn take_returns_slice_and_advances() {
        let mut c = Cursor::new(&[1, 2, 3, 4, 5]);
        assert_eq!(c.take(2).unwrap(), &[1, 2]);
        assert_eq!(c.take(3).unwrap(), &[3, 4, 5]);
        assert!(c.is_empty());
    }

    #[test]
    fn take_zero_is_ok_and_does_not_advance() {
        let mut c = Cursor::new(&[9]);
        assert_eq!(c.take(0).unwrap(), &[] as &[u8]);
        assert_eq!(c.position(), 0);
    }

    #[test]
    fn peek_does_not_advance() {
        let c = Cursor::new(&[1, 2, 3]);
        assert_eq!(c.peek(2).unwrap(), &[1, 2]);
        assert_eq!(c.position(), 0);
        assert_eq!(c.remaining(), 3);
    }

    #[test]
    fn skip_advances_without_returning() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        c.skip(3).unwrap();
        assert_eq!(c.position(), 3);
        assert_eq!(c.read_u8().unwrap(), 4);
    }

    #[test]
    fn rest_reflects_consumption() {
        let mut c = Cursor::new(&[1, 2, 3, 4]);
        c.skip(1).unwrap();
        assert_eq!(c.rest(), &[2, 3, 4]);
    }

    // --- the load-bearing property: every over-read is a clean error, never a panic ---

    #[test]
    fn over_read_is_truncated_not_panic() {
        let mut c = Cursor::new(&[1, 2]);
        assert_eq!(
            c.read_be_u32(),
            Err(Error::Truncated {
                needed: 4,
                remaining: 2
            })
        );
        // A failed read must not have advanced the cursor.
        assert_eq!(c.position(), 0);
        assert_eq!(c.remaining(), 2);
    }

    #[test]
    fn take_past_end_errors_and_leaves_cursor_intact() {
        let mut c = Cursor::new(&[1, 2, 3]);
        c.skip(2).unwrap();
        assert_eq!(
            c.take(2),
            Err(Error::Truncated {
                needed: 2,
                remaining: 1
            })
        );
        assert_eq!(c.position(), 2);
    }

    #[test]
    fn read_u8_on_empty_errors() {
        let mut c = Cursor::new(&[]);
        assert_eq!(
            c.read_u8(),
            Err(Error::Truncated {
                needed: 1,
                remaining: 0
            })
        );
    }

    #[test]
    fn huge_take_cannot_overflow_offset() {
        // n near usize::MAX must not wrap pos+n into a false in-bounds read.
        let mut c = Cursor::new(&[1, 2, 3]);
        c.skip(1).unwrap();
        assert!(matches!(c.take(usize::MAX), Err(Error::Truncated { .. })));
        assert_eq!(c.position(), 1);
        // The cursor is still usable after the rejected read.
        assert_eq!(c.take(2).unwrap(), &[2, 3]);
    }

    #[test]
    fn peek_past_end_errors() {
        let c = Cursor::new(&[1]);
        assert!(peek_is_truncated(&c));
    }

    fn peek_is_truncated(c: &Cursor<'_>) -> bool {
        matches!(
            c.peek(5),
            Err(Error::Truncated {
                needed: 5,
                remaining: 1
            })
        )
    }

    #[test]
    fn exhaustive_take_lengths_never_panic_and_are_consistent() {
        // For every buffer length and every requested length (incl. past-end and 0),
        // take() either returns exactly that many bytes and advances, or errors and
        // does not advance. Small exhaustive sweep — this is the whole contract.
        for buf_len in 0usize..=8 {
            let buf: Vec<u8> = (0..buf_len).map(|i| u8::try_from(i).unwrap()).collect();
            for take_len in 0usize..=12 {
                let mut c = Cursor::new(&buf);
                match c.take(take_len) {
                    Ok(s) => {
                        assert_eq!(s.len(), take_len);
                        assert_eq!(c.position(), take_len);
                        assert_eq!(c.remaining(), buf_len.saturating_sub(take_len));
                    }
                    Err(Error::Truncated { needed, remaining }) => {
                        assert_eq!(needed, take_len);
                        assert_eq!(remaining, buf_len);
                        assert!(take_len > buf_len);
                        assert_eq!(c.position(), 0); // no advance on failure
                    }
                }
            }
        }
    }

    #[test]
    fn error_display_is_readable() {
        let e = Error::Truncated {
            needed: 4,
            remaining: 1,
        };
        assert_eq!(e.to_string(), "truncated: need 4 byte(s), 1 remaining");
    }
}
