// cargo-fuzz target for `nmap_core::nse::stdlib::strpack`.
//
// `string.unpack` is how NSE's protocol libraries read packet fields, so its
// data argument is routinely bytes a remote host chose, and the format beside it
// is a small interpreter of its own (sizes, byte order, alignment, a `c` count
// that spills into the next option). The properties checked:
//
//   * `unpack`, `pack` and `packsize` are TOTAL: any format, any data, any
//     initial position gives a value or a Lua error, never a panic, an overflow
//     trap, or an out-of-bounds read;
//   * every byte string `unpack` returns is a sub-slice of the data it was
//     given, and the position it reports lies in `1 ..= len + 1`;
//   * `pack` inverts `unpack`: re-packing what was unpacked and unpacking that
//     again gives the same values. It is the property most likely to catch a
//     disagreement between the two halves over sign extension, byte order or
//     alignment, because each half is otherwise only checked against itself;
//   * `packsize`, when it answers, agrees with the length `pack` produces and
//     the position `unpack` reaches.
//
// Input layout: byte 0 picks the initial position, the format runs up to the
// first NUL (the C stops reading there too, so no format is unreachable), and
// the rest is data.
#![no_main]

use std::borrow::Cow;

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::stdlib::strpack::{pack, packsize, unpack, PackArgs, PackError, Unpacked};

/// Positions worth reaching from one selector byte: both ends, both signs, and
/// the extremes that exercise `posrelatI`'s clipping.
fn init_for(sel: u8, len: usize) -> i64 {
    let len = len as i64;
    match sel % 12 {
        0 => 1,
        1 => 0,
        2 => -1,
        3 => len,
        4 => len + 1,
        5 => len + 2,
        6 => -len,
        7 => -len - 1,
        8 => i64::MAX,
        9 => i64::MIN,
        10 => 2,
        _ => i64::from(sel as i8),
    }
}

/// Feeds `pack` the values `unpack` produced, in order. The same format drives
/// both, so each value is asked for as the kind it came out as.
struct Replay<'a>(Vec<Unpacked<'a>>);

impl PackArgs for Replay<'_> {
    fn integer(&mut self, arg: usize) -> Result<i64, PackError> {
        match self.0.get(arg - 2) {
            Some(Unpacked::Integer(i)) => Ok(*i),
            _ => Err(PackError::bad_argument(arg, "number expected")),
        }
    }
    fn number(&mut self, arg: usize) -> Result<f64, PackError> {
        match self.0.get(arg - 2) {
            Some(Unpacked::Float(f)) => Ok(*f),
            Some(Unpacked::Integer(i)) => Ok(*i as f64),
            _ => Err(PackError::bad_argument(arg, "number expected")),
        }
    }
    fn bytes(&mut self, arg: usize) -> Result<Cow<'_, [u8]>, PackError> {
        match self.0.get(arg - 2) {
            Some(Unpacked::Bytes(b)) => Ok(Cow::Borrowed(b)),
            _ => Err(PackError::bad_argument(arg, "string expected")),
        }
    }
}

/// Value equality with NaN equal to NaN. A float NaN's payload is not preserved
/// through `f32` -> `f64` -> `f32` on every target, and nothing in Lua can
/// observe the payload; everything else must round-trip bit for bit.
fn same(a: &Unpacked<'_>, b: &Unpacked<'_>) -> bool {
    match (a, b) {
        (Unpacked::Float(x), Unpacked::Float(y)) if x.is_nan() && y.is_nan() => true,
        (Unpacked::Float(x), Unpacked::Float(y)) => x.to_bits() == y.to_bits(),
        _ => a == b,
    }
}

fuzz_target!(|input: &[u8]| {
    let Some((&sel, rest)) = input.split_first() else {
        return;
    };
    let cut = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
    let fmt = &rest[..cut];
    let data = rest.get(cut + 1..).unwrap_or(&[]);
    let init = init_for(sel, data.len());

    let size = packsize(fmt);
    if let Ok(n) = size {
        assert!((0..=i64::from(i32::MAX)).contains(&n), "packsize {n} out of range");
    }

    let Ok((values, next)) = unpack(fmt, data, init) else {
        return;
    };
    assert!(
        (1..=data.len() as i64 + 1).contains(&next),
        "next position {next} outside 1..={}",
        data.len() + 1
    );
    let range = data.as_ptr_range();
    for v in &values {
        if let Unpacked::Bytes(b) = v {
            let r = b.as_ptr_range();
            assert!(
                b.is_empty() || (range.start <= r.start && r.end <= range.end),
                "unpack returned bytes outside its input"
            );
        }
    }

    // Round trip. Only from the start of the data: alignment is measured from
    // byte 1, so the bytes `pack` writes line up with a re-unpack at 1 only if
    // the original unpack also started there.
    if init != 1 {
        return;
    }
    let packed = pack(fmt, &mut Replay(values.clone()))
        .unwrap_or_else(|e| panic!("pack refused what unpack produced: {e}"));
    assert_eq!(
        packed.len() as i64,
        next - 1,
        "pack wrote a different length than unpack consumed"
    );
    if let Ok(n) = size {
        assert_eq!(n, next - 1, "packsize disagrees with unpack");
    }
    let (again, next_again) = unpack(fmt, &packed, 1)
        .unwrap_or_else(|e| panic!("unpack refused what pack produced: {e}"));
    assert_eq!(next_again, next);
    assert_eq!(again.len(), values.len());
    for (a, b) in values.iter().zip(&again) {
        assert!(same(a, b), "round trip changed {a:?} into {b:?}");
    }
});
