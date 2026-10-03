// cargo-fuzz target for `nmap_core::nse::stdlib::pattern`.
//
// Lua patterns are how NSE scripts read banners, headers and packets, so the
// subject is routinely bytes a remote host chose, and the pattern is a small
// language of its own whose errors the C diagnoses lazily, mid-match. The
// properties checked:
//
//   * `find`, `match`, `gmatch` and `gsub` are TOTAL: any pattern, any subject,
//     any initial position gives a value or a Lua error, never a panic, an
//     overflow trap, an out-of-bounds read or a stack overflow;
//   * every capture is a sub-slice of the subject, or a position in
//     `1 ..= len + 1`, and `find`'s range lies inside the subject;
//   * `find` and `match` agree. They share the matcher, except that `find`
//     answers a pattern with no magic characters with a plain substring search
//     — so on those inputs this is a cross-check of `lmemfind` against the
//     matcher, the two halves that would otherwise only be checked against
//     themselves;
//   * `gsub` with `%0` reproduces its subject exactly, and replaces exactly as
//     many matches as `gmatch` iterates: the two walk the subject with the same
//     loop, which this holds them to;
//   * `gmatch` terminates within `2 * (len + 1)` results.
//
// Input layout: byte 0 selects the initial position and the plain flag, byte 1
// the pattern length, then the pattern, then the subject.
//
// One thing is NOT fuzzed: the matcher's running time. The C algorithm is
// exponential in the number of quantified items, and the port keeps that
// algorithm (DIVERGENCES.md, `pattern-worst-case-time-is-the-cs`), so an input
// whose worst case is large would only ever report a libFuzzer timeout. Such
// inputs are skipped, which leaves every input the matcher can finish quickly —
// and that is every input whose correctness is in question.
#![no_main]

use libfuzzer_sys::fuzz_target;
use nmap_core::nse::stdlib::pattern::{find, set_memo_after, str_match, Capture, Gmatch, Gsub};

/// Positions worth reaching from one selector: both ends, both signs, and the
/// extremes that exercise `posrelatI`'s clipping.
fn init_for(sel: u8, len: usize) -> i64 {
    let len = len as i64;
    match sel % 10 {
        0 | 1 | 2 => 1,
        3 => 0,
        4 => -1,
        5 => len,
        6 => len + 1,
        7 => len + 2,
        8 => -len - 1,
        _ => i64::MIN,
    }
}

/// An upper bound on the C algorithm's work is `(len + 2) ^ k`, where `k`
/// counts the items that can each try every position — quantifiers, `%b` and
/// back-references. Skip inputs where that is large.
fn affordable(p: &[u8], len: usize) -> bool {
    let k = p
        .windows(2)
        .filter(|w| {
            matches!(w[1], b'*' | b'+' | b'-' | b'?')
                || (w[0] == b'%' && (w[1] == b'b' || w[1].is_ascii_digit()))
        })
        .count();
    let base = len as u128 + 2;
    u32::try_from(k)
        .ok()
        .and_then(|k| base.checked_pow(k))
        .is_some_and(|w| w <= 1 << 21)
}

fn in_subject(s: &[u8], c: &Capture<'_>) -> bool {
    match c {
        Capture::Bytes(b) => {
            let (r, c) = (s.as_ptr_range(), b.as_ptr_range());
            b.is_empty() || (r.start <= c.start && c.end <= r.end)
        }
        Capture::Position(n) => (1..=s.len() as i64 + 1).contains(n),
    }
}

const TEMPLATES: [&[u8]; 8] = [b"%0", b"x", b"%1", b"<%1|%2>", b"%%", b"", b"%", b"%9"];

/// Everything the four functions answer for one input, as text, so that two
/// runs can be compared whole.
fn transcript(sel: u8, p: &[u8], s: &[u8]) -> Vec<String> {
    let mut t = Vec::new();
    let init = init_for(sel, s.len());
    let plain = sel & 0x80 != 0;
    t.push(format!("{:?}", find(s, p, init, plain)));
    t.push(format!("{:?}", str_match(s, p, init)));
    let mut g = Gmatch::new(s.len(), init);
    for _ in 0..2 * (s.len() + 1) {
        match g.next(s, p) {
            Ok(Some(c)) => t.push(format!("{c:?}")),
            other => {
                t.push(format!("{other:?}"));
                break;
            }
        }
    }
    let tpl = TEMPLATES[usize::from(sel >> 4) % TEMPLATES.len()];
    let mut sub = Gsub::new(p, s.len() as i64 + 1);
    let r = (|| {
        while let Some(m) = sub.next(s, p)? {
            sub.add_template(s, &m, tpl)?;
        }
        sub.finish(s)
    })();
    t.push(format!("{r:?}"));
    t
}

fuzz_target!(|input: &[u8]| {
    {
        let [sel, plen, rest @ ..] = input else {
            return;
        };
        let (p, s) = rest.split_at(usize::from(*plen).min(rest.len()));
        if affordable(p, s.len()) {
            // The failure memo must change nothing: every answer and every
            // error, "pattern too complex" included, the same with it
            // recording from the first computation as with it never on.
            set_memo_after(Some(0));
            let with = transcript(*sel, p, s);
            set_memo_after(Some(u64::MAX));
            let without = transcript(*sel, p, s);
            set_memo_after(None);
            assert_eq!(with, without, "the memo changed an outcome");
        }
    }
    let [sel, plen, rest @ ..] = input else {
        return;
    };
    let (p, s) = rest.split_at(usize::from(*plen).min(rest.len()));
    if !affordable(p, s.len()) {
        return;
    }
    let len = s.len() as i64;
    let init = init_for(*sel, s.len());
    let plain = sel & 0x80 != 0;

    // find
    let found = find(s, p, init, plain);
    if let Ok(Some(f)) = &found {
        assert!(
            (1..=len + 1).contains(&f.start),
            "find start {} of {len}",
            f.start
        );
        assert!(
            f.start - 1 <= f.end && f.end <= len,
            "find range {}..{}",
            f.start,
            f.end
        );
        assert!(f.captures.iter().all(|c| in_subject(s, c)));
        if plain {
            assert!(f.captures.is_empty());
            assert_eq!(&s[(f.start - 1) as usize..f.end as usize], p);
        }
    }

    // match, and its agreement with find
    let matched = str_match(s, p, init);
    if let Ok(Some(caps)) = &matched {
        assert!(caps.iter().all(|c| in_subject(s, c)));
    }
    // `find` searches literally for a pattern with none of `^$*+?.([%-`, and
    // `)` is not among them — yet to the matcher it closes a capture. So
    // `find("a)", ")")` is `2, 2` while `match` raises "invalid pattern
    // capture", in the C as here; those inputs are left out of the comparison.
    let literal = !p.iter().any(|b| b"^$*+?.([%-".contains(b));
    if !plain && !(literal && p.contains(&b')')) {
        match (&found, &matched) {
            (Ok(Some(f)), Ok(Some(caps))) => {
                if f.captures.is_empty() {
                    let whole = &s[(f.start - 1) as usize..f.end as usize];
                    assert_eq!(
                        caps,
                        &vec![Capture::Bytes(whole)],
                        "match's whole match is not find's range"
                    );
                } else {
                    assert_eq!(&f.captures, caps, "find and match captured differently");
                }
            }
            (Ok(None), Ok(None)) => {}
            // `find` reads no captures of a capture-less match, so only the
            // matcher's own errors can differ — and they must not.
            (Err(a), Err(b)) => assert_eq!(a, b),
            (Ok(Some(f)), Err(_)) if f.captures.is_empty() => {
                panic!("match raised where find succeeded without captures")
            }
            (a, b) => panic!("find {a:?} and match {b:?} disagree"),
        }
    }

    // gmatch from `init`: bounded, and every capture inside the subject.
    let mut g = Gmatch::new(s.len(), init);
    let mut results = 0usize;
    while let Ok(Some(caps)) = g.next(s, p) {
        assert!(caps.iter().all(|c| in_subject(s, c)));
        results += 1;
        assert!(results <= 2 * (s.len() + 1), "gmatch did not terminate");
    }

    // gsub with `%0` is the identity, and replaces what gmatch iterates.
    if p.first() != Some(&b'^') {
        let mut g = Gmatch::new(s.len(), 1);
        let mut iterated = Ok(0i64);
        loop {
            match g.next(s, p) {
                Ok(Some(_)) => iterated = iterated.map(|n| n + 1),
                Ok(None) => break,
                Err(e) => {
                    iterated = Err(e);
                    break;
                }
            }
        }
        let mut sub = Gsub::new(p, len + 1);
        let replaced = (|| {
            while let Some(m) = sub.next(s, p)? {
                sub.add_template(s, &m, b"%0")?;
            }
            sub.finish(s)
        })();
        match (&iterated, &replaced) {
            (Ok(n), Ok((out, count))) => {
                assert_eq!(n, count, "gsub and gmatch found different matches");
                assert_eq!(
                    out.as_deref().unwrap_or(s),
                    s,
                    "gsub with %0 changed the subject"
                );
            }
            (Ok(_), Err(e)) => panic!("gsub raised {e} where gmatch did not"),
            _ => {}
        }
    }

    // gsub with an arbitrary template, and with every match kept: no panic,
    // and keeping everything reports the subject unchanged.
    let tpl = TEMPLATES[usize::from(*sel >> 4) % TEMPLATES.len()];
    let mut sub = Gsub::new(p, len + 1);
    let _ = (|| {
        while let Some(m) = sub.next(s, p)? {
            sub.add_template(s, &m, tpl)?;
        }
        sub.finish(s)
    })();
    let mut keep = Gsub::new(p, len + 1);
    let kept = (|| {
        while let Some(m) = keep.next(s, p)? {
            keep.keep(s, &m)?;
        }
        keep.finish(s)
    })();
    if let Ok((out, _)) = kept {
        assert!(out.is_none(), "keeping every match changed the subject");
    }
});
