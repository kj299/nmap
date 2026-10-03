//! `luaO_chunkid` (`lobject.c`): how an error message names a chunk.
//!
//! Runtime errors (`chunk:3: attempt to index a nil value`), syntax errors and
//! `error()`'s position prefix all name the chunk this way, so it lives here,
//! beside the executor that raises them.

/// The bytes of `s` before its first NUL: what C sees of a Lua string.
fn until_nul(s: &[u8]) -> &[u8] {
    s.iter().position(|&b| b == 0).map_or(s, |i| &s[..i])
}

/// `LUA_IDSIZE`: the size of `luaO_chunkid`'s buffer, NUL included.
const LUA_IDSIZE: usize = 60;

/// `luaO_chunkid` (`lobject.c:543`): how an error message names a chunk.
/// `=name` is `name`, `@file` is `file` (its tail if long), and anything else
/// is source text, quoted as `[string "first line..."]`.
pub fn chunk_id(source: &[u8]) -> Vec<u8> {
    const RETS: &[u8] = b"...";
    const PRE: &[u8] = b"[string \"";
    const POS: &[u8] = b"\"]";
    // `bufflen` after "..." is 57 bytes, and the C's copy of them ends with
    // the source's terminating NUL: 56 characters of a long `@file`.
    const AT_KEEP: usize = LUA_IDSIZE - RETS.len() - 1;
    // Room for source text: the buffer less prefix, "...", suffix and NUL.
    const ROOM: usize = LUA_IDSIZE - (PRE.len() + RETS.len() + POS.len()) - 1;
    // `luaL_loadbufferx` takes the name as a C string.
    let source = until_nul(source);
    match source.split_first() {
        Some((b'=', rest)) => rest[..rest.len().min(LUA_IDSIZE - 1)].to_vec(),
        Some((b'@', rest)) => {
            if source.len() <= LUA_IDSIZE {
                rest.to_vec()
            } else {
                let mut out = RETS.to_vec();
                out.extend_from_slice(&rest[rest.len().saturating_sub(AT_KEEP)..]);
                out
            }
        }
        _ => {
            let nl = source.iter().position(|&b| b == b'\n');
            let mut out = PRE.to_vec();
            if source.len() < ROOM && nl.is_none() {
                out.extend_from_slice(source);
            } else {
                let len = nl.unwrap_or(source.len()).min(ROOM);
                out.extend_from_slice(&source[..len]);
                out.extend_from_slice(RETS);
            }
            out.extend_from_slice(POS);
            out
        }
    }
}
