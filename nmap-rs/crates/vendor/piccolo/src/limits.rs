//! The limits PUC-Lua 5.4 puts on a running state, and the errors it raises
//! when a program reaches them.
//!
//! A stackless VM needs none of these to stay sound: its call stack lives on
//! the heap. They exist so that a runaway program — recursion through
//! `string.gsub`, an `__index` that indexes itself, a function that calls
//! itself without end — fails with PUC-Lua's catchable error at PUC-Lua's
//! depth, rather than growing the heap until the process dies.

/// `LUAI_MAXCCALLS` (`llimits.h`): how deep calls that PUC-Lua makes through
/// its C stack may nest. One level is taken by every call a C function makes
/// (`lua_call`, `lua_pcall`), every metamethod the VM calls, every generic
/// `for` iterator call, and every coroutine resume.
pub const LUAI_MAXCCALLS: u32 = 200;

/// `LUAI_MAXSTACK` (`luaconf.h`, 32-bit `int`): the most stack slots one
/// thread may use.
pub const LUAI_MAXSTACK: usize = 1_000_000;

/// The message `luaE_checkcstack` raises at `LUAI_MAXCCALLS`.
pub const C_STACK_OVERFLOW: &str = "C stack overflow";

/// The message `luaD_growstack` raises past `LUAI_MAXSTACK`.
pub const STACK_OVERFLOW: &str = "stack overflow";

/// The message of `LUA_ERRMEM` (`luaD_seterrorobj`), which carries no
/// position.
pub const NOT_ENOUGH_MEMORY: &str = "not enough memory";

/// The message of `LUA_ERRERR`: a call nested `LUAI_MAXCCALLS / 10 * 11`
/// deep, which only error handlers reach (`luaE_checkcstack`).
pub const ERROR_IN_ERROR_HANDLING: &str = "error in error handling";

/// How deep calls may go past `LUAI_MAXCCALLS` while an error is being
/// handled: only a call landing exactly on the limit fails with "C stack
/// overflow", and from here on every call fails with "error in error
/// handling".
pub const LUAI_MAXCCALLS_ERR: u32 = LUAI_MAXCCALLS / 10 * 11;

/// Why a call could not be made.
#[derive(Debug, Copy, Clone, PartialEq, Eq)]
pub enum CallLimit {
    /// `luaE_checkcstack`: "C stack overflow".
    CStack,
    /// `luaD_growstack`: "stack overflow".
    Stack,
    /// `luaE_checkcstack` past the margin error handlers have: "error in
    /// error handling", which no handler sees.
    ErrorHandling,
}

impl CallLimit {
    pub fn message(self) -> &'static str {
        match self {
            CallLimit::CStack => C_STACK_OVERFLOW,
            CallLimit::Stack => STACK_OVERFLOW,
            CallLimit::ErrorHandling => ERROR_IN_ERROR_HANDLING,
        }
    }
}

/// Whether a stack of `in_use` slots has room for `n` more
/// (`lua_checkstack`).
pub fn stack_has_room(in_use: usize, n: usize) -> bool {
    in_use <= LUAI_MAXSTACK && n <= LUAI_MAXSTACK - in_use
}
