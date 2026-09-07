//! The Nmap Scripting Engine (milestone M6).
//!
//! M6.1 ports the two inputs that decide **which** scripts run, before any of
//! the machinery that runs them: the generated script index (`script.db`) and
//! the metadata header of a `.nse` file. Both are pure functions over `&[u8]`
//! with no I/O, no Lua, and no code execution — which is the whole point, see
//! [`script`].

pub mod script;
