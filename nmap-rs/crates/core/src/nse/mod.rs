//! The Nmap Scripting Engine (milestone M6).
//!
//! M6.1 ports the two inputs that decide **which** scripts run, before any of
//! the machinery that runs them: the generated script index (`script.db`) and
//! the metadata header of a `.nse` file. Both are pure functions over `&[u8]`
//! with no I/O, no Lua, and no code execution — which is the whole point, see
//! [`script`].
//!
//! M6.2 adds [`selection`]: the `--script` expression grammar that decides,
//! given those two inputs, which scripts a run actually selects. Also pure,
//! also fuzzable, and independent of the Lua-runtime decision still open for
//! M6.0.
//!
//! [`stdlib`] is the first code here that touches the interpreter: the parts of
//! Lua's standard library the vendored VM does not ship, written in this crate
//! so that the port's own gates reach them.

pub mod script;
pub mod selection;
pub mod stdlib;
