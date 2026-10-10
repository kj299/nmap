//! LPeg's pattern trees: `lptree.c`'s constructors and grammar builder, and
//! the analyses of `lpcode.c` that construction runs (`lpeg.c:1000-1160`,
//! `:2120-3180`).
//!
//! A pattern is a **flat array of nodes**, laid out exactly as the C lays
//! out its `TTree` array:
//! - a node's first sibling is the node after it, `sib1(i) = i + 1`;
//! - its second sibling is `sib2(i) = i + u`, `u` being the C's `u.ps`;
//! - a charset's 32 bytes occupy the [`SET_SLOTS`] slots after its `Set`
//!   node, as `treebuffer` puts them, so every size counted in nodes is the
//!   C's size counted in `TTree`s.
//!
//! Keeping the C's layout, rather than a Rust enum tree, is what lets the
//! compiler of step c be instruction-exact: `codegen` reads sizes and
//! sibling offsets, and the backtrack ceilings the corpus pins depend on
//! the code it produces (`docs/M6.6-ANALYSIS.md`, D2).
//!
//! Nothing here knows Lua. A key ([`Key`]) is an index into the pattern's
//! constant table, which the binding ([`super`]) owns; this module only
//! shifts keys when tables are joined (`correctkeys`) and reports the key a
//! grammar error names. Keys are 32 bits wide where the C's are 16
//! (`lpeg-ktable-key-16bit`, D4).
//!
//! **Sizes.** The C computes a tree's size in an `int`, and hands it to
//! `newtree`, which allocates `8 * len + 16` bytes. Here every size is
//! computed exactly, then judged as the C's wrapped `int` would be
//! ([`c_size`]): a size the `int` holds is allocated through the memory
//! budget (`not enough memory` if refused); one that wraps to -3 or below is
//! the C's `luaM_toobig`, "memory allocation error: block too big"; and one
//! that wraps to anything else, where the C allocates too little and writes
//! past it, is `not enough memory` — unless the C raises another error
//! between the two, which the caller reproduces (`lpeg-tree-size-int-overflow`,
//! `lpeg-pattern-string-size-overflow`).
//!
//! **No recursion.** No walker recurses on the Rust stack (E2): each is a
//! loop over an explicit stack, and the ones that can take exponential time
//! are resumable state machines that stop when their step budget runs out
//! ([`walk`]).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "index arithmetic is on positions inside a tree, all below MAX_TREE (2^31 - 1), \
              so the sum of two cannot overflow usize; every size derived from a script's \
              input is computed with checked arithmetic"
)]

use crate::nse::stdlib::reserve;

mod walk;

pub use walk::{CheckAux, CheckLoops, FinalFix, FindOpenCall, FixedLen, Pred, VerifyGrammar};

/// `MAXRULES` (`lpeg.c:57`): the most rules a grammar may have, and the
/// longest chain of left calls the verifier and `fixedlenx` follow.
pub const MAXRULES: usize = 200;

/// `MAXBEHIND` (`lpeg.c:121`, `MAXAUX`): the longest pattern `B` accepts.
pub const MAXBEHIND: i64 = 255;

/// `SHRT_MAX`: the bound on a numbered capture (`p / n`) and on `Carg`.
pub const SHRT_MAX: i64 = 32_767;

/// `CHARSETSIZE`: a charset's bytes.
pub const CHARSET_SIZE: usize = 32;

/// `bytes2slots(CHARSETSIZE)`: the slots a charset takes after its node (a
/// `TTree` is 8 bytes).
pub const SET_SLOTS: usize = 4;

/// The largest tree, in nodes: the C counts sizes in `int` ([`c_size`]).
pub const MAX_TREE: usize = 0x7fff_ffff;

/// An index into a pattern's constant table (`ktable`); 0 is none.
pub type Key = u32;

/// A node's kind (`TTag`, `lpeg.c:160`), in the C's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum Tag {
    Char,
    Set,
    Any,
    True,
    False,
    Rep,
    Seq,
    Choice,
    Not,
    And,
    Call,
    OpenCall,
    /// `sib1` is the rule's pattern, `sib2` the next rule.
    Rule,
    /// `sib1` is the first rule; `u` is the number of rules.
    Grammar,
    Behind,
    Capture,
    RunTime,
}

impl Tag {
    /// `numsiblings` (`lpeg.c:2135`).
    #[must_use]
    pub const fn siblings(self) -> u8 {
        match self {
            Tag::Rep | Tag::Not | Tag::And | Tag::Grammar | Tag::Behind => 1,
            Tag::Capture | Tag::RunTime => 1,
            Tag::Seq | Tag::Choice | Tag::Rule => 2,
            _ => 0,
        }
    }

    /// `tagnames` (`lpeg.c:2028`), for the debug printer.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Tag::Char => "char",
            Tag::Set => "set",
            Tag::Any => "any",
            Tag::True => "true",
            Tag::False => "false",
            Tag::Rep => "rep",
            Tag::Seq => "seq",
            Tag::Choice => "choice",
            Tag::Not => "not",
            Tag::And => "and",
            Tag::Call => "call",
            Tag::OpenCall => "opencall",
            Tag::Rule => "rule",
            Tag::Grammar => "grammar",
            Tag::Behind => "behind",
            Tag::Capture => "capture",
            Tag::RunTime => "run-time",
        }
    }
}

/// A capture's kind (`CapKind`, `lpeg.c:236`), in the C's order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum CapKind {
    Close,
    Position,
    Const,
    Backref,
    Arg,
    Simple,
    Table,
    Function,
    Query,
    String,
    Num,
    Subst,
    Fold,
    Runtime,
    Group,
}

/// One `TTree`. `cap` is a [`CapKind`] on a capture and the rule's number on
/// a rule; `u` is the C's union: the second sibling's offset (`ps`) or a
/// counter (`n`: a character, a length, a number of rules).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Node {
    pub tag: Tag,
    pub cap: u8,
    pub key: Key,
    pub u: i32,
}

impl Node {
    /// A node of `tag` with every other field zero. (The C leaves them as
    /// `malloc` left them; none is read before it is written.)
    #[must_use]
    pub const fn new(tag: Tag) -> Node {
        Node {
            tag,
            cap: 0,
            key: 0,
            u: 0,
        }
    }

    const fn with_u(tag: Tag, u: i32) -> Node {
        Node {
            tag,
            cap: 0,
            key: 0,
            u,
        }
    }
}

/// A set of bytes (`Charset`): bit `b & 7` of byte `b >> 3`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Charset(pub [u8; CHARSET_SIZE]);

impl Charset {
    #[must_use]
    pub const fn empty() -> Charset {
        Charset([0; CHARSET_SIZE])
    }

    /// `setchar`.
    pub fn add(&mut self, b: u8) {
        self.0[usize::from(b >> 3)] |= 1 << (b & 7);
    }

    /// `testchar`.
    #[must_use]
    pub fn has(&self, b: u8) -> bool {
        self.0[usize::from(b >> 3)] & (1 << (b & 7)) != 0
    }

    #[must_use]
    pub fn union(&self, other: &Charset) -> Charset {
        let mut out = *self;
        for (o, b) in out.0.iter_mut().zip(other.0) {
            *o |= b;
        }
        out
    }

    /// `st1 & ~st2`.
    #[must_use]
    pub fn minus(&self, other: &Charset) -> Charset {
        let mut out = *self;
        for (o, b) in out.0.iter_mut().zip(other.0) {
            *o &= !b;
        }
        out
    }
}

/// Why a tree could not be built or checked. The binding turns each into
/// the C's message, rendering a [`Key`] as the rule name it stands for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TreeError {
    /// A size refused by the memory budget or the allocator, or one past
    /// [`MAX_TREE`] where the C would write past its allocation ([`c_size`]).
    NotEnoughMemory,
    /// A size the C's `int` wraps to -3 or below: `luaM_toobig`'s "memory
    /// allocation error: block too big", raised before anything is written.
    BlockTooBig,
    /// `p^n`, `n >= 0`, of a pattern that can match the empty string.
    LoopBodyNullable,
    /// An open call (`lpeg.V`) outside any grammar, found by `finalfix`.
    UsedOutsideGrammar(Key),
    /// A call to a rule the grammar does not define.
    UndefinedRule(Key),
    /// `verifyerror`: a rule that can call itself without consuming input.
    LeftRecursive(Key),
    /// `verifyerror` with no repeated rule in the chain.
    TooManyLeftCalls,
    /// A loop in this rule whose body can match the empty string.
    EmptyLoop(Key),
    /// A sibling offset that leads outside the tree. Never produced for a
    /// tree built by this module; the walkers report it rather than index
    /// out of bounds.
    Malformed,
}

/// A pattern's tree. The root is node 0.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Tree {
    nodes: Vec<Node>,
}

/// What the C's `newtree(L, len)` does with a tree of `len` nodes, `len`
/// computed exactly here and in an `int` there.
///
/// `newtree` allocates `(len - 1) * sizeof(TTree) + sizeof(Pattern)` bytes,
/// `8 * len + 16` on a 64-bit host, in `size_t`. Every size the C computes
/// is a sum or product of `int`s, so its `int` is `len` modulo 2^32: if that
/// is the true size, the C allocates it; if it is -3 or below, the size in
/// `size_t` is past `MAX_SIZE` and `luaS_newudata` raises `luaM_toobig`
/// before anything is written ("memory allocation error: block too big",
/// unpositioned; `INT_MIN` included, measured); and -2, -1, 0 or a positive
/// size short of the tree's are an allocation of 0, 8, 16 or `8 * w + 16`
/// bytes, which the C then writes past. Measured on the tree's oracle:
/// `P(2^31 - 1)` (-3) and `P(-(2^30))` (`INT_MIN`) are too big,
/// `P(-(2^31 - 1))` (-2) and `P'a'^-(2^30)` (-1) crash, `P''^(2^31 - 1)` (0)
/// raises the check that comes before the writes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CSize {
    /// The `int` holds the size: the C allocates it.
    Fits(usize),
    /// The `int` wrapped to -3 or below: "block too big".
    TooBig,
    /// The `int` wrapped to this, in -2 to `INT_MAX`, short of the tree: the
    /// C allocates that much and writes past it, unless a check between the
    /// two raises first.
    Short(i32),
}

/// [`CSize`] of a tree of `len` nodes.
#[must_use]
pub fn c_size(len: u64) -> CSize {
    if let Ok(n) = usize::try_from(len) {
        if n <= MAX_TREE {
            return CSize::Fits(n);
        }
    }
    // The low 32 bits, read as the C's `int`.
    let low = u32::try_from(len & 0xffff_ffff).unwrap_or(0);
    let w = i32::from_ne_bytes(low.to_ne_bytes());
    if w <= -3 {
        CSize::TooBig
    } else {
        CSize::Short(w)
    }
}

/// A vector for `len` nodes, or `not enough memory`.
pub fn alloc(len: usize) -> Result<Vec<Node>, TreeError> {
    if len > MAX_TREE {
        return Err(TreeError::NotEnoughMemory);
    }
    let mut v = Vec::new();
    if !reserve(&mut v, len) {
        return Err(TreeError::NotEnoughMemory);
    }
    Ok(v)
}

/// A vector for a tree of `len` nodes, as the C's `newtree` fares
/// ([`c_size`]): allocated if the C's `int` holds the size, "block too big"
/// where the C raises that, and `not enough memory` where it would write
/// past what it allocated.
fn alloc_c(len: u64) -> Result<Vec<Node>, TreeError> {
    match c_size(len) {
        CSize::Fits(n) => alloc(n),
        CSize::TooBig => Err(TreeError::BlockTooBig),
        CSize::Short(_) => Err(TreeError::NotEnoughMemory),
    }
}

/// `len` zeroed nodes, to be filled by index as the C fills a `newtree`.
fn zeroed(len: usize) -> Result<Vec<Node>, TreeError> {
    let mut v = alloc(len)?;
    v.resize(len, Node::new(Tag::True));
    Ok(v)
}

/// A count of nodes as the exact size [`c_size`] judges. Sizes here are of
/// trees that exist, or products of two `int`s: none reaches 2^64.
fn wide(n: usize) -> u64 {
    u64::try_from(n).unwrap_or(u64::MAX)
}

/// A size as the C's `int`: a sibling offset.
fn offset(n: usize) -> Result<i32, TreeError> {
    i32::try_from(n).map_err(|_| TreeError::NotEnoughMemory)
}

/// Bytes `8 * i .. 8 * i + 8` of a charset, as one data slot: four in
/// `key`, four in `u`.
fn set_slot(cs: &Charset, i: usize) -> Node {
    let b = &cs.0[i * 8..i * 8 + 8];
    Node {
        tag: Tag::Char,
        cap: 0,
        key: u32::from_le_bytes([b[0], b[1], b[2], b[3]]),
        u: i32::from_le_bytes([b[4], b[5], b[6], b[7]]),
    }
}

/// `fillseq` (`lpeg.c:2364`): `n` nodes of `tag`, the i-th with `u = s[i]`
/// (or 0), chained by `Seq` nodes. `n >= 1`.
fn fillseq(v: &mut Vec<Node>, tag: Tag, n: usize, s: Option<&[u8]>) {
    let byte = |i: usize| s.and_then(|s| s.get(i)).map_or(0, |&b| i32::from(b));
    let last = n.saturating_sub(1);
    for i in 0..last {
        v.push(Node::with_u(Tag::Seq, 2));
        v.push(Node::with_u(tag, byte(i)));
    }
    v.push(Node::with_u(tag, byte(last)));
}

impl Tree {
    /// The nodes, root first.
    #[must_use]
    pub fn nodes(&self) -> &[Node] {
        &self.nodes
    }

    /// The size in nodes (`getsize`).
    #[must_use]
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    /// Never true of a pattern: every tree has a root.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The root node.
    #[must_use]
    pub fn root(&self) -> Node {
        self.nodes.first().copied().unwrap_or(Node::new(Tag::True))
    }

    /// Node `i`.
    #[must_use]
    pub fn node(&self, i: usize) -> Option<Node> {
        self.nodes.get(i).copied()
    }

    /// `sib2(i)`: node `i` plus its offset, if that is inside the tree.
    #[must_use]
    pub fn sib2(&self, i: usize) -> Option<usize> {
        let n = self.nodes.get(i)?;
        let target = isize::try_from(i)
            .ok()?
            .checked_add(isize::try_from(n.u).ok()?)?;
        usize::try_from(target)
            .ok()
            .filter(|&t| t < self.nodes.len())
    }

    /// `sib1(i)`, if inside the tree.
    #[must_use]
    pub fn sib1(&self, i: usize) -> Option<usize> {
        i.checked_add(1).filter(|&t| t < self.nodes.len())
    }

    /// The bytes of the charset whose `Set` node is `i` (`treebuffer`).
    #[must_use]
    pub fn charset_at(&self, i: usize) -> Option<Charset> {
        let slots = self
            .nodes
            .get(i.checked_add(1)?..i.checked_add(1 + SET_SLOTS)?)?;
        let mut cs = Charset::empty();
        for (k, s) in slots.iter().enumerate() {
            cs.0[k * 8..k * 8 + 4].copy_from_slice(&s.key.to_le_bytes());
            cs.0[k * 8 + 4..k * 8 + 8].copy_from_slice(&s.u.to_le_bytes());
        }
        Some(cs)
    }

    /// `newleaf`.
    pub fn leaf(tag: Tag) -> Result<Tree, TreeError> {
        let mut nodes = alloc(1)?;
        nodes.push(Node::new(tag));
        Ok(Tree { nodes })
    }

    /// The size of a string pattern of `slen` bytes (`getpatt`,
    /// `LUA_TSTRING`): `2 * (slen - 1) + 1`, computed in `size_t` and passed
    /// as an `int` by the C.
    #[must_use]
    pub fn literal_size(slen: usize) -> CSize {
        match slen {
            0 => CSize::Fits(1),
            n => c_size(wide(n - 1) * 2 + 1),
        }
    }

    /// A string as a pattern (`getpatt`, `LUA_TSTRING`): `""` matches
    /// always, anything else is its bytes in sequence.
    pub fn literal(s: &[u8]) -> Result<Tree, TreeError> {
        if s.is_empty() {
            return Tree::leaf(Tag::True);
        }
        let mut nodes = alloc_c(wide(s.len() - 1) * 2 + 1)?;
        fillseq(&mut nodes, Tag::Char, s.len(), Some(s));
        Ok(Tree { nodes })
    }

    /// The size of `P(n)` (`numtree`): `2 * n - 1` for `n > 0`, `2 * -n` for
    /// `n < 0` (`-INT_MIN` is `INT_MIN` in the C, 2^31 here: the same
    /// modulo 2^32).
    #[must_use]
    pub fn number_size(n: i32) -> CSize {
        let m = u64::from(n.unsigned_abs());
        match n {
            0 => CSize::Fits(1),
            n if n > 0 => c_size(2 * m - 1),
            _ => c_size(2 * m),
        }
    }

    /// A number as a pattern (`numtree`, `lpeg.c:2381`): 0 matches always,
    /// `n > 0` is `n` of any byte, `n < 0` is not `-n` of any byte. `n` is
    /// already the C's `int` ([`super::narrow`]).
    pub fn number(n: i32) -> Result<Tree, TreeError> {
        if n == 0 {
            return Tree::leaf(Tag::True);
        }
        let m = usize::try_from(n.unsigned_abs()).map_err(|_| TreeError::NotEnoughMemory)?;
        let mut nodes = match Tree::number_size(n) {
            CSize::Fits(len) => alloc(len)?,
            CSize::TooBig => return Err(TreeError::BlockTooBig),
            CSize::Short(_) => return Err(TreeError::NotEnoughMemory),
        };
        if n < 0 {
            nodes.push(Node::new(Tag::Not));
        }
        fillseq(&mut nodes, Tag::Any, m, None);
        Ok(Tree { nodes })
    }

    /// A charset (`newcharset`, filled).
    pub fn charset(cs: &Charset) -> Result<Tree, TreeError> {
        let mut nodes = alloc(1 + SET_SLOTS)?;
        nodes.push(Node::new(Tag::Set));
        for i in 0..SET_SLOTS {
            nodes.push(set_slot(cs, i));
        }
        Ok(Tree { nodes })
    }

    /// `tocharset` (`lpeg.c:1022`) of the root: the set a `Set`, `Char` or
    /// `Any` pattern matches, and `None` for anything else.
    #[must_use]
    pub fn to_charset(&self) -> Option<Charset> {
        let root = self.nodes.first()?;
        match root.tag {
            Tag::Set => self.charset_at(0),
            Tag::Char => {
                let mut cs = Charset::empty();
                cs.add(u8::try_from(root.u).ok()?);
                Some(cs)
            }
            Tag::Any => Some(Charset([0xff; CHARSET_SIZE])),
            _ => None,
        }
    }

    /// A function as a pattern (`getpatt`, `LUA_TFUNCTION`): a run-time
    /// capture of the empty match, the function at `key`.
    pub fn runtime(key: Key) -> Result<Tree, TreeError> {
        let mut nodes = alloc(2)?;
        nodes.push(Node {
            key,
            ..Node::new(Tag::RunTime)
        });
        nodes.push(Node::new(Tag::True));
        Ok(Tree { nodes })
    }

    /// `newroot1sib`: a `tag` node over a copy of `sib`.
    pub fn root1(tag: Tag, sib: &Tree) -> Result<Tree, TreeError> {
        let mut nodes = alloc_c(1 + wide(sib.len()))?;
        nodes.push(Node::new(tag));
        nodes.extend_from_slice(&sib.nodes);
        Ok(Tree { nodes })
    }

    /// `newroot2sib`: a `tag` node over copies of `t1` and `t2`, `t2`'s keys
    /// shifted by `correction` (what `joinktables` returned).
    pub fn root2(tag: Tag, t1: &Tree, t2: &Tree, correction: Key) -> Result<Tree, TreeError> {
        let mut nodes = alloc_c(1 + wide(t1.len()) + wide(t2.len()))?;
        nodes.push(Node::with_u(tag, offset(1 + t1.len())?));
        nodes.extend_from_slice(&t1.nodes);
        nodes.extend_from_slice(&t2.nodes);
        let mut tree = Tree { nodes };
        let len = tree.len();
        tree.correct_keys(1 + t1.len(), len, correction)?;
        Ok(tree)
    }

    /// `lp_sub` for patterns that are not both charsets: `Seq(Not(t2), t1)`,
    /// `t2`'s keys shifted by `correction`.
    pub fn difference(t1: &Tree, t2: &Tree, correction: Key) -> Result<Tree, TreeError> {
        let mut nodes = alloc_c(2 + wide(t1.len()) + wide(t2.len()))?;
        nodes.push(Node::with_u(Tag::Seq, offset(2 + t2.len())?));
        nodes.push(Node::new(Tag::Not));
        nodes.extend_from_slice(&t2.nodes);
        nodes.extend_from_slice(&t1.nodes);
        let mut tree = Tree { nodes };
        tree.correct_keys(1, 2 + t2.len(), correction)?;
        Ok(tree)
    }

    /// `capture_aux`: a capture of kind `cap` over a copy of `sib`, with
    /// `key` (0 for none; a number for `Cnum`).
    pub fn capture(cap: CapKind, key: Key, sib: &Tree) -> Result<Tree, TreeError> {
        let mut tree = Tree::root1(Tag::Capture, sib)?;
        if let Some(root) = tree.nodes.first_mut() {
            root.cap = cap as u8;
            root.key = key;
        }
        Ok(tree)
    }

    /// `newemptycap`: a capture of the empty match.
    pub fn empty_capture(cap: CapKind, key: Key) -> Result<Tree, TreeError> {
        let mut nodes = alloc(2)?;
        nodes.push(Node {
            cap: cap as u8,
            key,
            ..Node::new(Tag::Capture)
        });
        nodes.push(Node::new(Tag::True));
        Ok(Tree { nodes })
    }

    /// `lp_constcapture` of two or more values: a group of one constant
    /// capture per value, each with its key (0 for `nil`).
    pub fn const_group(keys: &[Key]) -> Result<Tree, TreeError> {
        let n = keys.len();
        // `1 + 3 * (n - 1) + 2`.
        let mut nodes = alloc_c(wide(n).saturating_mul(3))?;
        nodes.push(Node {
            cap: CapKind::Group as u8,
            ..Node::new(Tag::Capture)
        });
        let const_cap = |key| Node {
            cap: CapKind::Const as u8,
            key,
            ..Node::new(Tag::Capture)
        };
        for (i, &key) in keys.iter().enumerate() {
            if i + 1 < n {
                nodes.push(Node::with_u(Tag::Seq, 3));
            }
            nodes.push(const_cap(key));
            nodes.push(Node::new(Tag::True));
        }
        Ok(Tree { nodes })
    }

    /// `lp_behind`'s tree: look `n` bytes behind for `sib`.
    pub fn behind(n: i32, sib: &Tree) -> Result<Tree, TreeError> {
        let mut tree = Tree::root1(Tag::Behind, sib)?;
        if let Some(root) = tree.nodes.first_mut() {
            root.u = n;
        }
        Ok(tree)
    }

    /// The size of `p^n` for `p` of `size1` nodes (`lp_star`,
    /// `lpeg.c:2638-2660`): `(n + 1) * (size1 + 1)` for `n >= 0` and
    /// `-n * (size1 + 3) - 1` otherwise, both `int` products in the C
    /// (`-INT_MIN` is `INT_MIN` there, 2^31 here: the same modulo 2^32). A
    /// [`CSize::Short`] size is allocated before the C checks a body for an
    /// empty loop (`n >= 0`), and the check comes before any write.
    #[must_use]
    pub fn star_size(size1: usize, n: i32) -> CSize {
        let s = wide(size1);
        let m = u64::from(n.unsigned_abs());
        if n >= 0 {
            c_size((m + 1).saturating_mul(s.saturating_add(1)))
        } else {
            c_size(m.saturating_mul(s.saturating_add(3)) - 1)
        }
    }

    /// The size of `p^n` when the C's `int` holds it ([`Tree::star_size`]).
    pub fn star_len(size1: usize, n: i32) -> Result<usize, TreeError> {
        match Tree::star_size(size1, n) {
            CSize::Fits(len) => Ok(len),
            CSize::TooBig => Err(TreeError::BlockTooBig),
            CSize::Short(_) => Err(TreeError::NotEnoughMemory),
        }
    }

    /// Room for `p^n` ([`Tree::star_len`] nodes): allocated before `p` is
    /// checked for an empty loop body, as `lp_star` allocates first.
    pub fn star_space(size1: usize, n: i32) -> Result<Vec<Node>, TreeError> {
        zeroed(Tree::star_len(size1, n)?)
    }

    /// `p^n` (`lp_star`), into `space` from [`Tree::star_space`]:
    /// - `n >= 0`: `n` copies of `p` in sequence, then `p*`;
    /// - `n < 0`: at most `-n` copies, as nested choices with `true`.
    pub fn star(t1: &Tree, n: i32, mut space: Vec<Node>) -> Result<Tree, TreeError> {
        let s = t1.len();
        if space.len() != Tree::star_len(s, n)? {
            return Err(TreeError::Malformed);
        }
        let ps = offset(s + 1)?;
        let mut at = 0usize;
        if n >= 0 {
            for _ in 0..n {
                // `seqaux`
                space[at] = Node::with_u(Tag::Seq, ps);
                space[at + 1..at + 1 + s].copy_from_slice(&t1.nodes);
                at += s + 1;
            }
            space[at] = Node::new(Tag::Rep);
            space[at + 1..at + 1 + s].copy_from_slice(&t1.nodes);
        } else {
            let mut m =
                usize::try_from(i64::from(n).unsigned_abs()).map_err(|_| TreeError::Malformed)?;
            while m > 1 {
                let span = m * (s + 3);
                space[at] = Node::with_u(Tag::Choice, offset(span - 2)?);
                space[at + span - 2] = Node::new(Tag::True);
                at += 1;
                space[at] = Node::with_u(Tag::Seq, ps);
                space[at + 1..at + 1 + s].copy_from_slice(&t1.nodes);
                at += s + 1;
                m -= 1;
            }
            space[at] = Node::with_u(Tag::Choice, ps);
            space[at + s + 1] = Node::new(Tag::True);
            space[at + 1..at + 1 + s].copy_from_slice(&t1.nodes);
        }
        Ok(Tree { nodes: space })
    }

    /// `correctkeys(tree, n)` over the subtree in `from..to`: add `n` to every
    /// key that indexes the constant table — on calls, rules, run-time
    /// captures and captures other than `Carg` and `Cnum`, whose keys are
    /// numbers.
    ///
    /// The C walks the subtree by its siblings. Every slot of a tree built
    /// here is either a node that walk reaches or a charset's data, and the
    /// nodes are in the walk's pre-order, so a scan of the slots that skips
    /// charset data visits exactly the same nodes, with no stack.
    pub fn correct_keys(&mut self, from: usize, to: usize, n: Key) -> Result<(), TreeError> {
        correct_keys(&mut self.nodes, from, to, n, usize::MAX).map(|_| ())
    }

    /// `hascaptures` (`lpeg.c:1045`) of the whole tree: whether any node is a
    /// capture or a run-time capture. A scan of the slots, as in
    /// [`Tree::correct_keys`].
    #[must_use]
    pub fn has_captures(&self) -> bool {
        let mut i = 0;
        while let Some(node) = self.nodes.get(i) {
            if matches!(node.tag, Tag::Capture | Tag::RunTime) {
                return true;
            }
            i += if node.tag == Tag::Set {
                1 + SET_SLOTS
            } else {
                1
            };
        }
        false
    }

    /// Set the key of node `i` (`initialrulename`, `capture_aux`).
    pub fn set_key(&mut self, i: usize, key: Key) {
        if let Some(n) = self.nodes.get_mut(i) {
            n.key = key;
        }
    }

    /// Set the counter of node `i` (`u.n`).
    pub fn set_u(&mut self, i: usize, u: i32) {
        if let Some(n) = self.nodes.get_mut(i) {
            n.u = u;
        }
    }

    pub(crate) fn nodes_mut(&mut self) -> &mut [Node] {
        &mut self.nodes
    }

    /// A tree of these nodes, laid out as [`Tree`] says: the compiler's copy
    /// of a pattern's tree, which it fixes and compiles (step c).
    pub(crate) fn from_nodes(nodes: Vec<Node>) -> Tree {
        Tree { nodes }
    }

    /// The bytes the tree holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<Node>())
    }
}

/// `correctkeys` over the nodes in `from..to`, at most `max` of them: the
/// slot to go on from, which is past `to` when it is done, and always a node
/// (never a charset's data). See [`Tree::correct_keys`].
fn correct_keys(
    nodes: &mut [Node],
    from: usize,
    to: usize,
    n: Key,
    max: usize,
) -> Result<usize, TreeError> {
    let to = to.min(nodes.len());
    if n == 0 {
        return Ok(to.max(from));
    }
    let mut i = from;
    let mut done = 0usize;
    while i < to && done < max {
        let node = &mut nodes[i];
        let shifts = match node.tag {
            Tag::OpenCall | Tag::Call | Tag::RunTime | Tag::Rule => true,
            Tag::Capture => node.cap != CapKind::Arg as u8 && node.cap != CapKind::Num as u8,
            _ => false,
        };
        if shifts && node.key > 0 {
            node.key = node.key.checked_add(n).ok_or(TreeError::NotEnoughMemory)?;
        }
        i += if node.tag == Tag::Set {
            1 + SET_SLOTS
        } else {
            1
        };
        done += 1;
    }
    Ok(i)
}

/// Where each rule of a grammar goes, and the grammar's size
/// (`collectrules`): the first rule's `Rule` node is at 1, each next one
/// after the last's pattern, and a `True` closes the list.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GrammarLayout {
    /// The index of each rule's `Rule` node, in rule order.
    pub positions: Vec<usize>,
    /// The tree's size: `Grammar`, each rule and its `Rule` node, `True`.
    pub size: usize,
}

impl GrammarLayout {
    /// The size of a grammar of rules of `sizes` nodes (`collectrules`):
    /// `Grammar`, each rule and its `Rule` node, and `True`.
    #[must_use]
    pub fn size(sizes: impl IntoIterator<Item = usize>) -> u64 {
        sizes
            .into_iter()
            .fold(2, |n: u64, s| n.saturating_add(1).saturating_add(wide(s)))
    }

    /// The layout for rules of `sizes` nodes, in order.
    pub fn new(sizes: &[usize]) -> Result<GrammarLayout, TreeError> {
        let size = match c_size(GrammarLayout::size(sizes.iter().copied())) {
            CSize::Fits(n) => n,
            CSize::TooBig => return Err(TreeError::BlockTooBig),
            CSize::Short(_) => return Err(TreeError::NotEnoughMemory),
        };
        let mut positions = Vec::new();
        if !reserve(&mut positions, sizes.len()) {
            return Err(TreeError::NotEnoughMemory);
        }
        let mut at = 1usize;
        for &s in sizes {
            positions.push(at);
            at += 1 + s;
        }
        Ok(GrammarLayout { positions, size })
    }

    /// `newtree(L, treesize)` for this grammar: allocated before the rule
    /// count is checked, as `newgrammar` allocates first.
    pub fn space(&self) -> Result<Vec<Node>, TreeError> {
        alloc(self.size)
    }

    /// `buildgrammar` (`lpeg.c:2988`) at once: the grammar of `rules`, each
    /// with the shift its keys take when its constant table is appended to
    /// the grammar's. See [`GrammarBuild`], which does it a slice at a time.
    pub fn build(&self, rules: &[(&Tree, Key)], space: Vec<Node>) -> Result<Tree, TreeError> {
        let mut b = GrammarBuild::new(space, rules.len())?;
        for (i, (rule, correction)) in rules.iter().enumerate() {
            let at = b.rule(i, rule.len())?;
            b.copy(rule, 0, usize::MAX);
            b.correct(at, at + rule.len(), *correction, usize::MAX)?;
        }
        Ok(b.finish())
    }
}

/// `buildgrammar` (`lpeg.c:2988`), in pieces a slice of fuel can do: each
/// rule's `Rule` node, then its nodes copied, then its keys shifted by what
/// its constant table's entries moved by when they were appended to the
/// grammar's (`mergektable`). Rule `i` is numbered `i` (`cap`), its key is 0
/// until a call to it is fixed, and its offset leads to the next; a `True`
/// closes the list.
#[derive(Debug, Clone)]
pub struct GrammarBuild {
    nodes: Vec<Node>,
}

impl GrammarBuild {
    /// Start in `space` (from [`alloc`] or [`GrammarLayout::space`]) a
    /// grammar of `rules` rules: its `Grammar` node.
    pub fn new(mut space: Vec<Node>, rules: usize) -> Result<GrammarBuild, TreeError> {
        let n = i32::try_from(rules).map_err(|_| TreeError::NotEnoughMemory)?;
        space.clear();
        space.push(Node::with_u(Tag::Grammar, n));
        Ok(GrammarBuild { nodes: space })
    }

    /// Rule `i`'s `Rule` node, for a rule of `len` nodes: where its first
    /// node will be.
    pub fn rule(&mut self, i: usize, len: usize) -> Result<usize, TreeError> {
        self.nodes.push(Node {
            cap: u8::try_from(i).map_err(|_| TreeError::Malformed)?,
            ..Node::with_u(Tag::Rule, offset(len + 1)?)
        });
        Ok(self.nodes.len())
    }

    /// Copy `rule`'s nodes from `from`, at most `max` of them: where the next
    /// copy goes on from (`rule.len()` when it is done).
    pub fn copy(&mut self, rule: &Tree, from: usize, max: usize) -> usize {
        let end = rule.len().min(from.saturating_add(max));
        if let Some(part) = rule.nodes.get(from..end) {
            self.nodes.extend_from_slice(part);
        }
        end.max(from)
    }

    /// `correctkeys(rule, n)` over the nodes `from..to`, at most `max` of
    /// them: where to go on from (`to` or past it when it is done).
    pub fn correct(
        &mut self,
        from: usize,
        to: usize,
        n: Key,
        max: usize,
    ) -> Result<usize, TreeError> {
        correct_keys(&mut self.nodes, from, to, n, max)
    }

    /// The tree, its list of rules closed.
    #[must_use]
    pub fn finish(mut self) -> Tree {
        self.nodes.push(Node::new(Tag::True));
        Tree { nodes: self.nodes }
    }

    /// The bytes the tree being built holds outside the VM's heap.
    #[must_use]
    pub fn heap_bytes(&self) -> usize {
        self.nodes
            .capacity()
            .saturating_mul(std::mem::size_of::<Node>())
    }
}

#[cfg(test)]
mod tests;
