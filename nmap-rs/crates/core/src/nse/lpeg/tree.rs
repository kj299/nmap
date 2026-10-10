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
//! **Where the C is not followed.** Every size is computed with checked
//! arithmetic and asked of the memory budget before anything is written;
//! a size the C computes in an overflowing `int` is `not enough memory`
//! here (`lpeg-tree-size-int-overflow`, `lpeg-pattern-string-size-overflow`).
//! And no walker recurses on the Rust stack (E2): each is a loop over an
//! explicit stack, and the ones that can take exponential time are
//! resumable state machines that stop when their step budget runs out
//! ([`walk`]).

#![allow(
    clippy::arithmetic_side_effects,
    reason = "index arithmetic is on positions inside a tree, all below MAX_TREE (2^31 - 1), \
              so the sum of two cannot overflow usize; every size derived from a script's \
              input is computed with checked arithmetic"
)]

use crate::nse::stdlib::reserve;

mod walk;

pub use walk::{CheckAux, CheckLoops, FinalFix, FixedLen, Pred, VerifyGrammar};

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

/// The largest tree, in nodes: the C counts sizes in `int`, so a larger one
/// is an overflow there (undefined, and in practice a heap overrun) and `not
/// enough memory` here.
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
    /// A size past [`MAX_TREE`], or refused by the memory budget or the
    /// allocator.
    NotEnoughMemory,
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

/// A vector for `len` nodes, or `not enough memory`.
fn alloc(len: usize) -> Result<Vec<Node>, TreeError> {
    if len > MAX_TREE {
        return Err(TreeError::NotEnoughMemory);
    }
    let mut v = Vec::new();
    if !reserve(&mut v, len) {
        return Err(TreeError::NotEnoughMemory);
    }
    Ok(v)
}

/// `len` zeroed nodes, to be filled by index as the C fills a `newtree`.
fn zeroed(len: usize) -> Result<Vec<Node>, TreeError> {
    let mut v = alloc(len)?;
    v.resize(len, Node::new(Tag::True));
    Ok(v)
}

/// `a + b` in nodes, or `not enough memory`.
fn add(a: usize, b: usize) -> Result<usize, TreeError> {
    a.checked_add(b).ok_or(TreeError::NotEnoughMemory)
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

    /// A string as a pattern (`getpatt`, `LUA_TSTRING`): `""` matches
    /// always, anything else is its bytes in sequence.
    pub fn literal(s: &[u8]) -> Result<Tree, TreeError> {
        if s.is_empty() {
            return Tree::leaf(Tag::True);
        }
        // 2 * (slen - 1) + 1, which overflows the C's `int` at 1 GiB.
        let len = (s.len() - 1)
            .checked_mul(2)
            .ok_or(TreeError::NotEnoughMemory)?;
        let mut nodes = alloc(add(len, 1)?)?;
        fillseq(&mut nodes, Tag::Char, s.len(), Some(s));
        Ok(Tree { nodes })
    }

    /// A number as a pattern (`numtree`, `lpeg.c:2381`): 0 matches always,
    /// `n > 0` is `n` of any byte, `n < 0` is not `-n` of any byte. `n` is
    /// already the C's `int` ([`super::narrow`]).
    pub fn number(n: i32) -> Result<Tree, TreeError> {
        if n == 0 {
            return Tree::leaf(Tag::True);
        }
        let m =
            usize::try_from(i64::from(n).unsigned_abs()).map_err(|_| TreeError::NotEnoughMemory)?;
        let seq = m.checked_mul(2).ok_or(TreeError::NotEnoughMemory)?;
        if n > 0 {
            let mut nodes = alloc(seq - 1)?;
            fillseq(&mut nodes, Tag::Any, m, None);
            Ok(Tree { nodes })
        } else {
            let mut nodes = alloc(seq)?;
            nodes.push(Node::new(Tag::Not));
            fillseq(&mut nodes, Tag::Any, m, None);
            Ok(Tree { nodes })
        }
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
        let mut nodes = alloc(add(1, sib.len())?)?;
        nodes.push(Node::new(tag));
        nodes.extend_from_slice(&sib.nodes);
        Ok(Tree { nodes })
    }

    /// `newroot2sib`: a `tag` node over copies of `t1` and `t2`, `t2`'s keys
    /// shifted by `correction` (what `joinktables` returned).
    pub fn root2(tag: Tag, t1: &Tree, t2: &Tree, correction: Key) -> Result<Tree, TreeError> {
        let len = add(add(1, t1.len())?, t2.len())?;
        let mut nodes = alloc(len)?;
        nodes.push(Node::with_u(tag, offset(1 + t1.len())?));
        nodes.extend_from_slice(&t1.nodes);
        nodes.extend_from_slice(&t2.nodes);
        let mut tree = Tree { nodes };
        tree.correct_keys(1 + t1.len(), len, correction)?;
        Ok(tree)
    }

    /// `lp_sub` for patterns that are not both charsets: `Seq(Not(t2), t1)`,
    /// `t2`'s keys shifted by `correction`.
    pub fn difference(t1: &Tree, t2: &Tree, correction: Key) -> Result<Tree, TreeError> {
        let len = add(add(2, t1.len())?, t2.len())?;
        let mut nodes = alloc(len)?;
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
        let len = n
            .checked_sub(1)
            .and_then(|m| m.checked_mul(3))
            .and_then(|m| m.checked_add(3))
            .ok_or(TreeError::NotEnoughMemory)?;
        let mut nodes = alloc(len)?;
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
    /// `-n * (size1 + 3) - 1` otherwise, both `int` products in the C.
    pub fn star_len(size1: usize, n: i32) -> Result<usize, TreeError> {
        let big = |v: Option<usize>| v.ok_or(TreeError::NotEnoughMemory);
        let len = if n >= 0 {
            let reps = usize::try_from(n).map_err(|_| TreeError::NotEnoughMemory)?;
            big(reps
                .checked_add(1)
                .and_then(|r| r.checked_mul(size1.checked_add(1)?)))?
        } else {
            let m = usize::try_from(i64::from(n).unsigned_abs())
                .map_err(|_| TreeError::NotEnoughMemory)?;
            big(m
                .checked_mul(size1.checked_add(3).ok_or(TreeError::NotEnoughMemory)?)
                .and_then(|l| l.checked_sub(1)))?
        };
        if len > MAX_TREE {
            return Err(TreeError::NotEnoughMemory);
        }
        Ok(len)
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
        if n == 0 {
            return Ok(());
        }
        let to = to.min(self.nodes.len());
        let mut i = from;
        while i < to {
            let node = &mut self.nodes[i];
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
        }
        Ok(())
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
    /// The layout for rules of `sizes` nodes, in order.
    pub fn new(sizes: &[usize]) -> Result<GrammarLayout, TreeError> {
        let mut positions = Vec::new();
        if !reserve(&mut positions, sizes.len()) {
            return Err(TreeError::NotEnoughMemory);
        }
        let mut size = 1usize;
        for &s in sizes {
            positions.push(size);
            size = add(add(size, 1)?, s)?;
        }
        let size = add(size, 1)?;
        if size > MAX_TREE {
            return Err(TreeError::NotEnoughMemory);
        }
        Ok(GrammarLayout { positions, size })
    }

    /// `newtree(L, treesize)` for this grammar: allocated before the rule
    /// count is checked, as `newgrammar` allocates first.
    pub fn space(&self) -> Result<Vec<Node>, TreeError> {
        alloc(self.size)
    }

    /// `buildgrammar` (`lpeg.c:2988`): the grammar of `rules`, each with the
    /// shift its keys take when its constant table is appended to the
    /// grammar's (`mergektable`). Rule `i` is numbered `i` (`cap`), its key
    /// is 0 until a call to it is fixed, and its offset leads to the next.
    pub fn build(&self, rules: &[(&Tree, Key)], mut space: Vec<Node>) -> Result<Tree, TreeError> {
        let n = i32::try_from(rules.len()).map_err(|_| TreeError::NotEnoughMemory)?;
        space.clear();
        space.push(Node::with_u(Tag::Grammar, n));
        for (i, (rule, _)) in rules.iter().enumerate() {
            space.push(Node {
                cap: u8::try_from(i).map_err(|_| TreeError::Malformed)?,
                ..Node::with_u(Tag::Rule, offset(rule.len() + 1)?)
            });
            space.extend_from_slice(&rule.nodes);
        }
        space.push(Node::new(Tag::True));
        let mut tree = Tree { nodes: space };
        for ((rule, correction), &at) in rules.iter().zip(&self.positions) {
            tree.correct_keys(at + 1, at + 1 + rule.len(), *correction)?;
        }
        Ok(tree)
    }
}

#[cfg(test)]
mod tests;
