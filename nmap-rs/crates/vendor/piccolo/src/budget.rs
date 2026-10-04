//! A Lua state's memory budget (`Lua::set_memory_limit`).
//!
//! The budget lives outside the GC arena, so that code holding no `Context`
//! — a table growing its array part — can ask it before it allocates. While
//! [`crate::Lua::enter`] runs, the budget of the state entered is this
//! thread's current one.

use std::{
    cell::{Cell, RefCell},
    rc::Rc,
};

use gc_arena::metrics::Metrics;

pub(crate) struct Budget {
    pub(crate) limit: Cell<usize>,
    /// An allocation was refused, and the code that asked has not yet failed.
    pub(crate) refused: Cell<bool>,
    /// A "not enough memory" error is unwinding to its handler.
    pub(crate) unwinding: Cell<bool>,
    /// Code grew the heap past the budget: a full collection must run before
    /// Lua code goes on.
    pub(crate) collect: Cell<bool>,
    /// That collection left the heap past the budget: the code fails.
    pub(crate) failed: Cell<bool>,
    /// A full collection should run before Lua code goes on, with no one to
    /// fail after it: a "not enough memory" error has reached its handler.
    pub(crate) sweep: Cell<bool>,
    /// What the last full collection left live.
    pub(crate) live: Cell<usize>,
    metrics: Metrics,
}

impl Budget {
    pub(crate) fn new(metrics: Metrics) -> Self {
        Budget {
            limit: Cell::new(usize::MAX),
            refused: Cell::new(false),
            unwinding: Cell::new(false),
            collect: Cell::new(false),
            failed: Cell::new(false),
            sweep: Cell::new(false),
            live: Cell::new(0),
            metrics,
        }
    }

    /// The heap's size now, as the budget counts it.
    pub(crate) fn total(&self) -> usize {
        self.metrics.total_allocation()
    }

    /// Whether `bytes` more may be allocated, as PUC-Lua's allocator decides
    /// (`luaM_malloc_`): what does not fit now is granted if it would fit
    /// beside what the last full collection left live, and a full collection
    /// then runs before Lua goes on, failing the code if the heap is still
    /// past the budget after it. What would not fit even then is refused,
    /// and the refusal recorded.
    pub(crate) fn allows(&self, bytes: usize) -> bool {
        let limit = self.limit.get();
        if self.total().saturating_add(bytes) <= limit {
            true
        } else if self.live.get().saturating_add(bytes) <= limit {
            self.collect.set(true);
            true
        } else {
            self.refused.set(true);
            false
        }
    }
}

thread_local! {
    static CURRENT: RefCell<Option<Rc<Budget>>> = const { RefCell::new(None) };
}

/// Makes a budget this thread's current one until dropped, then restores the
/// one before it.
pub(crate) struct Entered(Option<Rc<Budget>>);

pub(crate) fn enter(budget: Rc<Budget>) -> Entered {
    Entered(CURRENT.with(|c| c.replace(Some(budget))))
}

impl Drop for Entered {
    fn drop(&mut self) {
        let previous = self.0.take();
        CURRENT.with(|c| *c.borrow_mut() = previous);
    }
}

/// Whether `bytes` more fit the budget of the Lua state entered on this
/// thread; always, outside one. A refusal is recorded, and the Lua code
/// running fails with "not enough memory".
///
/// A callback that builds a buffer whose size a script chooses asks this
/// before it reserves the space: an allocator that overcommits grants
/// gigabytes it cannot back, and one that does not aborts the process.
pub fn allows(bytes: usize) -> bool {
    CURRENT.with(|c| c.borrow().as_ref().map_or(true, |b| b.allows(bytes)))
}
