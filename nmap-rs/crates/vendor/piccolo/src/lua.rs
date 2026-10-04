use std::{ops, rc::Rc};

use gc_arena::{
    arena::{CollectionPhase, Root},
    metrics::Metrics,
    Arena, Collect, Gc, Mutation, Rootable,
};

use crate::{
    budget::{self, Budget},
    finalizers::Finalizers,
    stash::{Fetchable, Stashable},
    stdlib::{load_base, load_coroutine, load_io, load_math, load_string, load_table},
    string::InternedStringSet,
    thread::BadThreadMode,
    Error, ExternError, FromMultiValue, FromValue, Fuel, IntoValue, Registry, RuntimeError,
    Singleton, StashedExecutor, String, Table, TypeError, Value,
};

/// A value representing the main "execution context" of a Lua state.
///
/// It provides access to the table of global variables, the registry, the string interner, and
/// other state that most every piece of running Lua code will need access to.
///
/// It is a cheap, copyable reference type that references internal state variables inside a [`Lua`]
/// instance.
///
/// As a convenience, it also contains the [`gc_arena::Mutation`] reference provided by `gc-arena`
/// when mutating a [`gc_arena::Arena`]. This allows code that uses piccolo to accept a single `ctx:
/// Context<'gc>` parameter, rather than having to accept both the piccolo `ctx` *and* the usual
/// `mc: &Mutation<'gc>` parameter.
///
/// To access the contained [`Mutation`] context, there is a `Deref` impl on `Context` that derefs
/// to `Mutation` that can be used like so:
///
/// ```
/// # use gc_arena::Gc;
/// # use piccolo::Lua;
/// # let mut lua = Lua::empty();
/// lua.enter(|ctx| {
///     // Create a new `Gc<'gc, i32>` pointer using the `&Mutation` held inside `ctx`
///     let p = Gc::new(&ctx, 13);
/// });
/// ```
#[derive(Copy, Clone)]
pub struct Context<'gc> {
    mutation: &'gc Mutation<'gc>,
    state: &'gc State<'gc>,
}

impl<'gc> Context<'gc> {
    /// Get a reference to [`Mutation`] (the `gc-arena` mutation handle) out of the `Context`
    /// object.
    ///
    /// This can also be done automatically with `Deref` coercion.
    pub fn mutation(self) -> &'gc Mutation<'gc> {
        self.mutation
    }

    pub fn globals(self) -> Table<'gc> {
        self.state.globals
    }

    pub fn registry(self) -> Registry<'gc> {
        self.state.registry
    }

    pub fn interned_strings(self) -> InternedStringSet<'gc> {
        self.state.strings
    }

    pub fn finalizers(self) -> Finalizers<'gc> {
        self.state.finalizers
    }

    // Calls `ctx.globals().get(key)`
    pub fn get_global<V: FromValue<'gc>>(self, key: &'static str) -> Result<V, TypeError> {
        self.state.globals.get(self, key)
    }

    // Calls `ctx.globals().get_value(key)`
    pub fn get_global_value(self, key: &'static str) -> Value<'gc> {
        self.state.globals.get_value(self, key)
    }

    // Calls `ctx.globals().set_field(key, value)`
    pub fn set_global<V: IntoValue<'gc>>(self, key: &'static str, value: V) -> Value<'gc> {
        self.state.globals.set_field(self, key, value)
    }

    /// Calls `ctx.registry().singleton::<S>(ctx)`.
    pub fn singleton<S>(self) -> &'gc Root<'gc, S>
    where
        S: for<'a> Rootable<'a> + 'static,
        Root<'gc, S>: Sized + Singleton<'gc> + Collect,
    {
        self.state.registry.singleton::<S>(self)
    }

    /// Calls `ctx.registry().stash(ctx, s)`.
    pub fn stash<S: Stashable<'gc>>(self, s: S) -> S::Stashed {
        self.state.registry.stash(&self, s)
    }

    /// Calls `ctx.registry().fetch(f)`.
    pub fn fetch<F: Fetchable>(self, f: &F) -> F::Fetched<'gc> {
        self.state.registry.fetch(f)
    }

    /// Calls `ctx.interned_strings().intern(&ctx, s)`.
    ///
    /// A string of `REFUSE_FROM` bytes or more that does not fit the memory
    /// budget is not made: the empty string comes back in its place, and the
    /// running Lua code fails with "not enough memory" before anything sees
    /// it (see [`Context::can_allocate`]).
    pub fn intern(self, s: &[u8]) -> String<'gc> {
        if s.len() >= REFUSE_FROM && !self.can_allocate(s.len()) {
            return self.state.empty;
        }
        self.state.strings.intern(&self, s)
    }

    /// The memory budget, in bytes ([`Lua::set_memory_limit`]).
    pub fn memory_limit(self) -> usize {
        self.state.budget.limit.get()
    }

    /// Whether `bytes` more may be allocated under the memory budget. Code
    /// that builds a buffer whose size a script chooses asks first, as
    /// PUC-Lua's allocator would be asked.
    ///
    /// The heap the budget counts holds garbage not yet collected, and
    /// PUC-Lua's allocator, refused, collects in full and tries again before
    /// it fails. So a request that does not fit now, but would beside what the
    /// last full collection left live, is granted, and a full collection runs
    /// before Lua goes on, failing the code with "not enough memory" if the
    /// heap is still past the budget then. A request that would not fit even
    /// then is refused: the Lua code running fails with "not enough memory"
    /// (`LUA_ERRMEM`) as soon as the callback, or the instruction, making it
    /// returns.
    pub fn can_allocate(self, bytes: usize) -> bool {
        self.state.budget.allows(bytes)
    }

    /// The heap's size now, to pass to [`Context::memory_check`] after the
    /// code it measures.
    pub fn memory_mark(self) -> usize {
        self.metrics().total_allocation()
    }

    /// Whether the code that ran since `mark` must fail with "not enough
    /// memory" now: an allocation it asked for was refused.
    ///
    /// Code that grew the heap past the budget does not fail here. PUC-Lua's
    /// allocator, refused, collects in full and tries again before it fails
    /// (`luaM_malloc_`); so a full collection is requested instead
    /// ([`Context::collection_requested`]), and if the heap is still past the
    /// budget after it, the code fails then, before it runs on (see
    /// [`Lua::enter`]). Code that allocates nothing never fails, so a script
    /// can always drop what it holds.
    pub fn memory_check(self, mark: usize) -> bool {
        let budget = &self.state.budget;
        if budget.refused.get() {
            return true;
        }
        let total = self.metrics().total_allocation();
        if total > budget.limit.get() && total > mark {
            budget.collect.set(true);
        }
        false
    }

    /// Whether a full collection must run before Lua code goes on: the
    /// executor ends its step, and [`Lua::enter`] collects.
    pub fn collection_requested(self) -> bool {
        self.state.budget.collect.get()
    }

    /// The error of a refused allocation: `LUA_ERRMEM`'s "not enough memory",
    /// made in advance so that raising it allocates nothing.
    pub fn not_enough_memory(self) -> Error<'gc> {
        Value::String(self.state.not_enough_memory).into()
    }

    /// The error of a call nested past the margin error handlers have:
    /// `LUA_ERRERR`'s "error in error handling".
    pub fn error_in_error_handling(self) -> Error<'gc> {
        Value::String(self.state.error_in_error_handling).into()
    }

    /// Whether `error` is one PUC-Lua throws past any message handler
    /// (`luaD_throw` with `LUA_ERRMEM` or `LUA_ERRERR`, not `luaG_errormsg`).
    /// A memory error is recognised by its text: `lua_error` raises any error
    /// object equal to the memory-error message as a memory error, so
    /// `error("not enough memory", 0)` is one too. "error in error handling"
    /// is recognised only as the very string
    /// [`Context::error_in_error_handling`] raises.
    pub fn bypasses_handler(self, error: &Error<'gc>) -> bool {
        let Error::Lua(e) = error else {
            return false;
        };
        let Value::String(s) = e.0 else {
            return false;
        };
        s.as_bytes() == crate::limits::NOT_ENOUGH_MEMORY.as_bytes()
            || Gc::ptr_eq(
                s.into_inner(),
                self.state.error_in_error_handling.into_inner(),
            )
    }

    /// Forget a refusal made outside any running Lua code, which has nothing
    /// to fail.
    pub(crate) fn clear_memory_refusal(self) {
        self.state.budget.refused.set(false);
    }

    /// Whether the code that last grew the heap past the budget must fail,
    /// the collection it requested having left the heap past it still.
    pub(crate) fn take_memory_failure(self) -> bool {
        self.state.budget.failed.replace(false)
    }

    /// Note that a "not enough memory" error is on its way to a handler, and
    /// forget the refusal that raised it.
    pub(crate) fn begin_memory_unwind(self) {
        self.state.budget.refused.set(false);
        self.state.budget.unwinding.set(true);
    }

    /// Whether a "not enough memory" error has just reached a handler, which
    /// should then wait for a collection before it runs; if so, that
    /// collection is requested.
    pub(crate) fn end_memory_unwind(self) -> bool {
        let caught = self.state.budget.unwinding.replace(false);
        if caught {
            self.state.budget.sweep.set(true);
        }
        caught
    }

    /// Calls `ctx.interned_strings().intern_static(&ctx, s)`.
    pub fn intern_static(self, s: &'static [u8]) -> String<'gc> {
        self.state.strings.intern_static(&self, s)
    }
}

impl<'gc> ops::Deref for Context<'gc> {
    type Target = Mutation<'gc>;

    fn deref(&self) -> &Self::Target {
        self.mutation
    }
}

/// Strings this long or longer are refused when they do not fit the memory
/// budget. A shorter one is made anyway, so that the VM's own small strings
/// (metamethod names, error messages) are always real; the code that asked
/// for it fails all the same.
pub const REFUSE_FROM: usize = 4096;

/// A Lua execution environment.
///
/// This is the top-level `piccolo` type. In order to load and call any Lua code, the first step is
/// to create a `Lua` instance.
pub struct Lua {
    arena: Arena<Rootable![State<'_>]>,
    budget: Rc<Budget>,
    /// The heap size past which `enter` collects in full before it returns.
    collect_at: usize,
}

impl Default for Lua {
    fn default() -> Self {
        Lua::core()
    }
}

impl Lua {
    /// Create a new `Lua` instance with no parts of the stdlib loaded.
    pub fn empty() -> Self {
        let arena = Arena::<Rootable![State<'_>]>::new(|mc| State::new(mc));
        let budget = arena.mutate(|_, state| state.budget.clone());
        Lua {
            arena,
            budget,
            collect_at: usize::MAX,
        }
    }

    /// Create a new `Lua` instance with the core stdlib loaded.
    pub fn core() -> Self {
        let mut lua = Self::empty();
        lua.load_core();
        lua
    }

    /// Create a new `Lua` instance with all of the stdlib loaded.
    pub fn full() -> Self {
        let mut lua = Lua::core();
        lua.load_io();
        lua
    }

    /// Load the core parts of the stdlib that do not allow performing any I/O.
    ///
    /// Calls:
    ///   - `load_base`
    ///   - `load_coroutine`
    ///   - `load_math`
    ///   - `load_string`
    ///   - `load_table`
    pub fn load_core(&mut self) {
        self.enter(|ctx| {
            load_base(ctx);
            load_coroutine(ctx);
            load_math(ctx);
            load_string(ctx);
            load_table(ctx);
        })
    }

    /// Load the parts of the stdlib that allow I/O.
    pub fn load_io(&mut self) {
        self.enter(|ctx| {
            load_io(ctx);
        })
    }

    /// Size of all memory used by this Lua context.
    ///
    /// This is equivalent to `self.gc_metrics().total_allocation()`. This counts all `Gc` allocated
    /// memory and also all data Lua datastructures held inside `Gc`, as they are tracked as
    /// "external allocations" in `gc-arena`.
    pub fn total_memory(&self) -> usize {
        self.gc_metrics().total_allocation()
    }

    /// Finish the current collection cycle completely, calls `gc_arena::Arena::collect_all()`.
    pub fn gc_collect(&mut self) {
        if self.arena.collection_phase() != CollectionPhase::Collecting {
            self.arena.mark_all().unwrap().finalize(|fc, root| {
                root.finalizers.prepare(fc);
            });
            self.arena.mark_all().unwrap().finalize(|fc, root| {
                root.finalizers.finalize(fc);
            });
        }

        self.arena.collect_all();
        assert!(self.arena.collection_phase() == CollectionPhase::Sleeping);
    }

    pub fn gc_metrics(&self) -> &Metrics {
        self.arena.metrics()
    }

    /// Limit the memory this state's Lua code may use, in bytes, as counted by
    /// [`Lua::total_memory`]. Past it, an allocation fails with a catchable
    /// "not enough memory" instead of growing the heap until the system
    /// refuses and the process aborts. Unlimited by default.
    pub fn set_memory_limit(&mut self, limit: usize) {
        self.budget.limit.set(limit);
        self.budget.live.set(self.total_memory());
        self.collect_at = self.next_collection(self.total_memory());
    }

    pub fn memory_limit(&self) -> usize {
        self.budget.limit.get()
    }

    /// Where the next full collection falls when `live` bytes survived the
    /// last: halfway to the limit, so that garbage alone never fills the
    /// budget.
    fn next_collection(&self, live: usize) -> usize {
        let limit = self.memory_limit();
        live.saturating_add(limit.saturating_sub(live) / 2)
    }

    /// Enter the garbage collection arena and perform some operation.
    ///
    /// In order to interact with Lua or do any useful work with Lua values, you must do so from
    /// *within* the garbage collection arena. All values branded with the `'gc` branding lifetime
    /// must forever live *inside* the arena, and cannot escape it.
    ///
    /// Garbage collection takes place *in-between* calls to `Lua::enter`, no garbage will be
    /// collected concurrently with accessing the arena.
    ///
    /// Automatically triggers garbage collection before returning if the allocation debt is larger
    /// than a small constant.
    pub fn enter<F, T>(&mut self, f: F) -> T
    where
        F: for<'gc> FnOnce(Context<'gc>) -> T,
    {
        const COLLECTOR_GRANULARITY: f64 = 1024.0;

        let entered = budget::enter(self.budget.clone());
        let r = self.arena.mutate(move |mc, state| f(state.ctx(mc)));
        drop(entered);
        let requested = self.budget.collect.replace(false);
        let sweep = self.budget.sweep.replace(false);
        if requested || sweep || self.total_memory() > self.collect_at {
            // Near the memory budget, or past it: free all garbage before Lua
            // runs again, so that the budget measures what is live. Still past
            // it, the code that went past it fails (`luaM_malloc_`'s retry).
            self.gc_collect();
            let live = self.total_memory();
            self.budget.live.set(live);
            self.collect_at = self.next_collection(live);
            if requested {
                self.budget.failed.set(live > self.budget.limit.get());
            }
        } else if self.arena.metrics().allocation_debt() > COLLECTOR_GRANULARITY {
            if self.arena.collection_phase() == CollectionPhase::Collecting {
                self.arena.collect_debt();
            } else {
                if let Some(marked) = self.arena.mark_debt() {
                    marked.finalize(|fc, root| {
                        root.finalizers.prepare(fc);
                    });
                    self.arena.mark_all().unwrap().finalize(|fc, root| {
                        root.finalizers.finalize(fc);
                    });
                    // Immediately transition to `CollectionPhase::Collecting`.
                    self.arena.mark_all().unwrap().start_collecting();
                }
            }
        }
        r
    }

    /// A version of `Lua::enter` that expects failure and automatically converts [`Error`] into
    /// [`ExternError`], allowing the error type to escape the arena.
    pub fn try_enter<F, R>(&mut self, f: F) -> Result<R, ExternError>
    where
        F: for<'gc> FnOnce(Context<'gc>) -> Result<R, Error<'gc>>,
    {
        self.enter(move |ctx| f(ctx).map_err(Error::into_extern))
    }

    /// Run the given executor to completion.
    ///
    /// This will periodically exit the arena in order to collect garbage concurrently with running
    /// Lua code.
    pub fn finish(&mut self, executor: &StashedExecutor) -> Result<(), BadThreadMode> {
        const FUEL_PER_GC: i32 = 4096;

        loop {
            let mut fuel = Fuel::with(FUEL_PER_GC);

            if self.enter(|ctx| ctx.fetch(executor).step(ctx, &mut fuel))? {
                break;
            }
        }

        Ok(())
    }

    /// Run the given executor to completion and then take return values from the returning thread.
    ///
    /// This is equivalent to calling `Lua::finish` on an executor and then calling
    /// `Executor::take_result` yourself.
    pub fn execute<R: for<'gc> FromMultiValue<'gc>>(
        &mut self,
        executor: &StashedExecutor,
    ) -> Result<R, ExternError> {
        self.finish(executor).map_err(RuntimeError::new)?;
        self.try_enter(|ctx| ctx.fetch(executor).take_result::<R>(ctx)?)
    }
}

#[derive(Collect)]
#[collect(no_drop)]
struct State<'gc> {
    globals: Table<'gc>,
    registry: Registry<'gc>,
    strings: InternedStringSet<'gc>,
    finalizers: Finalizers<'gc>,
    #[collect(require_static)]
    budget: Rc<Budget>,
    not_enough_memory: String<'gc>,
    error_in_error_handling: String<'gc>,
    empty: String<'gc>,
}

impl<'gc> State<'gc> {
    fn new(mc: &Mutation<'gc>) -> State<'gc> {
        let strings = InternedStringSet::new(mc);
        Self {
            globals: Table::new(mc),
            registry: Registry::new(mc),
            strings,
            finalizers: Finalizers::new(mc),
            budget: Rc::new(Budget::new(mc.metrics().clone())),
            not_enough_memory: strings
                .intern_static(mc, crate::limits::NOT_ENOUGH_MEMORY.as_bytes()),
            error_in_error_handling: strings
                .intern_static(mc, crate::limits::ERROR_IN_ERROR_HANDLING.as_bytes()),
            empty: strings.intern_static(mc, b""),
        }
    }

    fn ctx(&'gc self, mutation: &'gc Mutation<'gc>) -> Context<'gc> {
        Context {
            mutation,
            state: self,
        }
    }
}
