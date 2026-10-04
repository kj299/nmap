use std::hash::{Hash, Hasher};

use allocator_api2::vec;
use gc_arena::{allocator_api::MetricsAlloc, lock::RefLock, Collect, Gc, Mutation};
use thiserror::Error;

use crate::{
    compiler::{FunctionRef, LineNumber},
    limits::{CallLimit, LUAI_MAXCCALLS},
    thread::BadThreadMode,
    CallbackReturn, Context, Error, FromMultiValue, Fuel, Function, IntoMultiValue, SequencePoll,
    Stack, String, Thread, ThreadMode, Variadic,
};

use super::{
    thread::{Frame, LuaFrame, ThreadState},
    vm::run_vm,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutorMode {
    /// There are no threads being run and the `Executor` must be restarted to do any work.
    Stopped,
    /// Lua has errored or returned (or yielded) values that must be taken to move the `Executor` to
    /// the `Stopped` (or `Suspended`) state.
    Result,
    /// There is an active thread in the `ThreadMode::Normal` state and it is can be run with
    /// `Executor::step`.
    Normal,
    /// The main thread has yielded and is waiting on being resumed.
    Suspended,
    /// The `Executor` is currently inside its own `Executor::step` function.
    Running,
}

#[derive(Debug, Copy, Clone, Error)]
#[error("bad executor mode: {found:?}, expected {expected:?}")]
pub struct BadExecutorMode {
    pub found: ExecutorMode,
    pub expected: ExecutorMode,
}

#[derive(Debug, Collect)]
#[collect(no_drop)]
pub struct ExecutorState<'gc> {
    thread_stack: vec::Vec<Thread<'gc>, MetricsAlloc<'gc>>,
}

pub type ExecutorInner<'gc> = RefLock<ExecutorState<'gc>>;

/// The entry-point for the Lua VM.
///
/// An `Executor` runs networks of [`Thread`]s that may depend on each other and may yield
/// control back and forth. All Lua code that is run is done so directly or indirectly by calling
/// [`Executor::step`].
///
/// # Panics
///
/// `Executor` is dangerous to use from within any kind of Lua callback. It it not meant to be used
/// reentrantly, and calling `Executor` methods from within a callback which it itself is running
/// (other than `Executor::mode`) will panic. Additionally, even if an independent `Executor` is
/// used, cross-thread upvalues can still panic when an inner `Executor` tries to change an upvalue
/// in a `Thread` that an outer `Executor` has mutably borrowed.
///
/// `Executor`s are not meant to be used from callbacks at all, and `Executor`s should not be
/// nested. Instead, use the normal mechanisms for callbacks to call Lua code so that everything is
/// run by the same `Executor` which called the callback.
#[derive(Debug, Copy, Clone, Collect)]
#[collect(no_drop)]
pub struct Executor<'gc>(Gc<'gc, ExecutorInner<'gc>>);

impl<'gc> PartialEq for Executor<'gc> {
    fn eq(&self, other: &Executor<'gc>) -> bool {
        Gc::ptr_eq(self.0, other.0)
    }
}

impl<'gc> Eq for Executor<'gc> {}

impl<'gc> Hash for Executor<'gc> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Gc::as_ptr(self.0).hash(state)
    }
}

impl<'gc> Executor<'gc> {
    const VM_GRANULARITY: u32 = 64;

    const FUEL_PER_CALLBACK: i32 = 8;
    const FUEL_PER_SEQ_STEP: i32 = 4;
    const FUEL_PER_STEP: i32 = 4;

    /// Creates a new `Executor` with a stopped main thread.
    pub fn new(ctx: Context<'gc>) -> Self {
        Self::run(&ctx, Thread::new(ctx)).unwrap()
    }

    /// Creates a new `Executor` that begins running the given [`Thread`].
    ///
    /// If the provided thread is in [`ThreadMode::Waiting`] or [`ThreadMode::Running`], then this
    /// will return `Err(BadThreadMode)`.
    pub fn run(mc: &Mutation<'gc>, thread: Thread<'gc>) -> Result<Self, BadThreadMode> {
        let executor = Executor(Gc::new(
            mc,
            RefLock::new(ExecutorState {
                thread_stack: vec::Vec::new_in(MetricsAlloc::new(mc)),
            }),
        ));
        executor.reset(mc, thread)?;
        Ok(executor)
    }

    pub fn from_inner(inner: Gc<'gc, ExecutorInner<'gc>>) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> Gc<'gc, ExecutorInner<'gc>> {
        self.0
    }

    /// Creates a new `Executor` with a new [`Thread`] running the given function.
    pub fn start(
        ctx: Context<'gc>,
        function: Function<'gc>,
        args: impl IntoMultiValue<'gc>,
    ) -> Self {
        let thread = Thread::new(ctx);
        thread.start(ctx, function, args).unwrap();
        Self::run(&ctx, thread).unwrap()
    }

    pub fn mode(self) -> ExecutorMode {
        if let Ok(state) = self.0.try_borrow() {
            if state.thread_stack.len() > 1 {
                ExecutorMode::Normal
            } else {
                match state.thread_stack[0].mode() {
                    ThreadMode::Stopped => ExecutorMode::Stopped,
                    ThreadMode::Result => ExecutorMode::Result,
                    ThreadMode::Normal => ExecutorMode::Normal,
                    ThreadMode::Suspended => ExecutorMode::Suspended,
                    ThreadMode::Waiting => {
                        // This should never happen from correct `Executor` / `Thread` use. In
                        // order for the main thread to be in the `Waiting` state with no thread
                        // being waited on, that thread must have been used by two `Executor`s at
                        // one time, and the *other* `Executor` must have moved it to the `Waiting`
                        // state.
                        //
                        // We call this `ExecutorMode::Normal` since the main thread is still not in
                        // some completed state, but calling `Executor::step` will never exit this
                        // mode (only forever return a `BadThreadMode` error).
                        ExecutorMode::Normal
                    }
                    ThreadMode::Running => ExecutorMode::Running,
                }
            }
        } else {
            ExecutorMode::Running
        }
    }

    /// Runs the VM for a period of time controlled by the `fuel` parameter.
    ///
    /// The VM and callbacks will consume fuel as they run, and `Executor::step` will return as soon
    /// as `Fuel::can_continue()` returns false *and some minimal positive progress has been made*.
    ///
    /// Returns `false` if the method has exhausted its fuel, but there is more work to
    /// do, and returns `true` if no more progress can be made. If `true` is returned, then
    /// `Executor::mode()` will no longer be `ExecutorMode::Normal`.
    ///
    /// # Errors
    ///
    /// If a `Thread` being run by this `Executor` in an unexpected state, then this method will
    /// return a `BadThreadMode` error.
    ///
    /// If a `Thread` is currently in the stack of threads being run by an `Executor`, then that
    /// `Executor` expects to be the sole instance driving those threads to completion and expects
    /// that the state of these threads will not be externally changed. This rule cannot be violated
    /// from Lua or by normal `Rust` callbacks, only by purposefully misusing an `Executor` from
    /// Rust by, for example, setting a single `Thread` as the main thread of two `Executor`s
    /// at once or by manually calling [`Thread::take_result`] or [`Thread::reset`] on a thread
    /// currently being run by an `Executor`.
    ///
    /// This is considered "outside" of a normal Lua or Rust callback error since it cannot be
    /// triggered solely by Lua and likely indicates a bug in some Rust code, so this error is
    /// delivered through a separate channel than normal results and cannot be caught by Lua.
    pub fn step(self, ctx: Context<'gc>, fuel: &mut Fuel) -> Result<bool, BadThreadMode> {
        let mut state = self.0.borrow_mut(&ctx);
        ctx.clear_memory_refusal();
        if ctx.take_memory_failure() {
            // The code that ended the last step by growing the heap past the
            // budget fails, now that a collection has not brought it back.
            let thread = state.thread_stack.last().copied().unwrap();
            if let Ok(mut thread_state) = thread.into_inner().try_borrow_mut(&ctx) {
                if raise_memory_error(ctx, &mut thread_state) {
                    ctx.begin_memory_unwind();
                }
            }
        }
        Ok(loop {
            // Set when this pass raises "not enough memory": the step then
            // ends, so that `Lua::enter` collects before Lua runs again.
            let mut out_of_memory = false;
            let mut top_thread = state.thread_stack.last().copied().unwrap();
            let mut res_thread = None;
            match top_thread.mode() {
                ThreadMode::Normal => {}
                ThreadMode::Running => {
                    panic!("`Executor` thread already running")
                }
                ThreadMode::Stopped | ThreadMode::Suspended | ThreadMode::Result
                    if state.thread_stack.len() == 1 =>
                {
                    break true;
                }
                ThreadMode::Result => {
                    state.thread_stack.pop();
                    res_thread = Some(top_thread);
                    top_thread = state.thread_stack.last().copied().unwrap();
                }
                mode => {
                    return Err(BadThreadMode {
                        found: mode,
                        expected: None,
                    })
                }
            }

            let mut top_state = top_thread.into_inner().borrow_mut(&ctx);
            let top_state = &mut *top_state;
            if let Some(res_thread) = res_thread {
                let mode = top_state.mode();
                if mode != ThreadMode::Waiting {
                    // Shenanigans have happened and the top thread has had its state externally
                    // changed.
                    return Err(BadThreadMode {
                        found: mode,
                        expected: Some(ThreadMode::Waiting),
                    });
                }

                assert!(matches!(top_state.frames.pop(), Some(Frame::WaitThread)));
                assert_eq!(res_thread.mode(), ThreadMode::Result);
                // Take the results from the res_thread and return them to our top
                // thread.
                let mut res_state = res_thread.into_inner().borrow_mut(&ctx);
                match res_state.take_result() {
                    Ok(vals) => {
                        let bottom = top_state.stack.len();
                        top_state.stack.extend(vals);
                        top_state.return_to(bottom);
                    }
                    Err(err) => {
                        let ccalls = top_state.ccalls();
                        top_state.raise(err, ccalls);
                    }
                }
                drop(res_state);
            }

            if top_state.mode() == ThreadMode::Normal {
                fn do_yield<'gc>(
                    ctx: Context<'gc>,
                    thread_stack: &mut vec::Vec<Thread<'gc>, MetricsAlloc<'gc>>,
                    top_state: &mut ThreadState<'gc>,
                    to_thread: Option<Thread<'gc>>,
                    bottom: usize,
                ) {
                    if let Some(to_thread) = to_thread {
                        if let Err(err) =
                            to_thread.resume(ctx, Variadic(top_state.stack.drain(bottom..)))
                        {
                            let ccalls = top_state.ccalls();
                            top_state.raise(err.into(), ccalls);
                        } else {
                            top_state.frames.push(Frame::Yielded);
                            thread_stack.pop();
                            thread_stack.push(to_thread);
                        }
                    } else {
                        top_state.frames.push(Frame::Yielded);
                        top_state.frames.push(Frame::Result { bottom });
                    }
                }

                fn do_resume<'gc>(
                    ctx: Context<'gc>,
                    thread_stack: &mut vec::Vec<Thread<'gc>, MetricsAlloc<'gc>>,
                    top_state: &mut ThreadState<'gc>,
                    thread: Thread<'gc>,
                    bottom: usize,
                ) {
                    // `lua_resume`: the coroutine runs one C level above its
                    // resumer, which must be below the limit.
                    let from = top_state.ccalls();
                    if from >= LUAI_MAXCCALLS {
                        let ccalls = top_state.top_ccalls();
                        raise_limit(ctx, top_state, bottom, CallLimit::CStack, ccalls);
                        return;
                    }
                    // A thread that cannot be borrowed is running, and
                    // `resume` below reports that.
                    let _ = thread.set_ccalls(&ctx, from + 1);
                    if let Err(err) = thread.resume(ctx, Variadic(top_state.stack.drain(bottom..)))
                    {
                        top_state.raise(err.into(), from);
                    } else {
                        // Tail call the thread resume if we can.
                        if top_state.frames.is_empty() {
                            thread_stack.pop();
                        } else {
                            top_state.frames.push(Frame::WaitThread);
                        }
                        thread_stack.push(thread);
                    }
                }

                /// A call that would cross a limit, raised from the Rust
                /// function making it: as from a C function, with no
                /// position.
                fn raise_limit<'gc>(
                    ctx: Context<'gc>,
                    top_state: &mut ThreadState<'gc>,
                    bottom: usize,
                    limit: CallLimit,
                    ccalls: u32,
                ) {
                    top_state.stack.truncate(bottom);
                    let error = match limit {
                        CallLimit::ErrorHandling => ctx.error_in_error_handling(),
                        _ => crate::Value::String(ctx.intern(limit.message().as_bytes())).into(),
                    };
                    raise_limit_error(top_state, error, ccalls);
                }

                /// As `raise_limit`, for a call a Rust callback made in its
                /// place (`CallbackReturn::Call` with no `then`): a stand-in for
                /// the VM's own work, `__call`'s `tryfuncTM` say, which raises
                /// from the Lua function it returns to, with its position.
                fn raise_limit_in_caller<'gc>(
                    ctx: Context<'gc>,
                    top_state: &mut ThreadState<'gc>,
                    bottom: usize,
                    limit: CallLimit,
                    ccalls: u32,
                ) {
                    let Some(&Frame::Lua { closure, pc, .. }) = top_state.frames.last() else {
                        return raise_limit(ctx, top_state, bottom, limit, ccalls);
                    };
                    if limit == CallLimit::ErrorHandling {
                        return raise_limit(ctx, top_state, bottom, limit, ccalls);
                    }
                    top_state.stack.truncate(bottom);
                    let mut msg = lua_where(closure, pc.saturating_sub(1));
                    msg.extend_from_slice(limit.message().as_bytes());
                    let error = crate::Value::String(ctx.intern(&msg)).into();
                    raise_limit_error(top_state, error, ccalls);
                }

                fn raise_limit_error<'gc>(
                    top_state: &mut ThreadState<'gc>,
                    error: Error<'gc>,
                    ccalls: u32,
                ) {
                    // PUC-Lua counted the call before refusing it.
                    let ccalls = top_state.effective_ccalls(ccalls);
                    top_state.raise(error, ccalls);
                }

                match top_state.frames.pop() {
                    Some(Frame::Callback {
                        bottom,
                        callback,
                        ccalls,
                    }) => {
                        fuel.consume(Self::FUEL_PER_CALLBACK);
                        let mark = ctx.memory_mark();
                        let running = top_state.effective_ccalls(ccalls);
                        let ret = callback.call(
                            ctx,
                            Execution {
                                executor: self,
                                fuel,
                                threads: &state.thread_stack,
                                upper_frames: &top_state.frames,
                                ccalls: running,
                                error_ccalls: top_state.error_ccalls,
                            },
                            Stack::new(&mut top_state.stack, bottom),
                        );
                        // Whatever the callback made of a refused allocation
                        // is discarded; it fails, as `luaM_` would have.
                        out_of_memory = ctx.memory_check(mark);
                        let ret = if out_of_memory {
                            Err(ctx.not_enough_memory())
                        } else {
                            ret
                        };
                        match ret {
                            Ok(CallbackReturn::Return) => {
                                top_state.return_to(bottom);
                            }
                            Ok(CallbackReturn::Sequence(sequence)) => {
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: None,
                                    ccalls,
                                });
                            }
                            Ok(CallbackReturn::Call { function, then }) => {
                                // A callback that goes on afterwards calls with
                                // `lua_call`, which takes a C level. One that
                                // does not is a tail call (`__call`, `bind`), and
                                // keeps its own, as a Lua tail call does.
                                let tail = then.is_none();
                                let ccalls = match then {
                                    Some(sequence) => {
                                        top_state.frames.push(Frame::Sequence {
                                            bottom,
                                            sequence,
                                            pending_error: None,
                                            ccalls,
                                        });
                                        ccalls.saturating_add(1)
                                    }
                                    None => ccalls,
                                };
                                if let Err(limit) = top_state.push_call(bottom, function, ccalls) {
                                    if tail {
                                        raise_limit_in_caller(
                                            ctx, top_state, bottom, limit, ccalls,
                                        );
                                    } else {
                                        raise_limit(ctx, top_state, bottom, limit, ccalls);
                                    }
                                }
                            }
                            Ok(CallbackReturn::Yield { to_thread, then }) => {
                                if let Some(sequence) = then {
                                    top_state.frames.push(Frame::Sequence {
                                        bottom,
                                        sequence,
                                        pending_error: None,
                                        ccalls,
                                    });
                                }
                                do_yield(
                                    ctx,
                                    &mut state.thread_stack,
                                    top_state,
                                    to_thread,
                                    bottom,
                                );
                            }
                            Ok(CallbackReturn::Resume { thread, then }) => {
                                if let Some(sequence) = then {
                                    top_state.frames.push(Frame::Sequence {
                                        bottom,
                                        sequence,
                                        pending_error: None,
                                        ccalls,
                                    });
                                }
                                do_resume(ctx, &mut state.thread_stack, top_state, thread, bottom);
                            }
                            Err(err) => {
                                top_state.stack.truncate(bottom);
                                top_state.raise(err, running);
                            }
                        }
                    }
                    Some(Frame::Sequence {
                        bottom,
                        mut sequence,
                        pending_error,
                        ccalls,
                    }) => {
                        fuel.consume(Self::FUEL_PER_SEQ_STEP);

                        let running = top_state.effective_ccalls(ccalls);
                        let exec = Execution {
                            executor: self,
                            fuel,
                            threads: &state.thread_stack,
                            upper_frames: &top_state.frames,
                            ccalls: running,
                            error_ccalls: top_state.error_ccalls,
                        };
                        let mark = ctx.memory_mark();
                        // An error that `error` passes on keeps the level it
                        // was raised at; one that `poll` returns is raised here.
                        let handling = pending_error.is_some();
                        let poll = if let Some(err) = pending_error {
                            sequence.error(ctx, exec, err, Stack::new(&mut top_state.stack, bottom))
                        } else {
                            sequence.poll(ctx, exec, Stack::new(&mut top_state.stack, bottom))
                        };
                        out_of_memory = ctx.memory_check(mark);
                        let poll = if out_of_memory {
                            Err(ctx.not_enough_memory())
                        } else {
                            poll
                        };

                        match poll {
                            Ok(SequencePoll::Pending) => {
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: None,
                                    ccalls,
                                });
                            }
                            Ok(SequencePoll::Return) => {
                                top_state.return_to(bottom);
                            }
                            Ok(SequencePoll::Call {
                                function,
                                bottom: rel_bottom,
                            }) => {
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: None,
                                    ccalls,
                                });
                                let ccalls = ccalls.saturating_add(1);
                                if let Err(limit) =
                                    top_state.push_call(bottom + rel_bottom, function, ccalls)
                                {
                                    raise_limit(ctx, top_state, bottom + rel_bottom, limit, ccalls);
                                }
                            }
                            Ok(SequencePoll::CallAt {
                                function,
                                bottom: rel_bottom,
                                ccalls: absolute,
                            }) => {
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: None,
                                    ccalls,
                                });
                                let ccalls = top_state.relative_ccalls(absolute);
                                if let Err(limit) =
                                    top_state.push_call(bottom + rel_bottom, function, ccalls)
                                {
                                    raise_limit(ctx, top_state, bottom + rel_bottom, limit, ccalls);
                                }
                            }
                            Ok(SequencePoll::TailCall(function)) => {
                                if let Err(limit) = top_state.push_call(bottom, function, ccalls) {
                                    raise_limit(ctx, top_state, bottom, limit, ccalls);
                                }
                            }
                            Ok(SequencePoll::Yield {
                                to_thread,
                                bottom: rel_bottom,
                            }) => {
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: None,
                                    ccalls,
                                });
                                do_yield(
                                    ctx,
                                    &mut state.thread_stack,
                                    top_state,
                                    to_thread,
                                    bottom + rel_bottom,
                                );
                            }
                            Ok(SequencePoll::TailYield(to_thread)) => {
                                do_yield(
                                    ctx,
                                    &mut state.thread_stack,
                                    top_state,
                                    to_thread,
                                    bottom,
                                );
                            }
                            Ok(SequencePoll::Resume {
                                thread,
                                bottom: rel_bottom,
                            }) => {
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: None,
                                    ccalls,
                                });
                                do_resume(
                                    ctx,
                                    &mut state.thread_stack,
                                    top_state,
                                    thread,
                                    bottom + rel_bottom,
                                );
                            }
                            Ok(SequencePoll::TailResume(thread)) => {
                                do_resume(ctx, &mut state.thread_stack, top_state, thread, bottom);
                            }
                            Err(error) => {
                                top_state.stack.truncate(bottom);
                                if handling && !out_of_memory {
                                    top_state.frames.push(Frame::Error(error));
                                } else {
                                    top_state.raise(error, running);
                                }
                            }
                        }
                    }
                    Some(frame @ Frame::Lua { .. }) => {
                        top_state.frames.push(frame);

                        let lua_frame = LuaFrame {
                            state: top_state,
                            thread: top_thread,
                            fuel,
                        };
                        let mark = ctx.memory_mark();
                        let ran = run_vm(ctx, lua_frame, Self::VM_GRANULARITY);
                        // A call or return ends `run_vm` without its own
                        // check; the new top frame fails instead.
                        out_of_memory = matches!(ran, Err(super::VMError::NotEnoughMemory))
                            || (!ctx.collection_requested() && ctx.memory_check(mark));
                        if out_of_memory {
                            if let Ok(instructions_run) = ran {
                                fuel.consume(instructions_run.try_into().unwrap());
                            }
                            raise_memory_error(ctx, top_state);
                        } else {
                            match ran {
                                Err(err) => {
                                    // `luaG_runerror` from a Lua function: the
                                    // message, as a string, after the position of
                                    // the instruction that raised it.
                                    let ccalls = top_state.ccalls();
                                    let err = match top_state.frames.last() {
                                        // `LUA_ERRERR`: the one string handlers
                                        // let past, with no position.
                                        _ if matches!(
                                            err,
                                            super::VMError::ErrorInErrorHandling
                                        ) =>
                                        {
                                            ctx.error_in_error_handling()
                                        }
                                        Some(Frame::Lua { closure, pc, .. })
                                            if err.is_lua_error() =>
                                        {
                                            let mut msg = if err.is_positioned() {
                                                lua_where(*closure, pc.saturating_sub(1))
                                            } else {
                                                std::vec::Vec::new()
                                            };
                                            msg.extend_from_slice(err.to_string().as_bytes());
                                            Error::from(crate::Value::String(ctx.intern(&msg)))
                                        }
                                        _ => err.into(),
                                    };
                                    top_state.raise(err, ccalls);
                                }
                                Ok(instructions_run) => {
                                    fuel.consume(instructions_run.try_into().unwrap());
                                }
                            }
                        }
                    }
                    Some(Frame::Error(err)) => {
                        match top_state
                            .frames
                            .pop()
                            .expect("normal thread must have frame above error")
                        {
                            Frame::Lua { bottom, .. } => {
                                top_state.close_upvalues(&ctx, bottom);
                                top_state.stack.truncate(bottom);
                                top_state.frames.push(Frame::Error(err));
                            }
                            Frame::Sequence {
                                bottom,
                                sequence,
                                pending_error,
                                ccalls,
                            } => {
                                assert!(pending_error.is_none());
                                top_state.frames.push(Frame::Sequence {
                                    bottom,
                                    sequence,
                                    pending_error: Some(err),
                                    ccalls,
                                });
                                // A "not enough memory" error has reached its
                                // handler, and the frames it unwound are gone:
                                // collect them before the handler runs.
                                if ctx.end_memory_unwind() {
                                    break false;
                                }
                            }
                            frame => panic!("tried to wind through improper frame {frame:?}"),
                        }
                    }
                    _ => panic!("tried to step invalid frame type"),
                }
            }

            fuel.consume(Self::FUEL_PER_STEP);

            if out_of_memory {
                ctx.begin_memory_unwind();
                break false;
            }
            if ctx.collection_requested() {
                break false;
            }

            if !fuel.should_continue() {
                break false;
            }
        })
    }

    pub fn take_result<T: FromMultiValue<'gc>>(
        self,
        ctx: Context<'gc>,
    ) -> Result<Result<T, Error<'gc>>, BadExecutorMode> {
        let mode = self.mode();
        if mode == ExecutorMode::Result {
            let state = self.0.borrow();
            Ok(state.thread_stack[0].take_result(ctx).unwrap())
        } else {
            Err(BadExecutorMode {
                found: mode,
                expected: ExecutorMode::Result,
            })
        }
    }

    pub fn resume(
        self,
        ctx: Context<'gc>,
        args: impl IntoMultiValue<'gc>,
    ) -> Result<(), BadExecutorMode> {
        let mode = self.mode();
        if mode == ExecutorMode::Suspended {
            let state = self.0.borrow();
            state.thread_stack[0].resume(ctx, args).unwrap();
            Ok(())
        } else {
            Err(BadExecutorMode {
                found: mode,
                expected: ExecutorMode::Suspended,
            })
        }
    }

    pub fn resume_err(self, mc: &Mutation<'gc>, error: Error<'gc>) -> Result<(), BadExecutorMode> {
        let mode = self.mode();
        if mode == ExecutorMode::Suspended {
            let state = self.0.borrow();
            state.thread_stack[0].resume_err(mc, error).unwrap();
            Ok(())
        } else {
            Err(BadExecutorMode {
                found: mode,
                expected: ExecutorMode::Suspended,
            })
        }
    }

    /// Reset this `Executor` entirely, leaving it with a stopped main thread. Equivalent to
    /// creating a new executor with `Executor::new`.
    pub fn stop(self, mc: &Mutation<'gc>) {
        let mut state = self.0.borrow_mut(mc);
        state.thread_stack.truncate(1);
        state.thread_stack[0].reset(mc).unwrap();
    }

    /// Reset this `Executor` entirely and begins running the given thread.
    ///
    /// This is equivalent to creating a new executor with `Executor::run`.
    pub fn reset(self, mc: &Mutation<'gc>, thread: Thread<'gc>) -> Result<(), BadThreadMode> {
        let thread_mode = thread.mode();
        if matches!(thread_mode, ThreadMode::Waiting | ThreadMode::Running) {
            return Err(BadThreadMode {
                found: thread_mode,
                expected: Some(ThreadMode::Normal),
            });
        }
        let mut state = self.0.borrow_mut(mc);
        state.thread_stack.clear();
        state.thread_stack.push(thread);
        Ok(())
    }

    /// Reset this `Executor` entirely and begins running the given function, equivalent to
    /// creating a new executor with `Executor::start`.
    pub fn restart(
        self,
        ctx: Context<'gc>,
        function: Function<'gc>,
        args: impl IntoMultiValue<'gc>,
    ) {
        let mut state = self.0.borrow_mut(&ctx);
        state.thread_stack.truncate(1);
        state.thread_stack[0].reset(&ctx).unwrap();
        state.thread_stack[0].start(ctx, function, args).unwrap();
    }
}

/// Execution state passed to callbacks when they are run by an `Executor`.
pub struct Execution<'gc, 'a> {
    executor: Executor<'gc>,
    fuel: &'a mut Fuel,
    threads: &'a [Thread<'gc>],
    upper_frames: &'a [Frame<'gc>],
    ccalls: u32,
    error_ccalls: u32,
}

impl<'gc, 'a> Execution<'gc, 'a> {
    pub fn reborrow(&mut self) -> Execution<'gc, '_> {
        Execution {
            executor: self.executor,
            fuel: self.fuel,
            threads: self.threads,
            upper_frames: self.upper_frames,
            ccalls: self.ccalls,
            error_ccalls: self.error_ccalls,
        }
    }

    /// The C calls (PUC-Lua's `nCcalls`) the running callback runs under.
    pub fn ccalls(&self) -> u32 {
        self.ccalls
    }

    /// The C calls the error last raised in this thread was raised under:
    /// in `Sequence::error`, the error being handled. A message handler runs
    /// one level above it ([`SequencePoll::CallAt`](crate::SequencePoll)).
    pub fn error_ccalls(&self) -> u32 {
        self.error_ccalls
    }

    /// The fuel parameter passed to `Executor::step`.
    pub fn fuel(&mut self) -> &mut Fuel {
        self.fuel
    }

    /// The curently executing Thread.
    pub fn current_thread(&self) -> CurrentThread<'gc> {
        CurrentThread {
            thread: *self.threads.last().unwrap(),
            is_main: self.threads.len() == 1,
        }
    }

    /// The curently running Executor.
    ///
    /// Do not call methods on this from callbacks! This is provided only for identification
    /// purposes, so that callbacks can identify which executor that is currently executing them, or
    /// to store the pointer somewhere.
    pub fn executor(&self) -> Executor<'gc> {
        self.executor
    }

    /// `luaL_where(L, level)`: `chunk:line: ` for the function `level` calls
    /// up from the running callback — 1 is its caller — when that function is
    /// Lua, and nothing when it is a Rust function or there is no such level.
    pub fn where_at(&self, level: usize) -> std::vec::Vec<u8> {
        let mut seen = 0;
        for frame in self.upper_frames.iter().rev() {
            match frame {
                Frame::Lua { closure, pc, .. } => {
                    seen += 1;
                    if seen == level {
                        return lua_where(*closure, pc.saturating_sub(1));
                    }
                }
                Frame::Sequence { .. } | Frame::Callback { .. } => {
                    seen += 1;
                    if seen == level {
                        return std::vec::Vec::new();
                    }
                }
                _ => {}
            }
        }
        std::vec::Vec::new()
    }

    /// If the function we are returning to is Lua, returns information about the Lua frame we are
    /// returning to.
    pub fn upper_lua_frame(&self) -> Option<UpperLuaFrame<'gc>> {
        let Some(Frame::Lua { closure, pc, .. }) = self.upper_frames.last() else {
            return None;
        };

        let proto = closure.prototype();
        // The previously executed instruction for a callback should be the Call opcode.
        let call_opcode = *pc - 1;

        Some(UpperLuaFrame {
            chunk_name: proto.chunk_name,
            current_function: proto.reference,
            current_line: match proto
                .opcode_line_numbers
                .binary_search_by_key(&call_opcode, |(opi, _)| *opi)
            {
                Ok(i) => proto.opcode_line_numbers[i].1,
                Err(i) => proto.opcode_line_numbers[i - 1].1,
            },
        })
    }
}

/// Raise "not enough memory" in the code at the top of `state`, which has
/// just run: from a Lua frame, from the frame a call or return of it left on
/// top. Returns whether there was code to raise it in.
fn raise_memory_error<'gc>(ctx: Context<'gc>, state: &mut ThreadState<'gc>) -> bool {
    match state.frames.last() {
        Some(Frame::Lua { .. } | Frame::Sequence { .. }) => {}
        // The thread's last frame had returned: it ends with the error
        // instead.
        Some(Frame::Result { .. }) if state.frames.len() == 1 => {
            state.frames.pop();
            state.stack.clear();
        }
        // A call was queued: it is not made.
        Some(&Frame::Callback { bottom, .. }) => {
            state.frames.pop();
            state.stack.truncate(bottom);
        }
        // Anything else has stopped running Lua code, or has an error on its
        // way already.
        _ => return false,
    }
    let ccalls = state.ccalls();
    state.raise(ctx.not_enough_memory(), ccalls);
    true
}

/// `luaG_addinfo`'s prefix, `chunk:line: `, for instruction `op` of `closure`.
fn lua_where(closure: crate::Closure<'_>, op: usize) -> std::vec::Vec<u8> {
    let proto = closure.prototype();
    let line = match proto
        .opcode_line_numbers
        .binary_search_by_key(&op, |(opi, _)| *opi)
    {
        Ok(i) => proto.opcode_line_numbers[i].1,
        Err(0) => LineNumber(0),
        Err(i) => proto.opcode_line_numbers[i - 1].1,
    };
    let mut out = crate::chunk_id::chunk_id(proto.chunk_name.as_bytes());
    out.extend_from_slice(format!(":{line}: ").as_bytes());
    out
}

pub struct CurrentThread<'gc> {
    pub thread: Thread<'gc>,
    pub is_main: bool,
}

pub struct UpperLuaFrame<'gc> {
    pub chunk_name: String<'gc>,
    pub current_function: FunctionRef<String<'gc>>,
    pub current_line: LineNumber,
}
