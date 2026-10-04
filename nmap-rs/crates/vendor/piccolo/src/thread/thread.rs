use std::{
    cell::RefMut,
    hash::{Hash, Hasher},
};

use allocator_api2::vec;
use gc_arena::{
    allocator_api::MetricsAlloc, lock::RefLock, Collect, Finalization, Gc, GcWeak, Mutation,
};
use thiserror::Error;

use crate::{
    closure::{UpValue, UpValueState},
    fuel::count_fuel,
    limits::{CallLimit, LUAI_MAXCCALLS, LUAI_MAXCCALLS_ERR, LUAI_MAXSTACK},
    meta_ops,
    types::{RegisterIndex, VarCount},
    BoxSequence, Callback, Closure, Context, Error, FromMultiValue, Fuel, Function, IntoMultiValue,
    String, Table, UserData, Value,
};

use super::VMError;

/// The current state of a [`Thread`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreadMode {
    /// No frames are on the thread and there are no available results, the thread can be started.
    Stopped,
    /// The thread has an error or has returned (or yielded) values that must be taken to move the
    /// thread back to the `Stopped` (or `Suspended`) state.
    Result,
    /// Thread has an active Lua, Callback, or Sequence frame.
    Normal,
    /// Thread has yielded and is waiting on being resumed.
    Suspended,
    /// The thread is waiting on another thread to finish.
    Waiting,
    /// A callback or sequence that this thread owns is currently being run.
    Running,
}

#[derive(Debug, Copy, Clone, Error)]
#[error("bad thread mode: {found:?}{}", if let Some(expected) = *.expected {
        format!(", expected {:?}", expected)
    } else {
        format!("")
    })]
pub struct BadThreadMode {
    pub found: ThreadMode,
    pub expected: Option<ThreadMode>,
}

pub type ThreadInner<'gc> = RefLock<ThreadState<'gc>>;

/// A Lua coroutine.
///
/// All running Lua or callback code is run as part of a larger `Thread`. `Thread`s may create other
/// `Thread`s, suspend them, resume them, and may yield to calling `Thread`s.
#[derive(Debug, Clone, Copy, Collect)]
#[collect(no_drop)]
pub struct Thread<'gc>(Gc<'gc, RefLock<ThreadState<'gc>>>);

impl<'gc> PartialEq for Thread<'gc> {
    fn eq(&self, other: &Thread<'gc>) -> bool {
        Gc::ptr_eq(self.0, other.0)
    }
}

impl<'gc> Eq for Thread<'gc> {}

impl<'gc> Hash for Thread<'gc> {
    fn hash<H: Hasher>(&self, state: &mut H) {
        Gc::as_ptr(self.0).hash(state)
    }
}

impl<'gc> Thread<'gc> {
    pub fn new(ctx: Context<'gc>) -> Thread<'gc> {
        let p = Gc::new(
            &ctx,
            RefLock::new(ThreadState {
                frames: vec::Vec::new_in(MetricsAlloc::new(&ctx)),
                stack: vec::Vec::new_in(MetricsAlloc::new(&ctx)),
                open_upvalues: vec::Vec::new_in(MetricsAlloc::new(&ctx)),
                ccalls_base: 0,
                error_ccalls: 0,
            }),
        );
        ctx.finalizers().register_thread(&ctx, p);
        Thread(p)
    }

    pub fn from_inner(inner: Gc<'gc, ThreadInner<'gc>>) -> Self {
        Self(inner)
    }

    pub fn into_inner(self) -> Gc<'gc, ThreadInner<'gc>> {
        self.0
    }

    pub fn mode(self) -> ThreadMode {
        match self.0.try_borrow() {
            Ok(state) => state.mode(),
            Err(_) => ThreadMode::Running,
        }
    }

    /// If this thread is `Stopped`, start a new function with the given arguments.
    pub fn start(
        self,
        ctx: Context<'gc>,
        function: Function<'gc>,
        args: impl IntoMultiValue<'gc>,
    ) -> Result<(), BadThreadMode> {
        let mut state = self.check_mode(&ctx, ThreadMode::Stopped)?;
        assert!(state.stack.is_empty());
        state.stack.extend(args.into_multi_value(ctx));
        if let Err(limit) = state.push_call(0, function, 0) {
            state.raise_at_start(ctx, limit);
        }
        Ok(())
    }

    /// Set how many C calls (`LUAI_MAXCCALLS`) the code at the top of this
    /// thread runs under — PUC-Lua's `nCcalls` — from which calls it makes
    /// count up. An `Executor` sets it to one more than the resumer's for
    /// each coroutine it resumes, as `lua_resume` does, whatever depth the
    /// coroutine yielded at; an embedder sets it for a main thread it runs
    /// from inside nested calls of its own.
    pub fn set_ccalls(self, mc: &Mutation<'gc>, ccalls: u32) -> Result<(), BadThreadMode> {
        match self.0.try_borrow_mut(mc) {
            Ok(mut state) => {
                state.set_ccalls(ccalls);
                Ok(())
            }
            Err(_) => Err(BadThreadMode {
                found: ThreadMode::Running,
                expected: None,
            }),
        }
    }

    /// If this thread is `Stopped`, start a new suspended function.
    pub fn start_suspended(
        self,
        mc: &Mutation<'gc>,
        function: Function<'gc>,
    ) -> Result<(), BadThreadMode> {
        let mut state = self.check_mode(mc, ThreadMode::Stopped)?;
        state.frames.push(Frame::Start(function));
        Ok(())
    }

    /// If the thread is in the `Result` mode, take the returned (or yielded) values. Moves the
    /// thread back to the `Stopped` (or `Suspended`) mode.
    pub fn take_result<T: FromMultiValue<'gc>>(
        self,
        ctx: Context<'gc>,
    ) -> Result<Result<T, Error<'gc>>, BadThreadMode> {
        let mut state = self.check_mode(&ctx, ThreadMode::Result)?;
        Ok(state
            .take_result()
            .and_then(|vals| Ok(T::from_multi_value(ctx, vals)?)))
    }

    /// If the thread is in `Suspended` mode, resume it.
    pub fn resume(
        self,
        ctx: Context<'gc>,
        args: impl IntoMultiValue<'gc>,
    ) -> Result<(), BadThreadMode> {
        let mut state = self.check_mode(&ctx, ThreadMode::Suspended)?;

        let bottom = state.stack.len();
        state.stack.extend(args.into_multi_value(ctx));

        match state.frames.pop().expect("no frame to resume") {
            Frame::Start(function) => {
                assert!(bottom == 0 && state.open_upvalues.is_empty() && state.frames.is_empty());
                // `resume` starts the body with `ccall(L, ..., 0)`: no level
                // taken, but the limit checked.
                if let Err(limit) = state.push_call(0, function, 0) {
                    state.raise_at_start(ctx, limit);
                }
            }
            Frame::Yielded => {
                state.return_to(bottom);
            }
            _ => panic!("top frame not a suspended thread"),
        }
        Ok(())
    }

    /// If the thread is in `Suspended` mode, cause an error wherever the thread was suspended.
    pub fn resume_err(self, mc: &Mutation<'gc>, error: Error<'gc>) -> Result<(), BadThreadMode> {
        let mut state = self.check_mode(mc, ThreadMode::Suspended)?;
        assert!(matches!(
            state.frames.pop(),
            Some(Frame::Start(_) | Frame::Yielded)
        ));
        state.frames.push(Frame::Error(error));
        Ok(())
    }

    /// If this thread is in any other mode than `Running`, reset the thread completely and restore
    /// it to the `Stopped` state.
    pub fn reset(self, mc: &Mutation<'gc>) -> Result<(), BadThreadMode> {
        match self.0.try_borrow_mut(mc) {
            Ok(mut state) => {
                state.reset(mc);
                Ok(())
            }
            Err(_) => Err(BadThreadMode {
                found: ThreadMode::Running,
                expected: None,
            }),
        }
    }

    /// For each open upvalue pointing to this thread, if the upvalue itself is live, then resurrect
    /// the actual value that it is pointing to.
    ///
    /// Because open upvalues keep a *weak* pointer to their parent thread, their target values will
    /// not be properly marked as live until until they are manually marked with this method.
    pub(crate) fn resurrect_live_upvalues(
        self,
        fc: &Finalization<'gc>,
    ) -> Result<(), BadThreadMode> {
        // If this thread is not dead, then none of the held stack values can be dead, so we don't
        // need to resurrect them.
        if Gc::is_dead(fc, self.0) {
            let state = self.0.try_borrow().map_err(|_| BadThreadMode {
                found: ThreadMode::Running,
                expected: None,
            })?;
            state.resurrect_live_upvalues(fc);
        }
        Ok(())
    }

    fn check_mode(
        &self,
        mc: &Mutation<'gc>,
        expected: ThreadMode,
    ) -> Result<RefMut<'_, ThreadState<'gc>>, BadThreadMode> {
        assert!(expected != ThreadMode::Running);
        if let Ok(state) = self.0.try_borrow_mut(mc) {
            let found = state.mode();
            if found == expected {
                Ok(state)
            } else {
                Err(BadThreadMode {
                    found,
                    expected: Some(expected),
                })
            }
        } else {
            Err(BadThreadMode {
                found: ThreadMode::Running,
                expected: Some(expected),
            })
        }
    }
}

#[derive(Debug, Copy, Clone, Collect)]
#[collect(no_drop)]
pub struct OpenUpValue<'gc> {
    thread: GcWeak<'gc, RefLock<ThreadState<'gc>>>,
    stack_index: usize,
}

impl<'gc> OpenUpValue<'gc> {
    const UPGRADE_ERR: &'static str = "thread not finalized: upvalues not closed";

    pub fn get(self, mc: &Mutation<'gc>) -> Value<'gc> {
        self.thread
            .upgrade(mc)
            .expect(Self::UPGRADE_ERR)
            .borrow()
            .stack[self.stack_index]
    }

    pub fn set(self, mc: &Mutation<'gc>, v: Value<'gc>) {
        self.thread
            .upgrade(mc)
            .expect(Self::UPGRADE_ERR)
            .borrow_mut(mc)
            .stack[self.stack_index] = v;
    }
}

#[derive(Debug, Copy, Clone, Collect)]
#[collect(require_static)]
pub(super) enum MetaReturn {
    /// No return value is expected.
    None,
    /// Place a single return value at an index relative to the returned to function's stack bottom.
    Register(RegisterIndex),
    /// Increment the PC by one if the returned value converted to a boolean is equal to this.
    SkipIf(bool),
}

#[derive(Debug, Copy, Clone, Collect)]
#[collect(require_static)]
pub(super) enum LuaReturn {
    /// Normal function call, place return values at the bottom of the returning function's stack,
    /// as normal.
    Normal(VarCount),
    /// Synthetic metamethod call, do the operation specified in MetaReturn.
    Meta(MetaReturn),
}

#[derive(Debug, Collect)]
#[collect(no_drop)]
pub(super) enum Frame<'gc> {
    /// A running Lua frame.
    Lua {
        bottom: usize,
        closure: Closure<'gc>,
        base: usize,
        is_variable: bool,
        pc: usize,
        stack_size: usize,
        expected_return: Option<LuaReturn>,
        /// C calls (`nCcalls`) this frame runs under, counted from the
        /// thread's `ccalls_base`.
        ccalls: u32,
    },
    /// A frame for a running sequence. When it is the top frame, either the `poll` or `error`
    /// method will be called the next time this thread is stepped, depending on whether there is a
    /// pending error.
    Sequence {
        bottom: usize,
        sequence: BoxSequence<'gc>,
        // Will be set when unwinding has stopped at this frame. If set, this must be the top frame
        // of the stack.
        pending_error: Option<Error<'gc>>,
        ccalls: u32,
    },
    /// A suspended function call that has not yet been run. Must be the only frame in the stack.
    Start(Function<'gc>),
    /// A callback that has been queued but not called yet. Must be the top frame of the stack.
    Callback {
        bottom: usize,
        callback: Callback<'gc>,
        ccalls: u32,
    },
    /// Thread has yielded and is waiting resume. Must be the top frame of the stack or immediately
    /// below a Result frame.
    Yielded,
    /// We are waiting on an upper thread to finish. Must be the top frame of the stack.
    WaitThread,
    /// Results are waiting to be taken. Must be the top frame of the stack.
    Result { bottom: usize },
    /// An error is currently unwinding. Must be the top frame of the stack.
    Error(Error<'gc>),
}

#[derive(Debug, Collect)]
#[collect(no_drop)]
pub struct ThreadState<'gc> {
    pub(super) frames: vec::Vec<Frame<'gc>, MetricsAlloc<'gc>>,
    pub(super) stack: vec::Vec<Value<'gc>, MetricsAlloc<'gc>>,
    pub(super) open_upvalues: vec::Vec<UpValue<'gc>, MetricsAlloc<'gc>>,
    /// What frames' `ccalls` count from: chosen so that the top frame runs
    /// under the C calls last set by `set_ccalls`. Frames below it may then
    /// count below zero, and run under none.
    pub(super) ccalls_base: i64,
    /// The C calls the error unwinding, or last unwound, was raised under:
    /// an error handler runs one level above it (`luaG_errormsg`).
    pub(super) error_ccalls: u32,
}

impl<'gc> ThreadState<'gc> {
    /// The C calls the top frame runs under, counted from `ccalls_base`.
    pub(super) fn top_ccalls(&self) -> u32 {
        for frame in self.frames.iter().rev() {
            match frame {
                Frame::Lua { ccalls, .. }
                | Frame::Sequence { ccalls, .. }
                | Frame::Callback { ccalls, .. } => return *ccalls,
                _ => {}
            }
        }
        0
    }

    /// PUC-Lua's `nCcalls` for the code running at the top of this thread.
    pub(super) fn ccalls(&self) -> u32 {
        self.effective_ccalls(self.top_ccalls())
    }

    /// Raise `error` at the top of the thread, from code running under
    /// `ccalls` C calls (absolute).
    pub(super) fn raise(&mut self, error: Error<'gc>, ccalls: u32) {
        self.error_ccalls = ccalls;
        self.frames.push(Frame::Error(error));
    }

    /// The frame-relative `ccalls` for code running under `absolute` C calls.
    pub(super) fn relative_ccalls(&self, absolute: u32) -> u32 {
        u32::try_from((i64::from(absolute) - self.ccalls_base).max(0)).unwrap_or(u32::MAX)
    }

    pub(super) fn effective_ccalls(&self, ccalls: u32) -> u32 {
        u32::try_from(self.ccalls_base.saturating_add(i64::from(ccalls)).max(0)).unwrap_or(u32::MAX)
    }

    pub(super) fn set_ccalls(&mut self, ccalls: u32) {
        self.ccalls_base = i64::from(ccalls) - i64::from(self.top_ccalls());
    }

    /// The error for a thread whose first call could not be made: the
    /// thread ends with it, as `resume`'s `luaD_rawrunprotected` ends a
    /// coroutine.
    fn raise_at_start(&mut self, ctx: Context<'gc>, limit: CallLimit) {
        self.stack.clear();
        self.frames.push(Frame::Error(
            Value::String(ctx.intern(limit.message().as_bytes())).into(),
        ));
    }

    pub(super) fn mode(&self) -> ThreadMode {
        match self.frames.last() {
            None => {
                debug_assert!(self.stack.is_empty() && self.open_upvalues.is_empty());
                ThreadMode::Stopped
            }
            Some(frame) => match frame {
                Frame::Lua { .. } | Frame::Callback { .. } | Frame::Sequence { .. } => {
                    ThreadMode::Normal
                }
                Frame::Start(_) | Frame::Yielded => ThreadMode::Suspended,
                Frame::WaitThread => ThreadMode::Waiting,
                Frame::Result { .. } => ThreadMode::Result,
                Frame::Error(_) => {
                    if self.frames.len() == 1 {
                        ThreadMode::Result
                    } else {
                        ThreadMode::Normal
                    }
                }
            },
        }
    }

    /// Pushes a new function call frame.
    ///
    /// Arguments are taken from the top of the stack starting at `bottom`, which will become the
    /// bottom of the newly pushed frame.
    ///
    /// `ccalls` is the C calls the new frame runs under, counted from the
    /// thread's `ccalls_base`: the caller's, plus one where PUC-Lua makes
    /// the call through `ccall`. Nothing is changed when the call would
    /// cross `LUAI_MAXCCALLS` or `LUAI_MAXSTACK`; the caller raises the
    /// error.
    pub(super) fn push_call(
        &mut self,
        bottom: usize,
        function: Function<'gc>,
        ccalls: u32,
    ) -> Result<(), CallLimit> {
        if let Some(limit) = self.call_limit(bottom, self.stack.len() - bottom, function, ccalls) {
            return Err(limit);
        }
        match function {
            Function::Closure(closure) => {
                let proto = closure.prototype();
                let fixed_params = proto.fixed_params as usize;
                let stack_size = proto.stack_size as usize;
                let given_params = self.stack.len() - bottom;

                let var_params = if given_params > fixed_params {
                    given_params - fixed_params
                } else {
                    0
                };
                let base = bottom + var_params;
                self.stack[bottom..].rotate_right(var_params);

                self.stack.resize(base + stack_size, Value::Nil);

                self.frames.push(Frame::Lua {
                    bottom,
                    closure,
                    base,
                    is_variable: false,
                    pc: 0,
                    stack_size,
                    expected_return: None,
                    ccalls,
                });
            }
            Function::Callback(callback) => {
                self.frames.push(Frame::Callback {
                    bottom,
                    callback,
                    ccalls,
                });
            }
        }
        Ok(())
    }

    /// The limit a call of `function` with `given_params` arguments, whose
    /// frame would start at `bottom` and run under `ccalls`, would cross.
    pub(super) fn call_limit(
        &self,
        bottom: usize,
        given_params: usize,
        function: Function<'gc>,
        ccalls: u32,
    ) -> Option<CallLimit> {
        // `ccall` checks the C stack first (`luaE_checkcstack`). Only a call
        // landing exactly on the limit raises: an error handler runs one
        // level above the error it handles, past the limit, and may call on
        // until the margin past it runs out.
        let effective = self.effective_ccalls(ccalls);
        if effective == LUAI_MAXCCALLS {
            return Some(CallLimit::CStack);
        }
        if effective >= LUAI_MAXCCALLS_ERR {
            return Some(CallLimit::ErrorHandling);
        }
        if let Function::Closure(closure) = function {
            // `luaD_precall`'s `checkstackGCp`, before the frame exists. A
            // frame here starts at its function's register, where PUC-Lua's
            // starts one above, so each frame adds the function's slot.
            let proto = closure.prototype();
            let top = bottom
                .saturating_add(given_params.saturating_sub(proto.fixed_params as usize))
                .saturating_add(proto.stack_size as usize)
                .saturating_add(self.frames.len());
            if top > LUAI_MAXSTACK {
                return Some(CallLimit::Stack);
            }
        }
        None
    }

    /// Return to the current top frame from a popped frame.
    ///
    /// The current top frame (the frame we are returning to) must be a Lua frame, Sequence, or
    /// there must be no frames at all (in which case this will push a new `Result` frame.)
    ///
    /// `bottom` must be the bottom of the popped, returning frame, and the return values are taken
    /// from the top of the stack starting at `bottom`.
    pub(super) fn return_to(&mut self, bottom: usize) {
        match self.frames.last_mut() {
            Some(Frame::Sequence { .. }) => {}
            Some(Frame::Lua {
                expected_return,
                is_variable,
                base,
                stack_size,
                pc,
                ..
            }) => {
                let return_len = self.stack.len() - bottom;
                match expected_return.take() {
                    Some(LuaReturn::Normal(ret_count)) => {
                        let return_len = ret_count
                            .to_constant()
                            .map(|c| c as usize)
                            .unwrap_or(return_len);

                        self.stack.truncate(bottom + return_len);

                        *is_variable = ret_count.is_variable();
                        if !ret_count.is_variable() {
                            self.stack.resize(*base + *stack_size, Value::Nil);
                        }
                    }
                    Some(LuaReturn::Meta(meta_ret)) => {
                        let meta_val = self.stack.get(bottom).copied().unwrap_or_default();
                        self.stack.truncate(bottom);
                        self.stack.resize(*base + *stack_size, Value::Nil);
                        *is_variable = false;
                        match meta_ret {
                            MetaReturn::None => {}
                            MetaReturn::Register(reg) => {
                                self.stack[*base + reg.0 as usize] = meta_val;
                            }
                            MetaReturn::SkipIf(skip_if) => {
                                if meta_val.to_bool() == skip_if {
                                    *pc += 1;
                                }
                            }
                        }
                    }
                    None => panic!("no expected return set for returned to lua frame"),
                }
            }
            None => {
                self.frames.push(Frame::Result { bottom });
            }
            _ => panic!("return frame must be sequence or lua frame"),
        }
    }

    pub(super) fn take_result(
        &mut self,
    ) -> Result<impl Iterator<Item = Value<'gc>> + '_, Error<'gc>> {
        match self.frames.pop() {
            Some(Frame::Result { bottom }) => Ok(self.stack.drain(bottom..)),
            Some(Frame::Error(err)) => {
                assert!(self.stack.is_empty());
                assert!(self.frames.is_empty());
                assert!(self.open_upvalues.is_empty());
                Err(err)
            }
            _ => panic!("no results available to take"),
        }
    }

    pub(super) fn close_upvalues(&mut self, mc: &Mutation<'gc>, bottom: usize) {
        let start = match self
            .open_upvalues
            .binary_search_by(|&u| open_upvalue_ind(u).cmp(&bottom))
        {
            Ok(i) => i,
            Err(i) => i,
        };

        let this_ptr = self as *mut _;
        for &upval in &self.open_upvalues[start..] {
            match upval.get() {
                UpValueState::Open(open_upvalue) => {
                    debug_assert!(open_upvalue.thread.upgrade(mc).unwrap().as_ptr() == this_ptr);
                    upval.set(
                        mc,
                        UpValueState::Closed(self.stack[open_upvalue.stack_index]),
                    );
                }
                UpValueState::Closed(_) => panic!("upvalue is not open"),
            }
        }

        self.open_upvalues.truncate(start);
    }

    pub(super) fn reset(&mut self, mc: &Mutation<'gc>) {
        self.close_upvalues(mc, 0);
        assert!(self.open_upvalues.is_empty());
        self.stack.clear();
        self.frames.clear();
    }

    fn resurrect_live_upvalues(&self, fc: &Finalization<'gc>) {
        for &upval in &self.open_upvalues {
            if !Gc::is_dead(fc, UpValue::into_inner(upval)) {
                match upval.get() {
                    UpValueState::Open(open_upvalue) => {
                        match self.stack[open_upvalue.stack_index] {
                            Value::String(s) => Gc::resurrect(fc, String::into_inner(s)),
                            Value::Table(t) => Gc::resurrect(fc, Table::into_inner(t)),
                            Value::Function(Function::Closure(c)) => {
                                Gc::resurrect(fc, Closure::into_inner(c))
                            }
                            Value::Function(Function::Callback(c)) => {
                                Gc::resurrect(fc, Callback::into_inner(c))
                            }
                            Value::Thread(t) => Gc::resurrect(fc, Thread::into_inner(t)),
                            Value::UserData(u) => Gc::resurrect(fc, UserData::into_inner(u)),
                            _ => {}
                        }
                    }
                    UpValueState::Closed(_) => panic!("upvalue is not open"),
                }
            }
        }
    }
}

pub(super) struct LuaFrame<'gc, 'a> {
    pub(super) thread: Thread<'gc>,
    pub(super) state: &'a mut ThreadState<'gc>,
    pub(super) fuel: &'a mut Fuel,
}

impl<'gc, 'a> LuaFrame<'gc, 'a> {
    const FUEL_PER_CALL: i32 = 4;
    const FUEL_PER_ITEM: i32 = 1;

    // Returns the active closure for this Lua frame
    pub(super) fn closure(&self) -> Closure<'gc> {
        match self.state.frames.last() {
            Some(Frame::Lua { closure, .. }) => *closure,
            _ => panic!("top frame is not lua frame"),
        }
    }

    /// returns a view of the Lua frame's registers
    pub(super) fn registers<'b>(&'b mut self) -> LuaRegisters<'gc, 'b> {
        match self.state.frames.last_mut() {
            Some(Frame::Lua {
                bottom, base, pc, ..
            }) => {
                let (upper_stack, stack_frame) = self.state.stack[..].split_at_mut(*base);
                LuaRegisters {
                    pc,
                    stack_frame,
                    upper_stack,
                    bottom: *bottom,
                    base: *base,
                    open_upvalues: &mut self.state.open_upvalues,
                    thread: self.thread,
                }
            }
            _ => panic!("top frame is not lua frame"),
        }
    }

    /// Place the current frame's varargs at the given register, expecting the given count
    pub(super) fn varargs(&mut self, dest: RegisterIndex, count: VarCount) -> Result<(), VMError> {
        let Some(Frame::Lua {
            bottom,
            base,
            is_variable,
            ..
        }) = self.state.frames.last_mut()
        else {
            panic!("top frame is not lua frame");
        };

        if *is_variable {
            return Err(VMError::ExpectedVariableStack(false));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        let varargs_start = *bottom;
        let varargs_len = *base - varargs_start;

        let dest = *base + dest.0 as usize;
        if let Some(count) = count.to_constant() {
            let count = count as usize;
            self.fuel.consume(count_fuel(Self::FUEL_PER_ITEM, count));

            if count <= varargs_len {
                self.state
                    .stack
                    .copy_within(varargs_start..varargs_start + count, dest);
            } else {
                self.state
                    .stack
                    .copy_within(varargs_start..varargs_start + varargs_len, dest);
                self.state.stack[dest + varargs_len..dest + count].fill(Value::Nil);
            }
        } else {
            self.fuel
                .consume(count_fuel(Self::FUEL_PER_ITEM, varargs_len));

            *is_variable = true;
            self.state.stack.truncate(dest);
            self.state
                .stack
                .extend_from_within(varargs_start..varargs_start + varargs_len);
        }

        Ok(())
    }

    /// Set elements of a table as a group according to the `SetList` opcode protocol.
    ///
    /// Expects a table at register `table_base`, the current table index at `table_base + 1`, and
    /// `count` elements following this.
    pub(super) fn set_table_list(
        &mut self,
        mc: &Mutation<'gc>,
        table_base: RegisterIndex,
        count: VarCount,
    ) -> Result<(), VMError> {
        let Some(&mut Frame::Lua {
            base,
            ref mut is_variable,
            stack_size,
            ..
        }) = self.state.frames.last_mut()
        else {
            panic!("top frame is not lua frame");
        };

        if count.is_variable() != *is_variable {
            return Err(VMError::ExpectedVariableStack(count.is_variable()));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        let table_ind = base + table_base.0 as usize;
        let start_ind = table_ind + 1;

        let table = self.state.stack[table_ind];
        let start = self.state.stack[start_ind];

        let (Value::Table(table), Value::Integer(mut start)) = (table, start) else {
            return Err(VMError::BadSetList(table.type_name(), start.type_name()));
        };

        let set_count = count
            .to_constant()
            .map(|c| c as usize)
            .unwrap_or(self.state.stack.len() - table_ind - 2);

        self.fuel
            .consume(count_fuel(Self::FUEL_PER_ITEM, set_count));
        for i in 0..set_count {
            if let Some(inc) = start.checked_add(1) {
                start = inc;
                table
                    .set_raw(mc, inc.into(), self.state.stack[table_ind + 2 + i])
                    .unwrap();
            } else {
                break;
            }
        }

        self.state.stack[start_ind] = Value::Integer(start);

        if count.is_variable() {
            self.state.stack.resize(base + stack_size, Value::Nil);
            *is_variable = false;
        }

        Ok(())
    }

    /// Call the function at the given register with the given arguments. On return, results will be
    /// placed starting at the function register.
    pub(super) fn call_function(
        self,
        ctx: Context<'gc>,
        func: RegisterIndex,
        args: VarCount,
        returns: VarCount,
    ) -> Result<(), VMError> {
        let Some(Frame::Lua {
            expected_return,
            is_variable,
            base,
            ..
        }) = self.state.frames.last_mut()
        else {
            panic!("top frame is not lua frame");
        };

        if *is_variable != args.is_variable() {
            return Err(VMError::ExpectedVariableStack(args.is_variable()));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        let function_index = *base + func.0 as usize;
        let arg_count = args
            .to_constant()
            .map(|c| c as usize)
            .unwrap_or(self.state.stack.len() - function_index - 1);

        let call = meta_ops::call(ctx, self.state.stack[function_index])?;
        *expected_return = Some(LuaReturn::Normal(returns));

        self.fuel
            .consume(count_fuel(Self::FUEL_PER_ITEM, arg_count));

        self.state.stack.remove(function_index);
        self.state.stack.truncate(function_index + arg_count);

        // A Lua call (`OP_CALL`) takes no C level.
        let ccalls = self.state.top_ccalls();
        self.state
            .push_call(function_index, call, ccalls)
            .map_err(limit_error)
    }

    /// Calls the function at the given index with a constant number of arguments without
    /// invalidating the function or its arguments. Returns are placed *after* the function and its
    /// arguments, and all registers past this are invalidated as normal.
    pub(super) fn call_function_keep(
        self,
        ctx: Context<'gc>,
        func: RegisterIndex,
        arg_count: u8,
        returns: VarCount,
    ) -> Result<(), VMError> {
        let Some(Frame::Lua {
            expected_return,
            is_variable,
            base,
            ..
        }) = self.state.frames.last_mut()
        else {
            panic!("top frame is not lua frame");
        };

        if *is_variable {
            return Err(VMError::ExpectedVariableStack(false));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        let arg_count = arg_count as usize;

        let function_index = *base + func.0 as usize;
        let top = function_index + 1 + arg_count;

        let call = meta_ops::call(ctx, self.state.stack[function_index])?;
        *expected_return = Some(LuaReturn::Normal(returns));

        self.fuel
            .consume(count_fuel(Self::FUEL_PER_ITEM, arg_count));

        self.state.stack.truncate(top);
        self.state
            .stack
            .extend_from_within(function_index + 1..function_index + 1 + arg_count);

        // `OP_TFORCALL` calls the iterator with `luaD_call`: one C level.
        let ccalls = self.state.top_ccalls().saturating_add(1);
        self.state.push_call(top, call, ccalls).map_err(limit_error)
    }

    /// Calls an externally defined function in a completely non-destructive way in a new frame, and
    /// places an optional single result of this function call at the given register.
    ///
    /// Nothing at all in the frame is invalidated, other than optionally placing the return value.
    pub(super) fn call_meta_function(
        self,
        ctx: Context<'gc>,
        func: Function<'gc>,
        args: &[Value<'gc>],
        meta_ret: MetaReturn,
    ) -> Result<(), VMError> {
        // `luaT_callTMres` calls a metamethod with `luaD_call`: one C level.
        self.call_meta(ctx, func, args, meta_ret, 1)
    }

    /// As [`Self::call_meta_function`], for a function that stands for a loop
    /// of the VM's own, which takes no C level.
    pub(super) fn call_meta_loop(
        self,
        ctx: Context<'gc>,
        func: Function<'gc>,
        args: &[Value<'gc>],
        meta_ret: MetaReturn,
    ) -> Result<(), VMError> {
        self.call_meta(ctx, func, args, meta_ret, 0)
    }

    fn call_meta(
        self,
        _ctx: Context<'gc>,
        func: Function<'gc>,
        args: &[Value<'gc>],
        meta_ret: MetaReturn,
        levels: u32,
    ) -> Result<(), VMError> {
        let Some(Frame::Lua {
            expected_return,
            is_variable,
            base,
            stack_size,
            ..
        }) = self.state.frames.last_mut()
        else {
            panic!("top frame is not lua frame");
        };

        if *is_variable {
            return Err(VMError::ExpectedVariableStack(false));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        let top = self.state.stack.len();
        debug_assert_eq!(top, *base + *stack_size);

        *expected_return = Some(LuaReturn::Meta(meta_ret));

        self.fuel
            .consume(count_fuel(Self::FUEL_PER_ITEM, args.len()));

        self.state.stack.extend_from_slice(args);

        let ccalls = self.state.top_ccalls().saturating_add(levels);
        self.state.push_call(top, func, ccalls).map_err(limit_error)
    }

    /// Tail-call the function at the given register with the given arguments. Pops the current Lua
    /// frame, pushing a new frame for the given function.
    pub(super) fn tail_call_function(
        self,
        ctx: Context<'gc>,
        func: RegisterIndex,
        args: VarCount,
    ) -> Result<(), VMError> {
        let Some(&mut Frame::Lua {
            bottom,
            base,
            is_variable,
            ..
        }) = self.state.frames.last_mut()
        else {
            panic!("top frame is not lua frame");
        };

        if is_variable != args.is_variable() {
            return Err(VMError::ExpectedVariableStack(args.is_variable()));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        let function_index = base + func.0 as usize;
        let arg_count = args
            .to_constant()
            .map(|c| c as usize)
            .unwrap_or(self.state.stack.len() - function_index - 1);

        let call = meta_ops::call(ctx, self.state.stack[function_index])?;

        // The called function reuses this frame's C level, and its limits
        // are checked while this frame, whose position an error gives, is
        // still here (`luaD_pretailcall`).
        let ccalls = self.state.top_ccalls();
        if let Some(limit) = self.state.call_limit(bottom, arg_count, call, ccalls) {
            return Err(limit_error(limit));
        }

        self.state.close_upvalues(&ctx, bottom);
        self.state.frames.pop();

        self.fuel
            .consume(count_fuel(Self::FUEL_PER_ITEM, arg_count));

        self.state
            .stack
            .copy_within(function_index + 1..function_index + 1 + arg_count, bottom);
        self.state.stack.truncate(bottom + arg_count);

        self.state
            .push_call(bottom, call, ccalls)
            .map_err(limit_error)
    }

    /// Return to the upper frame with results starting at the given register index.
    pub(super) fn return_upper(
        self,
        mc: &Mutation<'gc>,
        start: RegisterIndex,
        count: VarCount,
    ) -> Result<(), VMError> {
        let Some(Frame::Lua {
            bottom,
            base,
            is_variable,
            ..
        }) = self.state.frames.pop()
        else {
            panic!("top frame is not lua frame");
        };

        if is_variable != count.is_variable() {
            return Err(VMError::ExpectedVariableStack(count.is_variable()));
        }

        self.fuel.consume(Self::FUEL_PER_CALL);

        self.state.close_upvalues(mc, bottom);

        let start = base + start.0 as usize;
        let count = count
            .to_constant()
            .map(|c| c as usize)
            .unwrap_or(self.state.stack.len() - start);

        self.fuel.consume(count_fuel(Self::FUEL_PER_ITEM, count));

        self.state.stack.copy_within(start..start + count, bottom);
        self.state.stack.truncate(bottom + count);
        self.state.return_to(bottom);

        Ok(())
    }
}

pub(super) struct LuaRegisters<'gc, 'a> {
    pub pc: &'a mut usize,
    pub stack_frame: &'a mut [Value<'gc>],
    upper_stack: &'a mut [Value<'gc>],
    bottom: usize,
    base: usize,
    open_upvalues: &'a mut vec::Vec<UpValue<'gc>, MetricsAlloc<'gc>>,
    thread: Thread<'gc>,
}

impl<'gc, 'a> LuaRegisters<'gc, 'a> {
    pub(super) fn open_upvalue(&mut self, mc: &Mutation<'gc>, reg: RegisterIndex) -> UpValue<'gc> {
        let ind = self.base + reg.0 as usize;
        match self
            .open_upvalues
            .binary_search_by(|&u| open_upvalue_ind(u).cmp(&ind))
        {
            Ok(i) => self.open_upvalues[i],
            Err(i) => {
                let uv = UpValue::new(
                    mc,
                    UpValueState::Open(OpenUpValue {
                        thread: Gc::downgrade(self.thread.0),
                        stack_index: ind,
                    }),
                );
                self.open_upvalues.insert(i, uv);
                uv
            }
        }
    }

    pub(super) fn get_upvalue(&self, mc: &Mutation<'gc>, upvalue: UpValue<'gc>) -> Value<'gc> {
        match upvalue.get() {
            UpValueState::Open(open_upvalue) => {
                if open_upvalue.thread.as_ptr() == Gc::as_ptr(self.thread.0) {
                    assert!(
                        open_upvalue.stack_index < self.bottom,
                        "upvalues must be above the current Lua frame"
                    );
                    self.upper_stack[open_upvalue.stack_index]
                } else {
                    open_upvalue.get(mc)
                }
            }
            UpValueState::Closed(v) => v,
        }
    }

    pub(super) fn set_upvalue(
        &mut self,
        mc: &Mutation<'gc>,
        upvalue: UpValue<'gc>,
        value: Value<'gc>,
    ) {
        match upvalue.get() {
            UpValueState::Open(open_upvalue) => {
                if open_upvalue.thread.as_ptr() == Gc::as_ptr(self.thread.0) {
                    assert!(
                        open_upvalue.stack_index < self.bottom,
                        "upvalues must be above the current Lua frame"
                    );
                    self.upper_stack[open_upvalue.stack_index] = value;
                } else {
                    open_upvalue.set(mc, value);
                }
            }
            UpValueState::Closed(_) => {
                upvalue.set(mc, UpValueState::Closed(value));
            }
        }
    }

    pub(super) fn close_upvalues(&mut self, mc: &Mutation<'gc>, bottom_register: RegisterIndex) {
        let bottom = self.base + bottom_register.0 as usize;
        let start = match self
            .open_upvalues
            .binary_search_by(|&u| open_upvalue_ind(u).cmp(&bottom))
        {
            Ok(i) => i,
            Err(i) => i,
        };

        for &upval in &self.open_upvalues[start..] {
            match upval.get() {
                UpValueState::Open(open_upvalue) => {
                    assert!(open_upvalue.thread.as_ptr() == Gc::as_ptr(self.thread.0));
                    upval.set(
                        mc,
                        UpValueState::Closed(if open_upvalue.stack_index < self.base {
                            self.upper_stack[open_upvalue.stack_index]
                        } else {
                            self.stack_frame[open_upvalue.stack_index - self.base]
                        }),
                    );
                }
                UpValueState::Closed(_) => panic!("upvalue is not open"),
            }
        }

        self.open_upvalues.truncate(start);
    }
}

/// A call limit, raised from the Lua function making the call
/// (`luaG_runerror`).
fn limit_error(limit: CallLimit) -> VMError {
    match limit {
        CallLimit::ErrorHandling => VMError::ErrorInErrorHandling,
        _ => VMError::Lua(limit.message().into()),
    }
}

fn open_upvalue_ind<'gc>(u: UpValue<'gc>) -> usize {
    match u.get() {
        UpValueState::Open(open_upvalue) => open_upvalue.stack_index,
        UpValueState::Closed(_) => panic!("upvalue is not open"),
    }
}
