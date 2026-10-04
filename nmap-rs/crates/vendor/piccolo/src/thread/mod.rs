mod executor;
mod thread;
mod vm;

use thiserror::Error;

use crate::meta_ops::{MetaCallError, MetaOperatorError};

pub use self::{
    executor::{
        BadExecutorMode, CurrentThread, Execution, Executor, ExecutorInner, ExecutorMode,
        UpperLuaFrame,
    },
    thread::{BadThreadMode, OpenUpValue, Thread, ThreadInner, ThreadMode},
};

#[derive(Debug, Clone, Error)]
pub enum VMError {
    #[error("{}", if *.0 {
        "operation expects variable stack"
    } else {
        "unexpected variable stack during operation"
    })]
    ExpectedVariableStack(bool),
    #[error("Bad types for SetList op, expected table, integer, found {0}, {1}")]
    BadSetList(&'static str, &'static str),
    #[error("{0}")]
    BadCall(#[from] MetaCallError),
    #[error("{0}")]
    OperatorError(#[from] MetaOperatorError),
    /// A runtime error in PUC-Lua's words (`luaG_runerror`), e.g. a bad
    /// `for` loop.
    #[error("{0}")]
    Lua(std::string::String),
    #[error("_ENV upvalue is only allowed on top-level closure")]
    BadEnvUpValue,
    #[error("Invalid types in for loop; expected numbers, found {0}, {1}, and {2}")]
    BadForLoop(&'static str, &'static str, &'static str),
    #[error("Invalid types in for loop; expected numbers, found {0} and {1}")]
    BadForLoopPrep(&'static str, &'static str),
}

impl VMError {
    /// Whether this is an error PUC-Lua raises with `luaG_runerror` from the
    /// running Lua function, and so gives that function's position. The rest
    /// are the VM's own invariants, which a correct program never meets.
    pub fn is_lua_error(&self) -> bool {
        matches!(
            self,
            VMError::BadCall(_) | VMError::OperatorError(_) | VMError::Lua(_)
        )
    }

    /// Whether PUC-Lua would prefix this error with the position of the Lua
    /// function running: not for one it raises from inside a C function.
    pub fn is_positioned(&self) -> bool {
        !matches!(
            self,
            VMError::OperatorError(MetaOperatorError::MessageFromC(_))
        )
    }
}
