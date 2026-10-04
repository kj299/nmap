use std::string::String as StdString;

use piccolo::{Closure, Executor, Lua};

const SOURCE: &str = r#"
    -- Purposeful typo of 'tostring'
    return tosting("hello")
"#;

#[test]
fn tail_call_stack_panic() {
    let mut lua = Lua::core();

    let exec = lua.enter(|ctx| ctx.stash(Executor::new(ctx)));

    lua.try_enter(|ctx| {
        let closure = Closure::load(ctx, None, SOURCE.as_bytes())?;
        ctx.fetch(&exec).restart(ctx, closure.into(), ());
        Ok(())
    })
    .expect("load closure");

    // Calling a nil global is a Lua error carrying PUC-Lua's message, as a
    // string, after the call's position.
    let err = lua.execute::<StdString>(&exec).unwrap_err();
    assert!(
        err.to_string().ends_with(":3: attempt to call a nil value"),
        "{err}"
    );
}
