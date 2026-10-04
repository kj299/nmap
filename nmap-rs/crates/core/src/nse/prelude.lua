-- The engine's own Lua, run once in every NSE state before anything else:
-- the parts of nmap's nse_main.lua that libraries and scripts rely on.
--
-- Everything between a "-- >>> nse_main.lua" line and the next "-- <<<" line
-- is copied from nse_main.lua byte for byte; a test fails if any such block
-- no longer appears there verbatim. Only the locals those blocks read are
-- written here, as nse_main.lua binds them.

local assert = assert;
local error = error;
local pcall = pcall;
local rawset = rawset;
local require = require;
local tonumber = tonumber;

local coroutine = require "coroutine";
local create = coroutine.create;
local resume = coroutine.resume;
local yield = coroutine.yield;

local debug = require "debug";
local traceback = debug.traceback;

local string = require "string";
local format = string.format;

local nmap = require "nmap";

-- >>> nse_main.lua
local stdnse = require "stdnse";

local strict = require "strict";
assert(_ENV == _G);
strict(_ENV);
-- <<<

-- >>> nse_main.lua
-- NSE_YIELD_VALUE
-- This is the table C uses to yield a thread with a unique value to
-- differentiate between yields initiated by NSE or regular coroutine yields.
local NSE_YIELD_VALUE = {};

do
  -- This is the method by which we allow a script to have nested
  -- coroutines. If a sub-thread yields in an NSE function such as
  -- nsock.connect, then we propagate the yield up. These replacements
  -- to the coroutine library are used only by Script Threads, not the engine.

  local function handle (co, status, ...)
    if status and NSE_YIELD_VALUE == ... then -- NSE has yielded the thread
      return handle(co, resume(co, yield(NSE_YIELD_VALUE)));
    else
      return status, ...;
    end
  end

  function coroutine.resume (co, ...)
    return handle(co, resume(co, ...));
  end

  local resume = coroutine.resume; -- local reference to new coroutine.resume
  local function aux_wrap (status, ...)
    if not status then
      return error(..., 2);
    else
      return ...;
    end
  end
  function coroutine.wrap (f)
    local co = create(f);
    return function (...)
      return aux_wrap(resume(co, ...));
    end
  end
end
-- <<<

-- >>> nse_main.lua
local log_write, verbosity, debugging =
    nmap.log_write, nmap.verbosity, nmap.debugging;
-- <<<

-- >>> nse_main.lua
local function print_verbose (level, fmt, ...)
  if verbosity() >= assert(tonumber(level)) or debugging() > 0 then
    log_write("stdout", format(fmt, ...));
  end
end

local function print_debug (level, fmt, ...)
  if debugging() >= assert(tonumber(level)) then
    log_write("stdout", format(fmt, ...));
  end
end

local function log_error (fmt, ...)
  log_write("stderr", format(fmt, ...));
end
-- <<<

-- >>> nse_main.lua
local REQUIRE_ERROR = {};
rawset(stdnse, "silent_require", function (...)
  local status, mod = pcall(require, ...);
  if not status then
    print_debug(2, "%s", traceback(mod));
    error(REQUIRE_ERROR)
  else
    return mod;
  end
end);
-- <<<

-- What the engine itself needs from here on.
return {
  NSE_YIELD_VALUE = NSE_YIELD_VALUE,
  REQUIRE_ERROR = REQUIRE_ERROR,
  print_verbose = print_verbose,
  print_debug = print_debug,
  log_error = log_error,
}
