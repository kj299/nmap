-- The engine's own Lua: nmap's nse_main.lua, less the parts this port does
-- in Rust, run once in every NSE state before anything else.
--
-- Everything between a "-- >>> nse_main.lua" line and the next "-- <<<" line
-- is copied from nse_main.lua byte for byte; a test fails if any such block
-- no longer appears there verbatim. What is written here instead is:
--
--   * the locals those blocks read, bound as nse_main.lua binds them;
--   * `_R`, a table of the engine's own standing in for the registry slots
--     nse_main.lua shares with nse_main.cc -- this state has no
--     debug.getregistry, and only the engine reads these slots;
--   * the glue that replaces the halves done in Rust (core::nse::engine):
--     choosing scripts and parsing --script-args happen there, and here
--     `load_script` and `scripts_loaded` load what was chosen; `render`
--     hands each result's text and XML to Rust, which prints them as
--     output.cc does.
--
-- What the chunk is called with, as nse_main.lua is: `cnse`, the engine's
-- functions written in Rust (nse_main.cc's `open_cnse`).

local cnse = ...;

-- The registry slots nse_main.lua writes (NSE_YIELD, NSE_FORMAT_TABLE, ...).
local _R = {};

local assert = assert;
local error = error;
local ipairs = ipairs;
local load = load;
local next = next;
local pairs = pairs;
local pcall = pcall;
local rawget = rawget;
local rawset = rawset;
local require = require;
local select = select;
local setmetatable = setmetatable;
local tonumber = tonumber;
local tostring = tostring;
local type = type;

-- `collectgarbage "step"` and `"collect"` are hints in nse_main.lua, made
-- between scheduler passes; this VM collects incrementally as it allocates,
-- and has no explicit collection to request.
local function collectgarbage () return 0 end

local coroutine = require "coroutine";
local create = coroutine.create;
local resume = coroutine.resume;
local status = coroutine.status;
local yield = coroutine.yield;
local wrap = coroutine.wrap;

local debug = require "debug";
local traceback = debug.traceback;

local io = require "io";
local lines = io.lines;

local math = require "math";
local max = math.max;

local string = require "string";
local find = string.find;
local format = string.format;
local gsub = string.gsub;
local match = string.match;
local sub = string.sub;

local table = require "table";
local concat = table.concat;
local insert = table.insert;
local pack = table.pack;
local unpack = table.unpack;

local os = require "os"
local time = os.time
local difftime = os.difftime

local nmap = require "nmap";

local socket = require "nmap.socket";

-- >>> nse_main.lua
local NAME = "NSE";

-- Script Scan phases.
local NSE_PRE_SCAN  = "NSE_PRE_SCAN";
local NSE_SCAN      = "NSE_SCAN";
local NSE_POST_SCAN = "NSE_POST_SCAN";

-- String keys into the registry (_R), for data shared with nse_main.cc.
local YIELD = "NSE_YIELD";
local BASE = "NSE_BASE";
local WAITING_TO_RUNNING = "NSE_WAITING_TO_RUNNING";
local DESTRUCTOR = "NSE_DESTRUCTOR";
local SELECTED_BY_NAME = "NSE_SELECTED_BY_NAME";
local FORMAT_TABLE = "NSE_FORMAT_TABLE";
local FORMAT_XML = "NSE_FORMAT_XML";
local PARALLELISM = "NSE_PARALLELISM";

-- Unique value indicating the action function is going to run.
local ACTION_STARTING = {};

-- This is a limit on the number of script instance threads running at once. It
-- exists only to limit memory use when there are many open ports. It doesn't
-- count worker threads started by scripts.
local CONCURRENCY_LIMIT = 1000;

-- Table of different supported rules.
local NSE_SCRIPT_RULES = {
  prerule = "prerule",
  hostrule = "hostrule",
  portrule = "portrule",
  postrule = "postrule",
};
-- <<<

-- The I/O half of the nmap module, written over core::nse::net, which checks
-- each call's arguments as the C does and starts the operation; here, the
-- thread then waits as nse_nsock.cc and nse_nmaplib.cc make it wait: it
-- yields through _R[YIELD] (nse_yield), and `loop`, which the scheduler runs
-- between passes, restores it through _R[WAITING_TO_RUNNING] (nse_restore)
-- with what the operation left. The scheduler, copied from nse_main.lua
-- below, sees the yields and restores nsock produces.
--
-- The functions are installed in `nmap` before stdnse loads, because stdnse
-- keeps `nmap.socket.sleep` as it finds it.
local net = cnse.net;
local running = coroutine.running;
local tointeger = math.tointeger;

-- nse_yield: yield the running thread to the engine; returns what the thread
-- is restored with.
local function nse_yield ()
  return yield(_R[YIELD](running()));
end

-- nse_restore: put `co` back among the running threads, with values.
local function nse_restore (co, ...)
  return _R[WAITING_TO_RUNNING](co, ...);
end

-- nse_destructor: call `destructor(co, key)` when the thread `co` belongs to
-- ends; "add" or "remove".
local function nse_destructor (what, co, key, destructor)
  return _R[DESTRUCTOR](what, co, key, destructor);
end

local NSOCK_SOCKET = {};       -- the socket methods
local pending = {};            -- operation -> the coroutine waiting on it
local owner = setmetatable({}, {__mode = "k"}); -- socket -> thread (nu->thread)
local thread_sockets = {};     -- base thread -> {socket = true} (THREAD_SOCKETS)
local connect_waiting = {};    -- base thread -> true (CONNECT_WAITING)

local function count (t)
  local n = 0; for _ in pairs(t) do n = n + 1 end return n;
end

-- `yield` in nse_nsock.cc, first half: the socket belongs to the running
-- thread until the operation completes. Called, not tail-called, by each
-- method, so that the error names the method's caller.
local function claim (sock)
  local co = running();
  local o = owner[sock];
  if o ~= nil and o ~= co then
    error("Invalid reuse of a socket from one thread to another.", 3);
  end
  owner[sock] = co;
end

-- The second half: wait for operation `op`, which core::nse::net started.
local function wait (op)
  pending[op] = running();
  return nse_yield();
end

-- socket_lock: a thread may hold sockets while fewer than --max-parallelism
-- (20 by default) other threads do.
local function socket_lock (sock)
  local p = net.max_parallelism == 0 and 20 or net.max_parallelism;
  local base = _R[BASE]();
  local sockets = thread_sockets[base];
  if sockets ~= nil then
    sockets[sock] = true;
    return true;
  elseif count(thread_sockets) <= p then
    thread_sockets[base] = {[sock] = true};
    return true;
  else
    connect_waiting[base] = true;
    return false;
  end
end

-- socket_unlock: a thread that has ended, or holds no open socket, gives up
-- its sockets (closing them), and the threads waiting to connect retry.
local function socket_unlock ()
  for thread, sockets in pairs(thread_sockets) do
    local open = 0;
    if status(thread) == "suspended" then
      for sock in pairs(sockets) do
        if net.is_open(sock) then open = open + 1 end
      end
    end
    if open == 0 then
      for sock in pairs(sockets) do
        sock:close();
      end
      thread_sockets[thread] = nil;
      for co in pairs(connect_waiting) do
        nse_restore(co);
        connect_waiting[co] = nil;
      end
    end
  end
end

function NSOCK_SOCKET.connect (self, host, port, proto)
  net.connect_args(self, host, port, proto);
  while not socket_lock(self) do
    nse_yield(); -- restart once a socket is free
  end
  local op, err = net.connect(self, host, port, proto);
  if op == false then return false, err end
  owner[self] = running();
  local r = pack(wait(op));
  -- After a connect, the socket may be used by another thread.
  owner[self] = nil;
  return unpack(r, 1, r.n);
end

function NSOCK_SOCKET.send (self, data)
  local op = net.send(self, data);
  claim(self);
  return wait(op);
end

function NSOCK_SOCKET.sendto (self, host, port, data)
  local op, err = net.sendto(self, host, port, data);
  if op == false then return false, err end
  claim(self);
  return wait(op);
end

function NSOCK_SOCKET.receive (self)
  local op = net.receive(self, "any");
  claim(self);
  return wait(op);
end

function NSOCK_SOCKET.receive_lines (self, n)
  local op = net.receive(self, "lines", n);
  claim(self);
  return wait(op);
end

function NSOCK_SOCKET.receive_bytes (self, n)
  local op = net.receive(self, "bytes", n);
  claim(self);
  return wait(op);
end

-- receive_buf: read until `delimiter` (a pattern, or a function returning
-- the delimiter's start and end) matches the buffered data; return what
-- precedes it (and the delimiter itself when `keeppattern`), and keep the
-- rest for the next call. A failed read loses what it had added, as in C.
function NSOCK_SOCKET.receive_buf (self, delimiter, keeppattern)
  net.check(self, true);
  local t = type(delimiter);
  if t ~= "function" and t ~= "string" then
    error(("bad argument #2 to '?' (function/string expected, got %s)"):format(t), 2);
  end
  if type(keeppattern) ~= "boolean" then
    error(("bad argument #3 to '?' (boolean expected, got %s)"):format(type(keeppattern)), 2);
  end
  local buf = net.buffer(self);
  while true do
    local l, r;
    if t == "function" then
      l, r = delimiter(buf);
    else
      l, r = find(buf, delimiter);
    end
    if tonumber(l) ~= nil and tonumber(r) ~= nil then
      l, r = tointeger(tonumber(l)) or 0, tointeger(tonumber(r)) or 0;
      if l > r or r > #buf then
        error("invalid indices for match", 2);
      end
      -- The C copies l-1 (or r) bytes as a size_t, and keeps buf+r: an
      -- index before the buffer is an out-of-bounds read there
      -- (nse-receive-buf-negative-index). Here it is the buffer's start.
      r = max(r, 0);
      net.set_buffer(self, sub(buf, r + 1));
      if keeppattern then
        return true, sub(buf, 1, r);
      else
        return true, sub(buf, 1, max(l - 1, 0));
      end
    end
    local op = net.receive(self, "any");
    claim(self);
    local ok, data = wait(op);
    if not ok then
      return ok, data;
    end
    buf = buf .. data;
  end
end

function NSOCK_SOCKET.close (self)
  owner[self] = nil;
  return net.close(self);
end

NSOCK_SOCKET.get_info = net.get_info;
NSOCK_SOCKET.set_timeout = net.set_timeout;
NSOCK_SOCKET.bind = net.bind;

-- What an nmap built without OpenSSL answers.
function NSOCK_SOCKET.reconnect_ssl (self)
  net.check(self, true);
  return false, "sorry, you don't have OpenSSL";
end

function NSOCK_SOCKET.get_ssl_certificate (self)
  error("SSL is not available", 2);
end

-- Packet capture is not available to scripts yet (nse-no-pcap-sockets).
function NSOCK_SOCKET.pcap_open (self, device, snaplen, promisc, bpf)
  net.check(self, false);
  error(("can't open pcap reader on %s"):format(tostring(device)), 2);
end

function NSOCK_SOCKET.pcap_receive (self)
  net.check(self, false);
  error("not a pcap socket", 2);
end

NSOCK_SOCKET.pcap_close = NSOCK_SOCKET.close;

net.set_meta({__index = NSOCK_SOCKET, __metatable = {}});

-- nmap.socket.sleep: a timer, cancelled if the thread ends first.
local function sleep (secs)
  local op = net.sleep(secs);
  nse_destructor("add", running(), {}, function () net.cancel(op) end);
  return wait(op);
end

-- nmap.socket.loop: give up the sockets of threads done with them, then
-- complete what the network has ready, waiting at most `ms`, and restore the
-- threads that waited on it.
local function loop (ms)
  socket_unlock();
  for _, c in ipairs(net.poll(ms)) do
    local co = pending[c.op];
    if co ~= nil then
      pending[c.op] = nil;
      nse_restore(co, unpack(c, 1, c.n));
    end
  end
end

socket.new = net.new;
socket.sleep = sleep;
socket.loop = loop;
socket.get_stats = function ()
  return {connect_waiting = count(connect_waiting)};
end
nmap.new_socket = net.new;

-- nmap.mutex(object): one mutex per object.
local mutexes = setmetatable({}, {__mode = "k"});
function nmap.mutex (object)
  local t = type(object);
  if t == "nil" or t == "boolean" or t == "number" then
    error("bad argument #1 to 'nmap.mutex' (object expected)", 2);
  end
  local m = mutexes[object];
  if m ~= nil then return m end
  local waiting, holder, key = {}, nil, {};
  local done;
  -- Raises at level 3: called, not tail-called, by the mutex function, so
  -- the error names the mutex function's caller.
  local function release (thread)
    if holder ~= thread then
      error("do not have a lock on this mutex", 3);
    end
    nse_destructor("remove", thread, key);
    holder = table.remove(waiting, 1);
    if holder ~= nil then
      nse_destructor("add", holder, key, done);
      nse_restore(holder);
    end
  end
  -- aux_mutex_done: a thread that ends holding the lock releases it.
  done = function (thread) pcall(release, thread) end;
  m = function (op)
    if op == "lock" then
      if holder == nil then
        holder = running();
        nse_destructor("add", holder, key, done);
        return;
      end
      waiting[#waiting+1] = running();
      return nse_yield();
    elseif op == "done" then
      release(running());
      return;
    elseif op == "trylock" then
      if holder == nil then
        holder = running();
        nse_destructor("add", holder, key, done);
        return true;
      end
      return false;
    elseif op == "running" then
      return holder;
    end
    error(("bad argument #1 to '?' (invalid option '%s')"):format(tostring(op)), 2);
  end
  mutexes[object] = m;
  return m;
end

-- nmap.condvar(object): one condition variable per object. A thread that
-- ends wakes every thread waiting on the condition variables it obtained.
local condvars = setmetatable({}, {__mode = "k"});
function nmap.condvar (object)
  local t = type(object);
  if t == "nil" or t == "boolean" or t == "number" then
    error("bad argument #1 to 'nmap.condvar' (object expected)", 2);
  end
  local cv = condvars[object];
  if cv == nil then
    local waiting = {};
    cv = function (op)
      local n;
      if op == "wait" then
        waiting[#waiting+1] = running();
        return nse_yield();
      elseif op == "signal" then
        n = #waiting;
        if n == 0 then n = 1 end
      elseif op == "broadcast" then
        n = 1;
      else
        -- The C's option list has no terminating NULL, so an unknown option
        -- reads past it (nse-condvar-option-overread).
        error(("bad argument #1 to '?' (invalid option '%s')"):format(tostring(op)), 2);
      end
      for i = #waiting, n, -1 do
        local co = waiting[i];
        if type(co) == "thread" then nse_restore(co) end
        waiting[i] = nil;
      end
    end
    condvars[object] = cv;
  end
  nse_destructor("add", running(), cv, function () pcall(cv, "broadcast") end);
  return cv;
end

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
local function table_size (t)
  local n = 0; for _ in pairs(t) do n = n + 1; end return n;
end

local function loadscript (filename)
  local source = "@"..filename;
  local function ld ()
    -- header for scripts to allow setting the environment
    yield [[return function (_ENV) return function (...)]];
    -- actual script
    for line in lines(filename, 2^15) do
      yield(line);
    end
    -- footer...
    yield [[ end end]];
    return nil;
  end
  return assert(load(wrap(ld), source, "t"))();
end

-- recursively copy a table, for host/port tables
-- not very rigorous, but it doesn't need to be
local tcopy = require "tableaux".tcopy

-- copies the host table while preserving the registry
local function host_copy(t)
  local h = tcopy(t)
  h.registry = t.registry
  return h
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

-- >>> nse_main.lua
-- Gets a string containing as much of a host's name, IP, and port as are
-- available.
local function against_name(host, port)
  local targetname, ip, portno, ipport, against;
  if host then
    targetname = host.targetname;
    ip = host.ip;
  end
  if port then
    portno = port.number;
  end
  if ip and portno then
    ipport = ip..":"..portno;
  elseif ip then
    ipport = ip;
  end
  if targetname and ipport then
    against = targetname.." ("..ipport..")";
  elseif targetname then
    against = targetname;
  elseif ipport then
    against = ipport;
  end
  if against then
    return " against "..against
  else
    return ""
  end
end

-- The Script Class, its constructor is Script.new.
local Script = {};
-- The Thread Class, its constructor is Script:new_thread.
local Thread = {};
-- The Worker Class, it's a subclass of Thread. Its constructor is
-- Thread:new_worker. It (currently) has no methods.
local Worker = {};
do
  -- Workers reference data from parent thread.
  function Worker:__index (key)
    return Worker[key] or self.parent[key]
  end

  local function replace(fmt, pattern, repl)
    -- Escape each % twice: once for gsub, and once for print_debug.
    local r = gsub(repl, "%%", "%%%%%%%%")
    return gsub(fmt, pattern, r);
  end
  -- Thread:d()
  -- Outputs debug information at level 1 or higher.
  -- Changes "%THREAD" with an appropriate identifier for the debug level
  function Thread:d (fmt, ...)
    local against = against_name(self.host, self.port);
    local dbg = debugging()
    if dbg > 1 then
      fmt = replace(fmt, "%%THREAD_AGAINST", self.info..against);
      fmt = replace(fmt, "%%THREAD", self.info);
    elseif dbg == 1 then
      fmt = replace(fmt, "%%THREAD_AGAINST", self.short_basename..against);
      fmt = replace(fmt, "%%THREAD", self.short_basename);
    else
      return
    end
    -- debugging() >= 1
    log_write("stdout", format(fmt, ...));
  end

  -- Sets script output. r1 and r2 are the (as many as two) return values.
  function Thread:set_output(r1, r2)
    if not self.worker then
      -- Structure table and unstructured string outputs.
      local tab, str

      if r2 then
        tab, str = r1, tostring(r2);
      elseif type(r1) == "string" then
        tab, str = nil, r1;
      elseif r1 == nil then
        return
      else
        tab, str = r1, nil;
      end

      if self.type == "prerule" or self.type == "postrule" then
        cnse.script_set_output(self.id, tab, str);
      elseif self.type == "hostrule" then
        cnse.host_set_output(self.host, self.id, tab, str);
      elseif self.type == "portrule" then
        cnse.port_set_output(self.host, self.port, self.id, tab, str);
      end
    end
  end

  -- prerule/postrule scripts may be timed out in the future
  -- based on start time and script lifetime?
  function Thread:timed_out ()
    -- checking whether user gave --script-timeout option or not
    if cnse.script_timeout and cnse.script_timeout > 0 and
      -- comparing script's timeout with time elapsed
      cnse.script_timeout < difftime(time(), self.start_time) then
      return true
    end
    if self.host then
      return cnse.timedOut(self.host)
    end
    return false
  end

  function Thread:start_time_out_clock ()
    if self.type == "hostrule" or self.type == "portrule" then
      cnse.startTimeOutClock(self.host);
    end
  end

  function Thread:stop_time_out_clock ()
    if self.type == "hostrule" or self.type == "portrule" then
      cnse.stopTimeOutClock(self.host);
    end
  end

  -- Register scripts in the timeouts list to track their timeouts.
  function Thread:start (timeouts)
    if self.host then
      timeouts[self.host] = timeouts[self.host] or {};
      timeouts[self.host][self.co] = true;
    end
    -- storing script's start time so as to account for script's timeout later
    if self.worker then
      self.start_time = self.parent.start_time
    else
      self.start_time = time()
    end
  end

  -- Remove scripts from the timeouts list and call their
  -- destructor handles.
  function Thread:close (timeouts, result)
    self.error = result;
    if self.host then
      timeouts[self.host][self.co] = nil;
      -- Any more threads running for this script/host?
      if not next(timeouts[self.host]) then
        self:stop_time_out_clock();
        timeouts[self.host] = nil;
      end
    end
    local ch = self.close_handlers;
    for key, destructor_t in pairs(ch) do
      destructor_t.destructor(destructor_t.thread, key);
      ch[key] = nil;
    end
  end

  -- thread = Script:new_thread(rule, ...)
  -- Creates a new thread for the script Script.
  -- Arguments:
  --   rule  The rule argument the rule, hostrule or portrule, tested.
  --   ...   The arguments passed to the rule function (host[, port]).
  -- Returns:
  --   thread  The thread (class) is returned, or nil.
  function Script:new_thread (rule, ...)
    local script_type = assert(NSE_SCRIPT_RULES[rule]);
    if not self[rule] then return nil end -- No rule for this script?

    -- Rebuild the environment for the running thread.
    local env = {
        SCRIPT_PATH = self.filename,
        SCRIPT_NAME = self.short_basename,
        SCRIPT_TYPE = script_type,
    };
    setmetatable(env, {__index = _G});
    local forced = self.forced_to_run;
    local script_closure_generator = self.script_closure_generator;
    local function main (...)
      local _ENV = env; -- change the environment
      -- Load the script's globals in the same Lua thread the action and rule
      -- functions will execute in.
      script_closure_generator(_ENV)();
      if forced or _ENV[rule](...) then
        yield(ACTION_STARTING)
        return action(...)
      end
    end

    local co = create(main);
    local thread = {
      action_started = false,
      args = pack(...),
      close_handlers = {},
      co = co,
      env = env,
      identifier = tostring(co),
      info = format("%s M:%s", self.id, match(tostring(co), "^thread: 0?[xX]?(.*)"));
      parent = nil, -- placeholder
      script = self,
      type = script_type,
      worker = false,
      start_time = 0, --for script timeout
    };
    thread.parent = thread;
    setmetatable(thread, Thread)
    return thread;
  end

  function Thread:new_worker (main, ...)
    local co = create(main);
    print_debug(2, "%s spawning new thread (%s).", self.parent.info, tostring(co));
    local thread = {
      args = pack(...),
      close_handlers = {},
      co = co,
      info = format("%s W:%s", self.id, match(tostring(co), "^thread: 0?[xX]?(.*)"));
      parent = self,
      worker = true,
      start_time = 0,
    };
    setmetatable(thread, Worker)
    local function info ()
      return status(co), rawget(thread, "error");
    end
    return thread, info;
  end

  function Thread:resume (timeouts)
    local ok, r1, r2 = resume(self.co, unpack(self.args, 1, self.args.n));
    local status = status(self.co);
    if ok and r1 == ACTION_STARTING then
      self:d("Starting %THREAD_AGAINST.");
      self.action_started = true
      return self:resume(timeouts);
    elseif not ok then
      -- Extend this to create new types of errors with custom handling.
      -- nmap.new_try does equivalent of: error({errtype="nmap.new_try", message="TIMEOUT"})
      if type(r1) == "table" and r1.errtype == "nmap.new_try" then
        -- nmap.new_try "exception" is closing the script
        if debugging() > 0 then
          self:d("Finished %THREAD_AGAINST. Reason: %s\n", r1.message);
        end
        r1 = r1.message
      elseif debugging() > 0 then
        self:d("%THREAD_AGAINST threw an error!\n%s\n", traceback(self.co, tostring(r1)));
      else
        self:set_output("ERROR: Script execution failed (use -d to debug)");
      end
      self:close(timeouts, r1);
      return false
    elseif status == "suspended" then
      if r1 == NSE_YIELD_VALUE then
        return true
      else
        self:d("%THREAD yielded unexpectedly and cannot be resumed.");
        self:close(timeouts, "yielded unexpectedly and cannot be resumed");
        return false
      end
    elseif status == "dead" then
      if self.action_started then
        self:set_output(r1, r2);
        -- -d1 = report finished scripts. -d2 = report finished threads
        if not self.worker or debugging() > 1 then
          self:d("Finished %THREAD_AGAINST.");
        end
      end
      self:close(timeouts);
    end
  end

  function Thread:__index (key)
    return Thread[key] or self.script[key]
  end

  -- Script.new provides defaults for some of these.
  local required_fields = {
    action = "function",
    categories = "table",
    dependencies = "table",
  };
  local quiet_errors = {
    [REQUIRE_ERROR] = true,
  }

  -- script = Script.new(filename)
  -- Creates a new Script Class for the script.
  -- Arguments:
  --   filename  The filename (path) of the script to load.
  --   script_params  The script selection parameters table.
  --     Possible key/value pairs:
  --       selection: A string to indicate the script selection type.
  --                  "name": Selected by name or pattern.
  --                  "category" Selected by category.
  --                  "file path" Selected by file path.
  --                  "directory" Selected by directory.
  --       verbosity: A boolean, if set to true the script will get a
  --                verbosity boost. Scripts selected by name or
  --                file paths must set this to true.
  --       forced: A boolean to indicate if the script will be
  --               forced to run regardless to its rule results.
  --               (e.g. "+script").
  -- Returns:
  --   script  The script (class) created.
  function Script.new (filename, script_params)
    local script_params = script_params or {};
    assert(type(filename) == "string", "string expected");
    if not find(filename, "%.nse$") then
      log_error(
          "Warning: Loading '%s' -- the recommended file extension is '.nse'.",
          filename);
    end

    local basename = match(filename, "([^/\\]+)$") or filename;
    local short_basename = match(filename, "([^/\\]+)%.nse$") or
        match(filename, "([^/\\]+)%.[^.]*$") or filename;

    print_debug(2, "Script %s was selected by %s%s.",
        basename,
        script_params.selection or "(unknown)",
        script_params.forced and " and forced to run" or "");
    local script_closure_generator = loadscript(filename);
    -- Give the closure its own environment, with global access
    local env = {
      SCRIPT_PATH = filename,
      SCRIPT_NAME = short_basename,
      categories = {},
      dependencies = {},
    };
    setmetatable(env, {__index = _G});
    local script_closure = script_closure_generator(env);
    local co = create(script_closure); -- Create a garbage thread
    local status, e = resume(co); -- Get the globals it loads in env
    if not status then
      if quiet_errors[e] then
        print_verbose(1, "Failed to load '%s'.", filename);
        return nil;
      else
        log_error("Failed to load %s:\n%s", filename, traceback(co, e));
        error("could not load script");
      end
    end
    -- Check that all the required fields were set
    for f, t in pairs(required_fields) do
      local field = rawget(env, f);
      if field == nil then
        error(filename.." is missing required field: '"..f.."'");
      elseif type(field) ~= t then
        error(filename.." field '"..f.."' is of improper type '"..
            type(field).."', expected type '"..t.."'");
      end
    end
    -- Check the required rule functions
    local rules = {}
    for rule in pairs(NSE_SCRIPT_RULES) do
      local rulef = rawget(env, rule);
      assert(type(rulef) == "function" or rulef == nil,
          rule.." must be a function!");
      rules[rule] = rulef;
    end
    assert(next(rules), filename.." is missing required function: 'rule'");
    local prerule = rules.prerule;
    local hostrule = rules.hostrule;
    local portrule = rules.portrule;
    local postrule = rules.postrule;
    -- Assert that categories is an array of strings
    for i, category in ipairs(rawget(env, "categories")) do
      assert(type(category) == "string",
        filename.." has non-string entries in the 'categories' array");
    end
    -- Assert that dependencies is an array of strings
    for i, dependency in ipairs(rawget(env, "dependencies")) do
      assert(type(dependency) == "string",
        filename.." has non-string entries in the 'dependencies' array");
    end
    -- Return the script
    local script = {
      filename = filename,
      basename = basename,
      short_basename = short_basename,
      id = match(filename, "^.-[/\\]([^\\/]-)%.nse$") or short_basename,
      script_closure_generator = script_closure_generator,
      prerule = prerule,
      hostrule = hostrule,
      portrule = portrule,
      postrule = postrule,
      args = {n = 0};
      description = rawget(env, "description"),
      categories = rawget(env, "categories"),
      author = rawget(env, "author"),
      license = rawget(env, "license"),
      dependencies = rawget(env, "dependencies"),
      threads = {},
      -- Make sure that the following are boolean types.
      selected_by_name = not not script_params.verbosity,
      forced_to_run = not not script_params.forced,
    };
    return setmetatable(script, Script)
  end

  Script.__index = Script;
end
-- <<<

-- get_chosen_scripts's last step, after the scripts are loaded: each
-- script's runlevel, one more than the highest of the scripts it depends on.
local function calculate_runlevels (chosen_scripts)
-- >>> nse_main.lua
  -- calculate runlevels
  local name_script = {};
  for i, script in ipairs(chosen_scripts) do
    assert(name_script[script.short_basename] == nil,
      ("duplicate script ID: '%s'"):format(script.short_basename));
    name_script[script.short_basename] = script;
  end
  local chain = {}; -- chain of script names
  local function calculate_runlevel (script)
    chain[#chain+1] = script.short_basename;
    if script.runlevel == false then -- circular dependency
      error("circular dependency in chain `"..concat(chain, "->").."`");
    else
      script.runlevel = false; -- placeholder
    end
    local runlevel = 1;
    for i, dependency in ipairs(script.dependencies) do
      -- yes, use rawget in case we add strong dependencies again
      local s = rawget(name_script, dependency);
      if s then
        local r = tonumber(s.runlevel) or calculate_runlevel(s);
        runlevel = max(runlevel, r+1);
      end
    end
    chain[#chain] = nil;
    script.runlevel = runlevel;
    return runlevel;
  end
  for i, script in ipairs(chosen_scripts) do
    local _ = script.runlevel or calculate_runlevel(script);
  end
-- <<<
end

-- >>> nse_main.lua
-- run(threads)
-- The main loop function for NSE. It handles running all the script threads.
-- Arguments:
--   threads  An array of threads (a runlevel) to run.
local function run (threads_iter)
  -- running scripts may be resumed at any time. waiting scripts are
  -- yielded until Nsock wakes them. After being awakened with
  -- nse_restore, waiting threads become pending and later are moved all
  -- at once back to running. pending is used because we cannot modify
  -- running during traversal.
  local running, waiting, pending = {}, {}, {};
  local all = setmetatable({}, {__mode = "kv"}); -- base coroutine to Thread
  local current; -- The currently running Thread.
  local total = 0; -- Number of threads, for record keeping.
  local timeouts = {}; -- A list to save and to track scripts timeout.
  local num_threads = 0; -- Number of script instances currently running.

  -- Map of yielded threads to the base Thread
  local yielded_base = setmetatable({}, {__mode = "kv"});
  -- _R[YIELD] is called by nse_yield in nse_main.cc
  _R[YIELD] = function (co)
    yielded_base[co] = current; -- set base
    return NSE_YIELD_VALUE; -- return NSE_YIELD_VALUE
  end
  _R[BASE] = function ()
    return current and current.co;
  end
  -- _R[WAITING_TO_RUNNING] is called by nse_restore in nse_main.cc
  _R[WAITING_TO_RUNNING] = function (co, ...)
    local base = yielded_base[co] or all[co]; -- translate to base thread
    if base then
      co = base.co;
      if waiting[co] then -- ignore a thread not waiting
        pending[co], waiting[co] = waiting[co], nil;
        pending[co].args = pack(...);
      end
    end
  end
  -- _R[DESTRUCTOR] is called by nse_destructor in nse_main.cc
  _R[DESTRUCTOR] = function (what, co, key, destructor)
    local thread = yielded_base[co] or all[co] or current;
    if thread then
      local ch = thread.close_handlers;
      if what == "add" then
        ch[key] = {
          thread = co,
          destructor = destructor
        };
      elseif what == "remove" then
        ch[key] = nil;
      end
    end
  end
  _R[SELECTED_BY_NAME] = function()
    return current and current.selected_by_name;
  end
  rawset(stdnse, "new_thread", function (main, ...)
    assert(type(main) == "function", "function expected");
    if current == nil then
      error "stdnse.new_thread can only be run from an active script"
    end
    local worker, info = current:new_worker(main, ...);
    total, all[worker.co], pending[worker.co], num_threads = total+1, worker, worker, num_threads+1;
    worker:start(timeouts);
    return worker.co, info;
  end);

  rawset(stdnse, "base", function ()
    return current and current.co;
  end);
  rawset(stdnse, "gettid", function ()
    return current and current.identifier;
  end);
  rawset(stdnse, "getid", function ()
    return current and current.id;
  end);
  rawset(stdnse, "getinfo", function ()
    return current and current.info;
  end);
  rawset(stdnse, "gethostport", function ()
    if current then
        return current.host, current.port;
    end
  end);
  rawset(stdnse, "isworker", function ()
    return current and current.worker;
  end);

  local progress = cnse.scan_progress_meter(NAME);

  -- Loop while any thread is running or waiting.
  while next(running) or next(waiting) or threads_iter do
    -- Start as many new threads as possible.
    while threads_iter and num_threads < CONCURRENCY_LIMIT do
      local thread = threads_iter()
      if not thread then
        threads_iter = nil;
        break;
      end
      all[thread.co], running[thread.co], total = thread, thread, total+1;
      num_threads = num_threads + 1;
      thread:start(timeouts);
    end

    local nr, nw = table_size(running), table_size(waiting);
    -- total may be 0 if no scripts are running in this phase
    if total > 0 and cnse.key_was_pressed() then
      print_verbose(1, "Active NSE Script Threads: %d (%d waiting)",
          nr+nw, nw);
      progress("printStats", total - (nr+nw), total);
      if debugging() >= 2 then
        for co, thread in pairs(running) do
          thread:d("Running: %THREAD_AGAINST\n\t%s",
              (gsub(traceback(co), "\n", "\n\t")));
        end
        for co, thread in pairs(waiting) do
          thread:d("Waiting: %THREAD_AGAINST\n\t%s",
              (gsub(traceback(co), "\n", "\n\t")));
        end
      elseif debugging() >= 1 then
        local display = {}
        local limit = 0
        for co, thread in pairs(running) do
          local this = display[thread.short_basename]
          if not this then
            this = {}
            limit = limit + 1
            if limit > 5 then
              -- Only print stats if 5 or fewer scripts remaining
              break
            end
          end
          this[1] = (this[1] or 0) + 1
          display[thread.short_basename] = this
        end
        for co, thread in pairs(waiting) do
          local this = display[thread.short_basename]
          if not this then
            this = {}
            limit = limit + 1
            if limit > 5 then
              -- Only print stats if 5 or fewer scripts remaining
              break
            end
          end
          this[2] = (this[2] or 0) + 1
          display[thread.short_basename] = this
        end
        if limit <= 5 then
          for name, stats in pairs(display) do
            print_debug(1, "Script %s: %d threads running, %d threads waiting",
              name, stats[1] or 0, stats[2] or 0)
          end
        end
      end
    elseif total > 0 and progress "mayBePrinted" then
      if verbosity() > 1 or debugging() > 0 then
        progress("printStats", total - (nr+nw), total);
      else
        progress("printStatsIfNecessary", total - (nr+nw), total);
      end
    end

    local orphans = true
    -- Checked for timed-out scripts and hosts.
    for co, thread in pairs(waiting) do
      if thread:timed_out() then
        waiting[co], all[co], num_threads = nil, nil, num_threads-1;
        thread:d("%THREAD_AGAINST timed out")
        thread:close(timeouts, "timed out");
      elseif not thread.worker then
        orphans = false
      end
    end

    for co, thread in pairs(running) do
      current, running[co] = thread, nil;
      thread:start_time_out_clock();

      if thread:resume(timeouts) then
        waiting[co] = thread;
        if not thread.worker then
          orphans = false
        end
      else
        all[co], num_threads = nil, num_threads-1;
      end
      current = nil;
    end

    loop(50); -- Allow nsock to perform any pending callbacks
    -- Move pending threads back to running.
    for co, thread in pairs(pending) do
      pending[co], running[co] = nil, thread;
      if not thread.worker then
        orphans = false
      end
    end

    collectgarbage "step";
    -- If we didn't see at least one non-worker thread, then any remaining are orphaned.
    if num_threads > 0 and orphans then
      print_debug(1, "%d orphans left!", total)
      break
    end
  end

  progress "endTask";
end
-- <<<

-- >>> nse_main.lua
-- This function does the automatic formatting of Lua objects into strings, for
-- normal output and for the XML @output attribute. Each nested table is
-- indented by two spaces. Tables having a __tostring metamethod are converted
-- using tostring. Otherwise, integer keys are listed first and only their
-- value is shown; then string keys are shown prefixed by the key and a colon.
-- Any other kinds of keys. Anything that is not a table is converted to a
-- string with tostring.
local function format_table(obj, indent)
  indent = indent or "  ";
  if type(obj) == "table" then
    local mt = getmetatable(obj)
    if mt and mt["__tostring"] then
      -- Table obeys tostring, so use that.
      return tostring(obj)
    end

    local lines = {};
    -- Do integer keys.
    for _, v in ipairs(obj) do
      lines[#lines + 1] = "\n"
      lines[#lines + 1] = indent
      lines[#lines + 1] = format_table(v, indent .. "  ")
    end
    -- Do string keys.
    for k, v in pairs(obj) do
      if type(k) == "string" then
        lines[#lines + 1] = "\n"
        lines[#lines + 1] = indent
        lines[#lines + 1] = k
        lines[#lines + 1] = ": "
        lines[#lines + 1] = format_table(v, indent .. "  ")
      end
    end
    return concat(lines);
  else
    return tostring(obj);
  end
end
_R[FORMAT_TABLE] = format_table

local format_xml
local function format_xml_elem(obj, key)
  if key then
    key = cnse.protect_xml(tostring(key));
  end
  if type(obj) == "table" then
    cnse.xml_start_tag("table", {key=key});
    cnse.xml_newline();
  else
    cnse.xml_start_tag("elem", {key=key});
  end
  format_xml(obj);
  cnse.xml_end_tag();
  cnse.xml_newline();
end

-- This function writes an XML representation of a Lua object to the XML stream.
function format_xml(obj, key)
  if type(obj) == "table" then
    -- Do integer keys.
    for _, v in ipairs(obj) do
      format_xml_elem(v);
    end
    -- Do string keys.
    for k, v in pairs(obj) do
      if type(k) == "string" then
        format_xml_elem(v, k);
      end
    end
  else
    cnse.xml_write_escaped(cnse.protect_xml(tostring(obj)));
  end
end
_R[FORMAT_XML] = format_xml
-- <<<

-- The scripts chosen by core::nse::engine, loaded by `load_script`.
local chosen_scripts = {};

-- Load one script Rust chose (get_chosen_scripts's selection, done in
-- core::nse::engine): `{path = ..., params = {...}}`, with the script
-- selection parameters `Script.new` takes. Rust calls it once per script, in
-- the order chosen, so that the stall limit bounds each script's load
-- (`nse-stall-limit`); then `scripts_loaded`.
local function load_script (chosen)
  chosen_scripts[#chosen_scripts+1] = Script.new(chosen.path, chosen.params);
end

-- The scripts are loaded: compute their runlevels.
local function scripts_loaded ()
  calculate_runlevels(chosen_scripts);
-- >>> nse_main.lua
print_verbose(1, "Loaded %d scripts for scanning.", #chosen_scripts);
for i, script in ipairs(chosen_scripts) do
  print_debug(2, "Loaded '%s'.", script.filename);
end
-- <<<
end

-- >>> nse_main.lua
-- This iterator is passed to the run function. It returns one new script
-- thread on demand until exhausted.
local threads_iters = {
  NSE_PRE_SCAN = function (hosts, scripts)
    return function () -- threads_iter
      for _, script in ipairs(scripts) do
        local thread = script:new_thread("prerule");
        if thread then
          yield(thread)
        end
      end
    end
  end,
  NSE_SCAN = function (hosts, scripts)
    return function () -- threads_iter
      -- Check hostrules for this host.
      for j, host in ipairs(hosts) do
        for _, script in ipairs(scripts) do
          local thread = script:new_thread("hostrule", host_copy(host));
          if thread then
            thread.host = host;
            yield(thread);
          end
        end
        -- Check portrules for this host.
        for port in cnse.ports(host) do
          for _, script in ipairs(scripts) do
            local thread = script:new_thread("portrule", host_copy(host), tcopy(port));
            if thread then
              thread.host, thread.port = host, port;
              yield(thread);
            end
          end
        end
      end
    end
  end,
  NSE_POST_SCAN = function (hosts, scripts)
    return function () -- threads_iter
      for _, script in ipairs(scripts) do
        local thread = script:new_thread("postrule");
        if thread then
          yield(thread);
        end
      end
    end
  end,
}
-- <<<

-- >>> nse_main.lua
-- main(hosts)
-- This is the main function we return to NSE (on the C side), nse_main.cc
-- gets this function by loading and executing nse_main.lua. This
-- function runs a script scan phase according to its arguments.
-- Arguments:
--   hosts  An array of hosts to scan.
--   scantype A string that indicates the current script scan phase.
--    Possible string values are:
--      "SCRIPT_PRE_SCAN"
--      "SCRIPT_SCAN"
--      "SCRIPT_POST_SCAN"
local function main (hosts, scantype)
  -- Used to set up the runlevels.
  local threads, runlevels = {}, {};

  -- Every script thread has a table that is used in the run function
  -- (the main loop of NSE).
  -- This is the list of the thread table key/value pairs:
  --  Key     Value
  --  type    A string that indicates the rule type of the script.
  --  co      A thread object to identify the coroutine.
  --  parent  A table that contains the parent thread table (it self).
  --  close_handlers
  --          A table that contains the thread destructor handlers.
  --  info    A string that contains the script name and the thread
  --            debug information.
  --  args    A table that contains the arguments passed to scripts,
  --            arguments can be host and port tables.
  --  env     A table that contains the global script environment:
  --            categories, description, author, license, nmap table,
  --            action function, rule functions, SCRIPT_PATH,
  --            SCRIPT_NAME, SCRIPT_TYPE (pre|host|port|post rule).
  --  identifier
  --          A string to identify the thread address.
  --  host    A table that contains the target host information. This
  --          will be nil for Pre-scanning and Post-scanning scripts.
  --  port    A table that contains the target port information. This
  --          will be nil for Pre-scanning and Post-scanning scripts.

  local runlevels = {};
  for i, script in ipairs(chosen_scripts) do
    runlevels[script.runlevel] = runlevels[script.runlevel] or {};
    insert(runlevels[script.runlevel], script);
  end

  if _R[PARALLELISM] > CONCURRENCY_LIMIT then
    CONCURRENCY_LIMIT = _R[PARALLELISM];
  end

  if scantype == NSE_PRE_SCAN then
    print_verbose(1, "Script Pre-scanning.");
  elseif scantype == NSE_SCAN then
    if #hosts > 1 then
      print_verbose(1, "Script scanning %d hosts.", #hosts);
    elseif #hosts == 1 then
      print_verbose(1, "Script scanning %s.", hosts[1].ip);
    end
  elseif scantype == NSE_POST_SCAN then
    print_verbose(1, "Script Post-scanning.");
  end

  for runlevel, scripts in ipairs(runlevels) do
    local threads_iter = assert(threads_iters[scantype](hosts, scripts))
    print_verbose(2, "Starting runlevel %u (of %u) scan.", runlevel, #runlevels);
    run(wrap(threads_iter))
  end

  collectgarbage "collect";
end
-- <<<

-- `_R[PARALLELISM]`, which init_main sets to --min-parallelism.
_R[PARALLELISM] = cnse.min_parallelism;

-- What ScriptResult::get_output_str and ::write_xml (nse_main.cc) read out of
-- a result, for each result the phase stored: its text, by FORMAT_TABLE when
-- it gave only a table, and the XML its table writes by FORMAT_XML. Each is
-- handed to `cnse.rendered`, with nil where there is none.
local function render (results)
  for i, result in ipairs(results) do
    local str = result.str;
    if type(str) ~= "string" then
      str = nil;
      if result.tab ~= nil then
        local ok, s = pcall(format_table, result.tab);
        if ok then
          str = s;
        elseif debugging() > 0 then
          log_write("stdout", "Error in FORMAT_TABLE: "..tostring(s));
        end
      end
    end
    local xml;
    if result.tab ~= nil then
      cnse.xml_begin();
      local ok, e = pcall(format_xml, result.tab);
      if not ok and debugging() > 0 then
        log_write("stdout", "Error in FORMAT_XML: "..tostring(e));
      end
      xml = cnse.xml_end();
    end
    cnse.rendered(i, str, xml);
  end
end

-- What the engine itself needs from here on.
return {
  NSE_YIELD_VALUE = NSE_YIELD_VALUE,
  REQUIRE_ERROR = REQUIRE_ERROR,
  print_verbose = print_verbose,
  print_debug = print_debug,
  log_error = log_error,
  load_script = load_script,
  scripts_loaded = scripts_loaded,
  main = main,
  render = render,
}
