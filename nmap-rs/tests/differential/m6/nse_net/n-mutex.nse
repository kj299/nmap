description = "Workers holding a mutex across a sleep never interleave."
categories = {"net"}
local nmap = require "nmap"
local stdnse = require "stdnse"
prerule = function() return true end
local function show(...) local t = table.pack(...) for i = 1, t.n do t[i] = tostring(t[i]) end return table.concat(t, ",") end
action = function()
  local log = {}
  local m = nmap.mutex("n-mutex")
  local cv = nmap.condvar(log)
  local done = 0
  for i = 1, 3 do
    stdnse.new_thread(function()
      m "lock"
      log[#log+1] = "in" .. i
      stdnse.sleep(0.05)
      log[#log+1] = "out" .. i
      m "done"
      done = done + 1
      cv "signal"
    end)
  end
  while done < 3 do cv "wait" end
  local pairs_ok = true
  for k = 1, #log, 2 do
    if log[k]:sub(3) ~= log[k+1]:sub(4) then pairs_ok = false end
  end
  local tl = m "trylock"
  local running = m "running" ~= nil
  m "done"
  return "nested " .. tostring(pairs_ok) .. " entries " .. #log .. " trylock " .. tostring(tl) ..
    " running " .. tostring(running) .. " same " .. tostring(nmap.mutex("n-mutex") == m) ..
    " notheld " .. show(pcall(m, "done")) .. " badobj " .. show(pcall(nmap.mutex, 5))
end
