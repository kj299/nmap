description = "Coroutines inside a script, through NSE's resume and wrap."
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host)
  local gen = coroutine.wrap(function() for i = 1, 3 do coroutine.yield(i) end end)
  local co = coroutine.create(function(a) local b = coroutine.yield(a + 1) return b * 2 end)
  local _, x = coroutine.resume(co, 1)
  local _, y = coroutine.resume(co, 10)
  return ("%d %d %d %d %d %s"):format(gen(), gen(), gen(), x, y, coroutine.status(co))
end
