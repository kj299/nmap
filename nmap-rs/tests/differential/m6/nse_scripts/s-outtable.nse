description = "stdnse.output_table keeps insertion order."
categories = {"shapes"}
local stdnse = require "stdnse"
hostrule = function(host) return true end
action = function(host)
  local o = stdnse.output_table()
  o.zebra = "z"
  o.apple = "a"
  local inner = stdnse.output_table()
  inner.second = 2
  inner.first = 1
  o.inner = inner
  o.mango = {"m1", "m2"}
  return o
end
