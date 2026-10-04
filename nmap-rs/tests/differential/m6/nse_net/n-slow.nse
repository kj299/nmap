description = "Sleeps past --script-timeout: timed out, no output."
categories = {"slow"}
local stdnse = require "stdnse"
prerule = function() return true end
action = function() stdnse.sleep(5) return "should have timed out" end
