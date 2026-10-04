description = "silent_require of a missing library: skipped quietly."
categories = {"bad"}
local stdnse = require "stdnse"
local missing = stdnse.silent_require "no_such_library_anywhere"
prerule = function() return true end
action = function() return "x" end
