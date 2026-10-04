description = "Script arguments."
categories = {"args"}
local stdnse = require "stdnse"
prerule = function() return true end
action = function()
  local a, b = stdnse.get_script_args("s-args.a", "b")
  return ("a=%s b=%s %s %s"):format(tostring(a), type(b), type(b) == "table" and b[1] or "-", type(b) == "table" and b[2] or "-")
end
