description = "A table with __tostring: its text, but its XML from its contents."
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host)
  return setmetatable({"inside", k = "v"}, {__tostring = function() return "custom text" end})
end
