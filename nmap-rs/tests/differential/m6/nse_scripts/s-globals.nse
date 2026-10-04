description = "The globals a script is given."
categories = {"shapes"}
prerule = function() return true end
action = function()
  return SCRIPT_NAME .. " " .. SCRIPT_TYPE .. " " .. SCRIPT_PATH:match("[^/]*$")
end
