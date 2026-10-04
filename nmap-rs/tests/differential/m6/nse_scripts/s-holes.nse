description = "A list with a hole, and keys that are not strings."
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host)
  return {1, nil, 3, [5] = "five", [1.5] = "x", [true] = "t", s = "str"}
end
