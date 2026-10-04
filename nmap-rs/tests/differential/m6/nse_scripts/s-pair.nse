description = "A table and a string: the string is the text."
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host) return {k = "v", "item"}, "explicit string" end
