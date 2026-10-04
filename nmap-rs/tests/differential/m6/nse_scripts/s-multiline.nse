description = "Several lines, an empty one, a trailing newline."
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host) return "a\nb\n\nc\n" end
