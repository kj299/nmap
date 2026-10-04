description = "Bytes that need escaping, in text and in keys."
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host)
  return {["k<&\"'>"] = "v\0\1\r\t\127\128\255 -- --- \"q\" 'a' <b> &c;", "\27[31mred\27[0m"},
    "text \0\1\2\r\t\127\128\255 -- --- <&>\"'"
end
