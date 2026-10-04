description = "A table: list items first, then string keys. (One string key per\nlevel: Lua orders string keys by hash, run to run.)"
categories = {"shapes"}
hostrule = function(host) return true end
action = function(host)
  return {"first", "second", {1, 2, {3}}, deep = {"d", x = {y = {z = "w"}}}}
end
