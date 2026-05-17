local key = "value"
local object = {
  value = 9,
  nested = {
    value = 4,
  },
}

local total = object[key] + object.nested[key]
object[key] = total + 3
object["nested"][key] = object[key] - 2

print("computed:" .. tostring(object.value) .. ":" .. tostring(object.nested.value))
