local function collect(...)
  local packed = { ... }
  local out = {}

  for index = 1, #packed do
    out[index] = tostring(packed[index])
  end

  return table.concat(out, "|"), #packed
end

local function wrap(...)
  local joined, count = collect(...)
  return joined .. "#" .. tostring(count)
end

print(wrap("x", 12, true, nil, "tail"))
