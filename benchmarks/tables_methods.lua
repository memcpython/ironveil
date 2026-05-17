local object = {
  label = "bench",
  values = { 2, 4, 6, 8 },
}

function object:mix(prefix, suffix)
  local joined = {}
  for index = 1, #self.values do
    joined[index] = self.values[index] * index
  end

  local total = 0
  for _, value in ipairs(joined) do
    total = total + value
  end

  return prefix .. ":" .. self.label .. ":" .. tostring(total) .. ":" .. suffix
end

print(object:mix("ok", "done"))
