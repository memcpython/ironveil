local state = {
  score = 17,
  floor = 12,
  flags = {
    open = true,
  },
}

local output

if state.score > state.floor then
  output = "gt"
else
  output = "le"
end

if state.flags.open ~= false then
  output = output .. ":open"
end

if not (state.score <= 10) then
  output = output .. ":high"
end

print(output)
