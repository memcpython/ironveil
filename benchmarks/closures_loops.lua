local function makeCounter(seed)
  local state = seed
  return function(step)
    state = state + step
    return state
  end
end

local counter = makeCounter(10)
local sum = 0

for index = 1, 5 do
  sum = sum + counter(index)
end

local cursor = 1
while cursor <= 3 do
  sum = sum + cursor
  cursor = cursor + 1
end

repeat
  sum = sum - 1
until sum % 7 == 0

print("closures_loops:" .. tostring(sum))
