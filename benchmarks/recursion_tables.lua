local function fib(n)
  if n < 2 then
    return n
  end

  return fib(n - 1) + fib(n - 2)
end

local items = {
  alpha = fib(6),
  beta = fib(7),
}

local total = 0
for _, value in pairs(items) do
  total = total + value
end

print("fibsum:" .. tostring(total))
