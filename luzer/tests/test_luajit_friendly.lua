local luzer = require("luzer")

local chunk = [[
local function fib(n)
  if n <= 1 then
      return n
  end
  return fib(n - 1) + fib(n - 2)
end
]]

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local numbers = fdp:consume_numbers(0, 2*10^6, 10)
    for _, n in ipairs(numbers) do
        if n == 100500 then
            assert("Bingo!")
        end
    end

    -- Needed for testing LuaJIT metric with aborted traces.
    if fdp:consume_boolean() then
        math.randomseed(0)
    end

    -- Needed for testing LuaJIT metric with parsed functions.
    load(chunk)
end

local args = {
    print_pcs = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
