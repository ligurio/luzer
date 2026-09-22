local luzer = require("luzer")

-- LuaJIT allocates memory for a JIT compiler state (in particular, an
-- IR buffer) when a trace is being recorded. The test triggers trace
-- recording and checks that LeakSanitizer does not report the memory
-- allocated for the compiler state, see
-- https://github.com/ligurio/luzer/issues/85.
local function TestOneInput(buf)
    local sum = 0
    for i = 1, #buf % 16 + 2 do
        sum = sum + i
    end
end

luzer.Fuzz(TestOneInput)
