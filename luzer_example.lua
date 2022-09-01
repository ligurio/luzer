local luzer = require("luzer")
local math = luzer.require_instrument("math")

local function custom_mutator(data, max_size, seed)
    print(data, max_size, seed)
    return data .. "xxx"
end

local function TestOneInput(data)
    -- The entry point for our fuzzer.
    --
    -- This is a callback that will be repeatedly invoked with different
    -- arguments after Fuzz() is called.
    --
    -- We translate the arbitrary byte string into a format our function being
    -- fuzzed can understand, then call it.
    --
    -- Args:
    --    data: string coming from the fuzzing engine.

    local fdp = luzer.FuzzedDataProvider(data)
    print(fdp.consume_string())
    print(fdp.consume_boolean())

    return
end

local res
if #arg > 1 and arg[1] == "--no_mutator" then
    res = luzer.Setup(arg, TestOneInput, custom_mutator)
else
    res = luzer.Setup(arg, TestOneInput)
end
assert(res == true)

luzer.Fuzz()
