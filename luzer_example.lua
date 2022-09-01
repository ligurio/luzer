local luzer = require("luzer")
local _ = luzer.require_instrument("math")

local function custom_mutator(data, max_size, seed)
    print(data, max_size, seed)
    return data .. "xxx"
end

local function TestOneInput(data, _)
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

    local _ = luzer.FuzzedDataProvider(data)
    --fdp.consume_string()
    --fdp.consume_boolean()

    local b = {}
    buf:gsub(".", function(c) table.insert(b, c) end)
    if b[1] == 'c' then
        if b[2] == 'r' then
            if b[3] == 'a' then
                if b[4] == 's' then
                    if b[5] == 'h' then
                        assert(nil)
                    end
                end
            end
        end
    end

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
