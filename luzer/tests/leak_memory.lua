local luzer = require("luzer")

local leaky_cache = {} -- luacheck: no unused

-- Function to create a large, nested table.
local function make_big_object(size)
    if size <= 0 then
        return {}
    end
    -- Create nested tables recursively.
    return {
        make_big_object(size - 1)
    }
end

-- Accumulates objects in a global cache without releasing them.
-- libFuzzer's per-mutation leak detection is disabled by default,
-- so a real leak should be detected as out-of-memory (issue #52).
local function TestOneInput(_buf)
    local new_object = make_big_object(2)
    table.insert(leaky_cache, new_object)
end

luzer.Fuzz(TestOneInput)
