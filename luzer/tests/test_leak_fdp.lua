local luzer = require("luzer")

-- Every call allocates a FuzzedDataProvider object. Lua uses the
-- GC-based memory management model, so the object can stay allocated
-- between TestOneInput() calls and be reported by LeakSanitizer as a
-- memory leak, see https://github.com/ligurio/luzer/issues/52.
local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    fdp:consume_string(1)
end

local opts = { runs = 100 }
luzer.Fuzz(TestOneInput, nil, opts)
