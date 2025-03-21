local luac = require("luac")
local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local max_len = fdp:consume_integer(1, 100)
    local str = fdp:consume_string(max_len)
    luac.say_hello(str)
end

luzer.Fuzz(TestOneInput, nil, {})
