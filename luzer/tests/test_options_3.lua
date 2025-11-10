local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    local str_chars = {}
    str:gsub(".", function(c) table.insert(str_chars, c) end)
end

luzer.Fuzz(TestOneInput)
