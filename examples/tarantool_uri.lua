local uri = require("uri")
local luzer = require("luzer")

-- "uri.parse_many"
-- "uri.format"
-- "uri.parse"

local function TestOneInput(data)
    local res = uri.parse(data)
    assert(res ~= nil)
end

local args = {
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
