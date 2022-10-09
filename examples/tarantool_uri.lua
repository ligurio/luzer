local uri = require("uri")
local luzer = require("luzer")

-- "uri.parse_many"
-- "uri.format"

local function TestOneInput(buf)
    uri.parse(buf)
end

local args = {
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
