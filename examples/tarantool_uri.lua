local uri = require("uri")
local luzer = require("luzer")

-- "uri.parse_many"
-- "uri.format"

local function TestOneInput(buf)
    uri.parse(buf)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    only_ascii = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
