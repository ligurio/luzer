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

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 1024,
    only_ascii = 1,
    corpus = script_path .. "tarantool_uri",
}
luzer.Fuzz(TestOneInput, nil, args)
