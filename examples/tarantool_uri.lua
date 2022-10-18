local uri = require("uri")
local luzer = require("luzer")

local function TestOneInput(buf)
    local url = uri.parse(buf)
    if type(url) == "table" and
        url ~= nil then
        local str = uri.format(url)
        assert(str)
    end
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
