local csv = require("csv")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(csv.load, buf)
    if ok == true then
        assert(res ~= nil)
    end
	ok, res = pcall(csv.dump, res)
	assert(ok == true)
	assert(res)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    dict = script_path .. "tarantool_csv.dict",
    corpus = script_path .. "tarantool_csv",
}
luzer.Fuzz(TestOneInput, nil, args)
