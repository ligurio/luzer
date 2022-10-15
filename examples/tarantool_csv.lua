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

local args = {
    dict = "/home/sergeyb/sources/luzer/examples/tarantool_csv.dict",
    corpus = "/home/sergeyb/sources/luzer/examples/tarantool_csv",
}
luzer.Fuzz(TestOneInput, nil, args)
