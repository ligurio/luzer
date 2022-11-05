--[[

6.9 – Operating System Facilities
https://www.lua.org/manual/5.3/manual.html#6.9

PUC Rio Lua bugs: https://www.lua.org/bugs.html

]]


local luzer = require("luzer")

local function TestOneInput(buf)
    local str = os.date(buf)
    assert(str)
    -- os.difftime(t2, t1)
    -- os.time([table])
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    only_ascii = 1,
    max_len = 1024,
}
luzer.Fuzz(TestOneInput, nil, args)
