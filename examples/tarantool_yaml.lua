local yaml = require("yaml")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(yaml.decode, buf)
    if ok == false then
        return
    end
    local encoded = yaml.encode(res)
    assert(#encoded == #buf)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    dict = script_path .. "tarantool_yaml.dict",
    max_len = 1024,
}
luzer.Fuzz(TestOneInput, nil, args)
