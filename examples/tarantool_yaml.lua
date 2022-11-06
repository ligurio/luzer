-- https://github.com/tarantool/tarantool/issues/4773 \x36\x00\x80

local yaml = require("yaml")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(yaml.decode, buf)
    if ok == false then
        return
    end
    yaml.encode(res)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 128,
    dict = script_path .. "tarantool_yaml.dict",
    corpus = script_path .. "tarantool_yaml",
    print_pcs = 1,
    artifact_prefix = "tarantool_yaml_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
