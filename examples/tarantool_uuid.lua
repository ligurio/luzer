-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/uuid/

local uuid = require("uuid")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(uuid.frombin, buf)
    if ok == true then
        assert(res ~= nil)
        assert(uuid.is_uuid(res))
        assert(res:str())
    end
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    print_pcs = 1,
    max_len = 1024,
    corpus = script_path .. "tarantool_uuid",
    artifact_prefix = "tarantool_uuid_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
