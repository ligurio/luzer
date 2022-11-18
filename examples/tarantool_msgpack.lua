--[[
https://github.com/tarantool/tarantool/issues/5184
https://github.com/tarantool/tarantool/issues/4724
https://github.com/tarantool/tarantool/issues/3900
https://github.com/tarantool/tarantool/issues/5014 "\xd4\x02\x00"
https://github.com/tarantool/tarantool/issues/5016 "\xd4\xfe\x00"
https://github.com/tarantool/tarantool/issues/5017 "\xd4\x0f\x00"
https://github.com/tarantool/tarantool/issues/206

https://www.tarantool.io/ru/doc/latest/reference/reference_lua/msgpack/
]]

local msgpack = require("msgpack")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(msgpack.decode, buf)
    if ok == true then
        ok, res = pcall(msgpack.encode, res)
        if ok == false and
           string.find(res, "Too high nest level") then
            return -1
        end
        assert(ok == true)
        assert(res ~= nil)
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
    corpus = script_path .. "tarantool-corpus/tarantool_msgpack",
    dict = script_path .. "tarantool-corpus/tarantool_msgpack.dict",
    max_len = 4096,
    artifact_prefix = "tarantool_msgpack_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
