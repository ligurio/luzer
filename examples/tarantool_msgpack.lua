[[
https://github.com/tarantool/tarantool/issues/206
https://github.com/tarantool/tarantool/issues/5184
https://github.com/tarantool/tarantool/issues/5017
https://github.com/tarantool/tarantool/issues/5016
https://github.com/tarantool/tarantool/issues/5014
https://github.com/tarantool/tarantool/issues/4724
https://github.com/tarantool/tarantool/issues/3900

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
            return
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

local args = {
    max_len = 4096,
}
luzer.Fuzz(TestOneInput, nil, args)
