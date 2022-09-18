-- https://github.com/tarantool/tarantool/issues/5014
require('msgpack').decode('\xd4\x02\x00')
-- https://github.com/tarantool/tarantool/issues/5016
require('msgpack').decode('\xd4\xfe\x00')
-- https://github.com/tarantool/tarantool/issues/5017
require('msgpack').decode('\xd4\x0f\x00')
-- https://github.com/tarantool/tarantool/issues/206

local msgpack = require("msgpack")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(msgpack.decode, buf)
    if ok == true then
        local b
        ok, b = pcall(msgpack.encode, res)
	assert(ok == true)
        assert(#b == #buf)
        assert(b == buf)
    end
end

local arg1 = { "-max_len=4096", "-max_len=4096", "-only_ascii=1", "./corpus/" }

luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
