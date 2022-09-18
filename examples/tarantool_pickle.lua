local pickle = require("pickle")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, res = pcall(pickle.unpack, buf)
    if ok == true then
        local b
        ok, b = pcall(pickle.pack, buf)
	assert(ok == true)
        assert(#b == #buf)
        assert(b == buf)
    end
end

local arg1 = { "-max_len=4096", "-max_len=4096", "-only_ascii=1", "./corpus/" }

luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
