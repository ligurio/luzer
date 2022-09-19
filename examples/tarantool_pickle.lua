local pickle = require("pickle")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, unpacked = pcall(pickle.unpack, buf)
    if ok == true then
        local packed
        ok, packed = pcall(pickle.pack, unpacked)
	assert(ok == true)
        assert(#packed == #buf)
    end
end

local arg1 = { "-max_len=4096", "-max_len=4096", "-only_ascii=1", "./corpus/" }

luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
