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

local args = {
    max_len = 4096,
    only_ascii = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
