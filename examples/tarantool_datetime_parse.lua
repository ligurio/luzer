local luzer = require("luzer")
local dt = require("datetime")

local function TestOneInput(buf, _size)
    local ok, res = pcall(dt.parse, buf)
    if ok == true then
        assert(res ~= nil)
    end
end

local args = {
    max_len = 4096,
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
