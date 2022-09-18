local luzer = require("luzer")
local dt = require("datetime")

local function TestOneInput(buf, _size)
    local ok, res = pcall(dt.parse, buf)
    if ok == true then
        assert(res ~= nil)
    end
end

local arg1 = {"-max_len=4096", "-max_len=4096", "-only_ascii=1", "corpus/"}
luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
