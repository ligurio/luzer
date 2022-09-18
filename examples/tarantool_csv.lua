local csv = require("csv")
local luzer = require("luzer")

-- "csv.dump"
-- "csv.iterate"

local function TestOneInput(buf)
    local ok, res = pcall(csv.load, buf)
    if ok == true then
        assert(res ~= nil)
    end
end

local arg1 = {"-max_len=4096", "-max_len=4096", "-only_ascii=1", "corpus/"}
luzer.Setup(arg1, TestOneInput)
luzer.Fuzz()
