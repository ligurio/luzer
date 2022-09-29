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

local args = {
    max_len = 4096,
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
