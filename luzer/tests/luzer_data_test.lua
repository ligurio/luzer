local luzer = require("luzer")

local function TestOneInput(buf)
    local str = [[
Twas brillig, and the slithy toves
Did gyre and gimble in the wabe:
All mimsy were the borogoves,
And the mome raths outgrabe.]]

    local len = #str
    local fdp = luzer.FuzzedDataProvider(buf)
    assert(fdp:remaining_bytes() < len)
    local b = fdp:consume_string(len)
    if b == str then assert(nil) end
end

luzer.Fuzz(TestOneInput)
