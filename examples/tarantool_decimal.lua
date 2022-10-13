--[[
"decimal.scale"
"decimal.new"
"decimal.log10"
"decimal.rescale"
"decimal.ln"
"decimal.round"
"decimal.is_decimal"
"decimal.exp"
"decimal.trim"
"decimal.abs"
"decimal.precision"
"decimal.sqrt"
]]

local luzer = require("luzer")
local decimal = require("decimal")

local function TestOneInput(buf)
    local ok, res = pcall(decimal.new, buf)
    if ok == false then
	    return
    end
    assert(res ~= nil)
    assert(decimal.is_decimal(res) == true)
    assert(res - res == 0)
end

local args = {
    max_len = 4096,
}
luzer.Fuzz(TestOneInput, nil, args)
