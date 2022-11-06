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

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 4096,
    corpus = script_path .. "tarantool_decimal",
    print_pcs = 1,
    detect_leaks = 1,
    artifact_prefix = "tarantool_decimal_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
