local datetime = require("datetime")
local luzer = require("luzer")

local function TestOneInput(buf)
    datetime.parse(buf)
end

if arg[1] then
    local fh = io.open(arg[1])
    local testcase = fh:read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    detect_leaks = 1,
    print_pcs = 1,
    corpus = script_path .. "tarantool-corpus/datetime_parse",
    artifact_prefix = "datetime_parse_",
    max_len = 2048,
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
