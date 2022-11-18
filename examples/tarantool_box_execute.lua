-- https://github.com/tarantool/tarantool/issues/3866
-- https://github.com/tarantool/tarantool/issues/3861

local luzer = require("luzer")

local function TestOneInput(buf)
    os.execute("rm -f *.snap")
    require("fiber").sleep(0.1)
    box.cfg{}
    box.execute(buf)
end

if arg[1] then
    local fh = io.open(arg[1])
    local testcase = fh:read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 4096,
    corpus = script_path .. "tarantool-corpus/tarantool_box_execute",
    print_pcs = 1,
    print_final_stats = 1,
    artifact_prefix = "tarantool_box_execute_",
    max_total_time = 60,
}
luzer.Fuzz(TestOneInput, nil, args)
