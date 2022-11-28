-- https://github.com/tarantool/tarantool/issues/6781

local luzer = require("luzer")
local net_box = require("net.box")

local function TestOneInput(buf)
    os.execute("rm -f *.snap")
    box.cfg{
        listen = 3303,
    }
    local conn = net_box.connect("3303")
	pcall(conn.call, conn, buf)
end

if arg[1] then
    local fh = io.open(arg[1])
    local testcase = fh:read("*all")
    TestOneInput(testcase)
    os.exit(0)
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 4096,
    corpus = script_path .. "tarantool-corpus/net_box_call",
    print_pcs = 1,
    artifact_prefix = "net_box_call_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
