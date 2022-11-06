local pickle = require("pickle")
local luzer = require("luzer")

local function TestOneInput(buf)
    local ok, unpacked = pcall(pickle.unpack, buf)
    if ok == true then
        local packed = pickle.pack(unpacked)
        assert(#packed == #buf)
    end
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    max_len = 4096,
    artifact_prefix = "tarantool_pickle_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
