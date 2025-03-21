local luzer = require("luzer")
local has_ffi, ffi = pcall(require, "ffi")
if not has_ffi then
    os.exit(0)
end

ffi.cdef[[
int say_goodbye(const char *buf);
]]

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local len = fdp:consume_integer(1, 100)
    local str = fdp:consume_string(len)
    local libgoodbye = ffi.load("./build/luzer/tests/libgoodbye.so")
    libgoodbye.say_goodbye(str)
end

local opts = {
    detect_leaks = 1,
    max_len = 4096,
    only_ascii = 1,
    print_coverage = 1,
    print_full_coverage = 1,
    print_pcs = 1,
    use_cmp = 1,
    use_value_profile = 1,
    runs = 100000,
}
luzer.Fuzz(TestOneInput, nil, opts)
