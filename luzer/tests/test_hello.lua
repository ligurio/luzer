local hello = require("hello")
local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local len = fdp:consume_integer(1, 100)
    local str = fdp:consume_string(len)
    hello.say_hello(str)
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
