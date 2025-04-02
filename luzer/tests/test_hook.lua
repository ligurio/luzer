local luzer = require("luzer")

local function trace(_, line)
    local src_path = debug.getinfo(2).short_src
    print(src_path .. ":" .. line)
end

debug.sethook(trace, "l")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local magic_str = "MAGIC STRING"
    local max_len = fdp:consume_integer(0, #magic_str)
    local str = fdp:consume_string(max_len)
    if str == magic_str then
		assert(nil, "assert has triggered")
    end
end

local opts = {
    max_len = 4096,
}
luzer.Fuzz(TestOneInput, nil, opts)
