local luzer = require("luzer")

local MAGIC_STR = "MAGIC STRING"

local function trace_func(_, line_n)
    local src_path = debug.getinfo(2).short_src
    io.stderr:write(("%s:%d\n"):format(src_path, line_n))
end

debug.sethook(trace_func, "l")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local max_len = fdp:consume_integer(0, #MAGIC_STR)
    local str = fdp:consume_string(max_len)
    if str == MAGIC_STR then
        assert(nil, "assert has triggered")
    end
end

luzer.Fuzz(TestOneInput)
