local luzer = require("luzer")
local has_ffi, ffi = pcall(require, "ffi")
if not has_ffi then
    io.stderr:write("FFI is not supported\n")
    os.exit(0)
end

ffi.cdef[[
int say_hello(const char *buf);
]]

local testlib = ffi.load("testlib.so")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local max_len = fdp:consume_integer(1, 100)
    local str = fdp:consume_string(max_len)
    testlib.say_hello(str)
end

luzer.Fuzz(TestOneInput, nil, {})
