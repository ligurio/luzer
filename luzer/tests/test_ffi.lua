local luzer = require("luzer")
local has_ffi, ffi = pcall(require, "ffi")
if not has_ffi then
    io.stderr:write("FFI is not supported\n")
    os.exit(0)
end

ffi.cdef[[
int say_hello(const char *buf, size_t len);
]]

local lib_name = os.getenv("FFI_LIB_NAME")
local testlib = ffi.load(lib_name)

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local max_len = fdp:consume_integer(1, 100)
    local str = fdp:consume_string(max_len)
    testlib.say_hello(str, #str + 1)
end

luzer.Fuzz(TestOneInput, nil, {})
