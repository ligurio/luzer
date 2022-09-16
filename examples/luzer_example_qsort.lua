-- qsort_arg
-- https://github.com/tarantool/tarantool/pull/7610

local luzer = require("luzer")
local has_ffi, ffi = pcall(require, "ffi")

if not has_ffi then
    print("ffi is not found")
    os.exit(1)
end

ffi.cdef[[
void qsort(void *base, size_t nel, size_t width, int (*compar)(const void *, const void *));
]]

local function cmp(a, b)
    return a[0] - b[0]
end

local cmp_cb = ffi.cast("int (*)(const char *, const char *)", cmp)

local function TestOneInput(buf, size)
    local bytes = ffi.new(("char[%s]"):format(size))
    ffi.copy(bytes, buf, size)
    ffi.C.qsort(bytes, size, 1, cmp_cb)
    collectgarbage()
end

local arg1 = {"-max_len=4096", "-max_len=4096"}
luzer.Setup(arg1, TestOneInput)

luzer.Fuzz()
