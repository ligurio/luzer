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
    ffi.C.qsort(bytes, size, 10, cmp_cb)
    local sorted = ffi.string(bytes, ffi.sizeof(bytes))

    assert(#sorted == #buf)

    -- local t = {}
    -- buf:gsub(".", function(c) table.insert(t, c) end)
    -- table.sort(t, cmp)
    -- print(buf, b)
    -- assert(#buf == #b)
end

local args = {
    max_len = 4096,
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
