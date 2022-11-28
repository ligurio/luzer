--[[

6.4 – String Manipulation
https://www.lua.org/manual/5.3/manual.html#6.4

LuaJIT bugs:

- https://github.com/LuaJIT/LuaJIT/issues/300
- https://github.com/LuaJIT/LuaJIT/issues/378
- https://github.com/LuaJIT/LuaJIT/issues/375
- https://github.com/LuaJIT/LuaJIT/issues/505
- https://github.com/LuaJIT/LuaJIT/issues/118
- https://github.com/LuaJIT/LuaJIT/issues/784
- https://github.com/LuaJIT/LuaJIT/issues/795
- https://github.com/LuaJIT/LuaJIT/issues/797
- https://github.com/LuaJIT/LuaJIT/issues/798
- https://github.com/LuaJIT/LuaJIT/issues/799
- https://github.com/LuaJIT/LuaJIT/issues/799
- https://github.com/LuaJIT/LuaJIT/issues/816
- https://github.com/LuaJIT/LuaJIT/issues/860
- https://github.com/LuaJIT/LuaJIT/issues/755
- https://github.com/LuaJIT/LuaJIT/issues/727
- https://github.com/LuaJIT/LuaJIT/issues/540
]]

local luzer = require("luzer")

local function TestOneInput(buf, size)
    assert(string.reverse(string.reverse(buf)) == buf)

    -- string.find(str, pattern)
    -- string.gsub(str, pattern, rep)
    -- string.sub(str, string.find(str, pattern))
    -- string.lower(str)
    -- string.upper(str)
    -- string.match(str)
    -- string.gmatch(str)
    -- string.format(str, table.unpack(args))
    -- string.rep()
    -- string.dump()

    local tbl = {}
    buf:gsub(".", function(c)
        table.insert(tbl, c)
    end)
    assert(string.len(buf) == table.getn(tbl))

    -- local fdp = luzer.FuzzedDataProvider(buf)
    -- local b = fdp:consume_string(1)
    -- local char_code = string.byte(b)
    -- assert(type(char_code) == "number")
    -- local byte = string.char(char_code)
    -- assert(byte == b)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 4096,
    max_total_time = 60,
    artifact_prefix = "stdlib_string_",
    dict = script_path .. "stdlib_string.dict",
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
