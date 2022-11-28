--[[

6.6 – Table Manipulation
https://www.lua.org/manual/5.1/manual.html#5.5

LuaJIT bugs:
- https://github.com/LuaJIT/LuaJIT/issues/494
- https://github.com/LuaJIT/LuaJIT/issues/844
- https://github.com/LuaJIT/LuaJIT/issues/792

"table.sort"
"table.move"

]]

local luzer = require("luzer")

local function TestOneInput(buf, size)
    local len = string.len(buf)

    local tbl = {}
    buf:gsub(".", function(c)
        local pos = table.getn(tbl) + 1
        table.insert(tbl, pos, c)
        assert(tbl[pos] == c)
    end)
    assert(table.getn(tbl), len)
    assert(buf == table.concat(tbl))

    table.foreach(tbl, function(k, v) end)

    table.foreachi(tbl, function(v) end)

    for i = 1, table.getn(tbl) do
        assert(tbl[1] == table.remove(tbl, 1))
        assert(table.getn(tbl) == len - i)
    end
    assert(table.getn(tbl) == 0)
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 4096,
    artifact_prefix = "stdlib_table_",
    dict = script_path .. "stdlib_table.dict",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)