--[[

6.6 – Table Manipulation
https://www.lua.org/manual/5.1/manual.html#5.5

PUC Rio Lua bugs: https://www.lua.org/bugs.html

LuaJIT bugs:
- https://github.com/LuaJIT/LuaJIT/issues/494
- https://github.com/LuaJIT/LuaJIT/issues/844
- https://github.com/LuaJIT/LuaJIT/issues/792

"table.foreach"
"table.foreachi"
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

local args = {
    max_len = 4096,
}
luzer.Fuzz(TestOneInput, nil, args)
