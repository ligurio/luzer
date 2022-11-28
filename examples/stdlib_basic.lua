--[[

5.1 – Basic Functions
https://www.lua.org/manual/5.1/manual.html

LuaJIT bugs:

- https://github.com/LuaJIT/LuaJIT/issues/124
- https://github.com/LuaJIT/LuaJIT/issues/158
- https://github.com/LuaJIT/LuaJIT/issues/180
- https://github.com/LuaJIT/LuaJIT/issues/241
- https://github.com/LuaJIT/LuaJIT/issues/528
- https://github.com/LuaJIT/LuaJIT/issues/601
- https://github.com/LuaJIT/LuaJIT/issues/688
- https://github.com/LuaJIT/LuaJIT/issues/690
- https://github.com/LuaJIT/LuaJIT/issues/737
- https://github.com/LuaJIT/LuaJIT/issues/744
- https://github.com/LuaJIT/LuaJIT/issues/753
- https://github.com/LuaJIT/LuaJIT/issues/754
- https://github.com/LuaJIT/LuaJIT/issues/788
- https://github.com/LuaJIT/LuaJIT/issues/791
- https://github.com/LuaJIT/LuaJIT/issues/794
- https://github.com/LuaJIT/LuaJIT/issues/796
- https://github.com/LuaJIT/LuaJIT/issues/827
- https://github.com/LuaJIT/LuaJIT/issues/839
- https://github.com/LuaJIT/LuaJIT/issues/864

]]

local luzer = require("luzer")

local function TestOneInput(buf)
    print(buf)
end

local args = {
    max_len = 4096,
    artifact_prefix = "stdlib_basic_",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
