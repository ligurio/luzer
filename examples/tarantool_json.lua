--[[
$ luarocks install --tree modules --lua-version 5.1
	lua-cjson CC="clang" CFLAGS="-ggdb -fPIC -fsanitize=address" LDFLAGS="-fsanitize=address"

Installing https://luarocks.org/lua-cjson-2.1.0.6-1.src.rock

lua-cjson 2.1.0.6-1 depends on lua >= 5.1 (5.1-1 provided by VM)
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c lua_cjson.c -o lua_cjson.o
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c strbuf.c -o strbuf.o
clang -ggdb -fPIC -fsanitize=address -I/usr/include/lua5.1 -c fpconv.c -o fpconv.o
gcc -shared -o cjson.so lua_cjson.o strbuf.o fpconv.o
No existing manifest. Attempting to rebuild...
lua-cjson 2.1.0.6-1 is now installed in /home/sergeyb/sources/luzer/build/modules (license: MIT)

$ export LUA_PATH="$LUA_PATH;modules/lib/lua/5.1/?.lua"
$ export LUA_CPATH="$LUA_CPATH;modules/lib/lua/5.1/?.so;./?.so"
$ mkdir -p corpus
$ echo -n "{}" > corpus/sample
$ luajit luzer_example_json.lua
]]

-- https://github.com/tarantool/tarantool/issues/4366

local json = require("json")
local luzer = require("luzer")
local math = require("math")

local function TestOneInput(buf)
    local ok, obj = pcall(json.decode, buf)
    if obj == math.inf or
       obj == 0/0 then
        return -1
    end
    if ok == true then
        ok = json.encode(obj)
        assert(ok == true)
    end
end

local args = {
    dict = "/home/sergeyb/sources/luzer/examples/tarantool_json.dict",
    max_len = 4096,
}
luzer.Fuzz(TestOneInput, nil, args)
