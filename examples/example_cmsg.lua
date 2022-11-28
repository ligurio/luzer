--[[

An example of reproducing CVE-2018-11218 impacting version 0.4.0-0 of
lua-cmsgpack is given which demonstrates how the fuzzing coverage extends
across pure-Lua into C Lua modules.

http://antirez.com/news/119
https://github.com/antirez/lua-cmsgpack/tree/0.4.0

V=5.1
luarocks install --local --lua-version $V lua-cmsgpack 0.4.0-0 CC="clang" CFLAGS="-ggdb -fPIC"
luarocks path
export LUA_PATH="$LUA_PATH;modules/lib/lua/$V/?.lua"
export LUA_CPATH="$LUA_CPATH;modules/lib/lua/$V/?.so;../../?.so"
mkdir -p corpus
echo -n "\0\0" > corpus/sample

]]

local cmsg = require("cmsgpack")
local cmsgsafe = require("cmsgpack.safe")

package.cpath = "./?.so"
local luzer = require("luzer")

local function TestOneInput(buf)
    local u, err = cmsgsafe.unpack(buf)
    if not err and u then
        local res = {cmsg.unpack(buf)}
        cmsg.pack(table.unpack(res))
    end
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 1024,
    print_pcs = 1,
    detect_leaks = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
