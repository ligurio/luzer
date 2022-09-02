package.cpath = "./?.so"

local luzer = require("luzer")

local function trace(_, line)
    local s = debug.getinfo(2).short_src
    print(s .. ":" .. line)
end

debug.sethook(trace, "l")

-- luzer.version
local version = luzer.VERSION
assert(type(version) == "table")
local version_lua = version.LUA
local version_luzer = version.LUZER
local version_llvm = version.LLVM
assert(type(version_lua) == "string")
local semver_re = "%d+%.%d+%.%d+"
assert(string.match(version_lua, semver_re) ~= nil, version_lua)
assert(type(version_luzer) == "string")
assert(string.match(version_luzer, semver_re) ~= nil, version_luzer)
assert(type(version_llvm) == "string")
assert(string.match(version_llvm, semver_re) ~= nil, version_llvm)

-- luzer.FuzzedDataProvider
assert(type(luzer.FuzzedDataProvider) == "function")
local fdp = luzer.FuzzedDataProvider(string.rep('A', 1024))

assert(type(fdp.consume_string) == "function")
local res = fdp.consume_string()
assert(type(res) == "string")

assert(type(fdp.consume_boolean) == "function")
res = fdp.consume_boolean()
assert(type(res) == "boolean")

assert(type(fdp.consume_booleans) == "function")
res = fdp.consume_booleans(2)
assert(type(res) == "table")
assert(type(res[1]) == "boolean")
assert(type(res[2]) == "boolean")

assert(type(fdp.consume_number) == "function")
res = fdp.consume_number(1, 10)
assert(type(res) == "number")

assert(type(fdp.consume_numbers) == "function")
res = fdp.consume_numbers(2)
assert(type(res) == "table")
assert(type(res[1]) == "number")
assert(type(res[2]) == "number")

assert(type(fdp.consume_integer) == "function")
res = fdp.consume_integer()
assert(type(res) == "number")
assert(res == 300)

assert(type(fdp.consume_integers) == "function")
res = fdp.consume_integers(2)
assert(type(res) == "table")
assert(type(res[1]) == "number")
assert(type(res[2]) == "number")

assert(type(fdp.remaining_bytes) == "function")
res = fdp.remaining_bytes()
assert(type(res) == "number")

assert(type(fdp.consume_probability) == "function")
local p1 = fdp.consume_probability()
local p2 = fdp.consume_probability()
assert(type(p1) == "number")
assert(type(p2) == "number")
assert(p1 >= 0 and p2 >= 0)
assert(p1 <= 1 and p2 <= 1)
-- FIXME: assert(p1 ~= p2)

print("Success!")
