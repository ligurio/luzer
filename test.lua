package.cpath = "./?.so"

local luzer = require("luzer")

local function trace(_, line)
    local s = debug.getinfo(2).short_src
    print(s .. ":" .. line)
end

debug.sethook(trace, "l")

-- luzer._VERSION
local version = luzer._VERSION
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

local ok
local fdp
local res

-- luzer.FuzzedDataProvider()
assert(type(luzer.FuzzedDataProvider) == "function")
ok = pcall(luzer.FuzzedDataProvider)
assert(ok == false)
fdp = luzer.FuzzedDataProvider(string.rep('A', 1024))
assert(type(fdp) == "table")

-- luzer.FuzzedDataProvider.remaining_bytes()
fdp = luzer.FuzzedDataProvider("A")
assert(type(fdp.remaining_bytes) == "function")
res = fdp.remaining_bytes()
assert(type(res) == "number")
assert(res == 1)
fdp = luzer.FuzzedDataProvider("ABC")
res = fdp.remaining_bytes()
assert(type(res) == "number")
assert(res == 3)

-- luzer.FuzzedDataProvider.consume_string()
fdp = luzer.FuzzedDataProvider("ABCD")
assert(type(fdp.consume_string) == "function")

assert(fdp.remaining_bytes() == 4)
res = fdp.consume_string(2)
assert(type(res) == "string")
assert(res == "AB")
assert(fdp.remaining_bytes() == 2)
res = fdp.consume_string(2)
assert(type(res) == "string")
assert(res == "CD")
res = fdp.consume_string(2)
assert(fdp.remaining_bytes() == 0)
assert(type(res) == "string")
assert(res == "")

ok = pcall(fdp.consume_string)
-- FIXME: assert(ok == false)

-- luzer.FuzzedDataProvider.consume_strings()
fdp = luzer.FuzzedDataProvider("ABCDEF")
assert(type(fdp.consume_strings) == "function")

res = fdp.consume_strings(2, 3)
assert(type(res) == "table")
assert(#res == 3, #res)
assert(fdp.remaining_bytes() == 0)

ok = pcall(fdp.consume_strings)
-- FIXME: assert(ok == false)

-- luzer.FuzzedDataProvider.consume_boolean()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_boolean) == "function")

assert(fdp.remaining_bytes() == 2)
res = fdp.consume_boolean()
assert(type(res) == "boolean")
assert(fdp.remaining_bytes() == 1)
res = fdp.consume_boolean()
assert(type(res) == "boolean")
assert(fdp.remaining_bytes() == 0)
res = fdp.consume_boolean()
assert(type(res) == "boolean")
assert(res == false)
assert(fdp.remaining_bytes() == 0)
res = fdp.consume_boolean()
assert(type(res) == "boolean")
assert(res == false)

-- luzer.FuzzedDataProvider.consume_booleans()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_booleans) == "function")

res = fdp.consume_booleans(2)
assert(type(res) == "table")
assert(type(res[1]) == "boolean")
assert(type(res[2]) == "boolean")
assert(fdp.remaining_bytes() == 0)
res = fdp.consume_booleans(2)
assert(type(res) == "table")
assert(res[1] == false)
assert(res[2] == false)

ok = pcall(fdp.consume_booleans)
-- FIXME: assert(ok == false)

-- luzer.FuzzedDataProvider.consume_number()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_number) == "function")

res = fdp.consume_number(1, 10)
assert(type(res) == "number")
assert(res >= 1)
assert(res <= 10, res)

ok = pcall(fdp.consume_number)
assert(ok == false)

-- luzer.FuzzedDataProvider.consume_numbers()
fdp = luzer.FuzzedDataProvider("ABCDEF")
assert(type(fdp.consume_numbers) == "function")

res = fdp.consume_numbers(2, 3, 1)
assert(type(res) == "table")
assert(type(res[1]) == "number")
assert(res[2] == nil)

ok = pcall(fdp.consume_numbers)
assert(ok == false)

-- luzer.FuzzedDataProvider.consume_integer()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_integer) == "function")

res = fdp.consume_integer(10, 20)
assert(type(res) == "number")
assert(res >= 10)
assert(res <= 20)

ok = pcall(fdp.consume_integer)
assert(ok == false)

-- luzer.FuzzedDataProvider.consume_integers()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_integers) == "function")

res = fdp.consume_integers(2, 6, 1)
assert(type(res) == "table")
assert(type(res[1]) == "number")
assert(res[1] <= 6, res[1])
assert(res[1] > 2, res[1])
assert(res[2] == nil)

ok = pcall(fdp.consume_integers)
assert(ok == false)

-- luzer.FuzzedDataProvider.consume_probability()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_probability) == "function")

local p1 = fdp.consume_probability()
local p2 = fdp.consume_probability()
assert(type(p1) == "number")
assert(type(p2) == "number")
assert(p1 >= 0 and p2 >= 0)
assert(p1 <= 1 and p2 <= 1)
assert(p1 ~= p2)

-- luzer.Fuzz()
luzer = require("luzer")
ok = pcall(luzer.Fuzz)
assert(ok == false)

-- luzer.Setup()
luzer = require("luzer")
ok = pcall(luzer.Setup)
assert(ok == false)

print("Success!")
