local luzer = require("luzer")

local function trace(_, line)
    local s = debug.getinfo(2).short_src
    print(s .. ":" .. line)
end

debug.sethook(trace, "l")

assert(type(luzer._internal.LUZER_VERSION) == "string")
assert(type(luzer._internal.LLVM_VERSION) == "string")
assert(type(luzer._internal.LUA_VERSION) == "string")

local ok
local err
local fdp
local res

-- By default `lua_Integer` is ptrdiff_t in Lua 5.1 and Lua 5.2
-- and `long long` in Lua 5.3+, (usually a 64-bit two-complement
-- integer), but that can be changed to `long` or `int` (usually a
-- 32-bit two-complement integer), see LUA_INT_TYPE in
-- <luaconf.h>. Lua 5.3+ has two functions: `math.maxinteger` and
-- `math.mininteger` that returns an integer with the maximum
-- value for an integer and an integer with the minimum value for
-- an integer, see [1] and [2].

-- `0x7ffffffffffff` is a maximum integer in `long long`, however
-- this number is not representable in `double` and the nearest
-- number representable in `double` is `0x7ffffffffffffc00`.
--
-- 1. https://www.lua.org/manual/5.1/manual.html#lua_Integer
-- 2. https://www.lua.org/manual/5.3/manual.html#lua_Integer
local MAX_REPRESENTABLE_INT = 0x7fffffffffffffff
local MIN_REPRESENTABLE_INT = MAX_REPRESENTABLE_INT
if _VERSION == "Lua 5.1" or _VERSION == "Lua 5.2" then
    MAX_REPRESENTABLE_INT = 0x7ffffffffffffc00
    MIN_REPRESENTABLE_INT = 0x8000000000000000
end
local MAX_INT = math.maxinteger or MAX_REPRESENTABLE_INT
local MIN_INT = math.mininteger or -MIN_REPRESENTABLE_INT

-- luzer.FuzzedDataProvider()
assert(type(luzer.FuzzedDataProvider) == "function")
ok, err = pcall(luzer.FuzzedDataProvider)
assert(ok == false)
assert(err ~= nil)
fdp = luzer.FuzzedDataProvider(string.rep('A', 1024))
assert(type(fdp) == "userdata")

-- luzer.FuzzedDataProvider.remaining_bytes()
fdp = luzer.FuzzedDataProvider("A")
assert(type(fdp.remaining_bytes) == "function")
res = fdp:remaining_bytes()
assert(type(res) == "number")
assert(res == 1)
fdp = luzer.FuzzedDataProvider("ABC")
res = fdp:remaining_bytes()
assert(type(res) == "number")
assert(res == 3)

-- luzer.FuzzedDataProvider.consume_string()
fdp = luzer.FuzzedDataProvider("ABCD")
assert(type(fdp.consume_string) == "function")

assert(fdp:remaining_bytes() == 4)
res = fdp:consume_string(2)
assert(type(res) == "string")
assert(res == "AB")
assert(fdp:remaining_bytes() == 2)
res = fdp:consume_string(2)
assert(type(res) == "string")
assert(res == "CD")
res = fdp:consume_string(2)
assert(fdp:remaining_bytes() == 0)
assert(type(res) == "string")
assert(res == "")

ok = pcall(fdp.consume_string)
assert(ok == false)
assert(err ~= nil)

-- luzer.FuzzedDataProvider.consume_strings()
fdp = luzer.FuzzedDataProvider("ABCDEF")
assert(type(fdp.consume_strings) == "function")

res = fdp:consume_strings(2, 3)
assert(type(res) == "table")
assert(#res == 2, #res)
assert(fdp:remaining_bytes() == 0)

ok = pcall(fdp.consume_strings)
assert(ok == false)
assert(err ~= nil)

-- luzer.FuzzedDataProvider.consume_boolean()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_boolean) == "function")

assert(fdp:remaining_bytes() == 2)
res = fdp:consume_boolean()
assert(type(res) == "boolean")
assert(fdp:remaining_bytes() == 1)
res = fdp:consume_boolean()
assert(type(res) == "boolean")
assert(fdp:remaining_bytes() == 0)
res = fdp:consume_boolean()
assert(type(res) == "boolean")
assert(res == false)
assert(fdp:remaining_bytes() == 0)
res = fdp:consume_boolean()
assert(type(res) == "boolean")
assert(res == false)

-- luzer.FuzzedDataProvider.consume_booleans()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_booleans) == "function")

res = fdp:consume_booleans(2)
assert(type(res) == "table")
assert(type(res[1]) == "boolean")
assert(type(res[2]) == "boolean")
assert(fdp:remaining_bytes() == 0)
res = fdp:consume_booleans(2)
assert(type(res) == "table")
assert(res[1] == false)
assert(res[2] == false)

ok = pcall(fdp.consume_booleans)
assert(ok == false)

-- luzer.FuzzedDataProvider.consume_number()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_number) == "function")

res = fdp:consume_number(1, 10)
assert(type(res) == "number")
assert(res >= 1)
assert(res <= 10, res)

ok, err = pcall(fdp.consume_number)
assert(ok == false)
assert(err ~= nil)

local num = fdp:consume_number(1, MAX_INT)
assert(type(num) == "number")

-- luzer.FuzzedDataProvider.consume_numbers()
fdp = luzer.FuzzedDataProvider(string.rep("XYZ", 100))
assert(type(fdp.consume_numbers) == "function")

local min = 1
local max = MAX_INT
local count = 3
res = fdp:consume_numbers(min, max, count)
assert(type(res) == "table")
assert(#res == count)
for _, n in ipairs(res) do
    assert(type(n) == "number")
    assert(n <= max)
    assert(n >= min)
end

ok, err = pcall(fdp.consume_numbers, fdp)
assert(ok == false)
assert(err ~= nil)

-- luzer.FuzzedDataProvider.consume_integer()
fdp = luzer.FuzzedDataProvider(string.rep("ABC", 1000))
assert(type(fdp.consume_integer) == "function")

res = fdp:consume_integer(10, 20)
assert(type(res) == "number")
assert(res >= 10)
assert(res <= 20)

ok, err = pcall(fdp.consume_integer)
assert(ok == false)
assert(err ~= nil)

local max_int = fdp:consume_integer(MAX_INT, MAX_INT)
assert(type(max_int) == "number")
assert(max_int == MAX_INT)

local min_int = fdp:consume_integer(MIN_INT, MIN_INT)
assert(type(min_int) == "number")
assert(min_int == MIN_INT)

local i = fdp:consume_integer(MIN_INT, MAX_INT)
assert(type(i) == "number")

-- luzer.FuzzedDataProvider.consume_integers()
fdp = luzer.FuzzedDataProvider(string.rep("XYZ", 100))
assert(type(fdp.consume_integers) == "function")

min = 1
max = MAX_INT
count = 3
res = fdp:consume_integers(min, max, count)
assert(#res == count)
assert(type(res) == "table")
for _, n in ipairs(res) do
    assert(type(n) == "number")
    assert(n <= max)
    assert(n >= min)
end

ok, err = pcall(fdp.consume_integers)
assert(ok == false)
assert(err ~= nil)

-- luzer.FuzzedDataProvider.consume_probability()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_probability) == "function")

local p1 = fdp:consume_probability()
local p2 = fdp:consume_probability()
assert(type(p1) == "number")
assert(type(p2) == "number")
assert(p1 >= 0 and p2 >= 0)
assert(p1 <= 1 and p2 <= 1)
assert(p1 ~= p2)

-- luzer.FuzzedDataProvider.oneof()
fdp = luzer.FuzzedDataProvider("ABCDEFGHIJKLMNOPQRSTUVWXYZ")
assert(type(fdp.oneof) == "function")

-- Call `oneof()` with no values should raise an error.
ok, err = pcall(fdp.oneof, fdp)
assert(ok == false)
assert(err:match("table expected, got no value"), err)

-- Call `oneof()` with empty table returns a `nil`.
local n = fdp:oneof({})
assert(n == nil)

-- Call `oneof()` with numbers.
local a = 3
local b = 4
n = fdp:oneof({a, b})
assert(type(n) == "number" and (n == a or n == b))

-- Call `oneof()` with strings.
local str1 = "Python"
local str2 = "Lua"
local str = fdp:oneof({str1, str2})
assert(type(str) == "string" and (str == str1 or str == str2))

local function custom_mutator(data, size, max_size, seed)
    assert(type(data) == "string")
    assert(type(size) == "number")
    assert(size == #data)
    assert(type(max_size) == "number")
    assert(max_size == size)
    assert(type(seed) == "number")
    return data
end

-- luzer._internal.set_custom_mutator()
assert(luzer_custom_mutator == nil)
luzer._internal.set_custom_mutator(custom_mutator)
assert(luzer_custom_mutator ~= nil)
assert(type(luzer_custom_mutator) == "function")
local buf = "data"
assert(luzer_custom_mutator(buf, #buf, #buf, math.random(1, 10)) == buf)
luzer_custom_mutator = nil -- Clean up.

-- luzer._internal.mutate()
luzer._internal.set_custom_mutator(custom_mutator)
assert(luzer_custom_mutator ~= nil)
-- luzer._internal.mutate(buf, #buf, #buf, math.random(1, 10)) -- TODO
luzer_custom_mutator = nil -- Clean up.

-- luzer._internal.parse_flag()
local flag_testcases = {
    { "dict", "/tmp/lua.dict" },
    { "help", "1" },
    { "rss_limit_mb", "2048" },
    { "runs", "-1" },
}
for _, testcase in ipairs(flag_testcases) do
    local name = testcase[1]
    local val = testcase[2]
    -- libFuzzer flags are strictly in form `-flag=value`.
    local flag = ("-%s=%s"):format(name, val)
    -- Expected a table with `name` and `value`.
    res = { luzer._internal.parse_flag(flag) }
    assert(name == res[1], ("expected %s"):format(name))
    assert(val == res[2], ("expected %s"):format(val))
end

print("Success!")
