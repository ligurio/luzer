package.cpath = "./?.so"

local luzer = require("luzer")

local function trace(_, line)
    local s = debug.getinfo(2).short_src
    print(s .. ":" .. line)
end

debug.sethook(trace, "l")

-- luzer._VERSION
assert(type(luzer._VERSION) == "string")
assert(type(luzer._LLVM_VERSION) == "string")
assert(type(luzer._LUA_VERSION) == "string")

local ok
local err
local fdp
local res

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

-- luzer.FuzzedDataProvider.consume_numbers()
fdp = luzer.FuzzedDataProvider("ABCDEF")
assert(type(fdp.consume_numbers) == "function")

res = fdp:consume_numbers(2, 1, 3)
assert(type(res) == "table")
assert(type(res[1]) == "number")
assert(type(res[2]) == "number")
assert(res[3] == nil, res[3])

ok, err = pcall(fdp.consume_numbers, fdp)
assert(ok == false)
assert(err ~= nil)

-- luzer.FuzzedDataProvider.consume_integer()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_integer) == "function")

res = fdp:consume_integer(10, 20)
assert(type(res) == "number")
assert(res >= 10)
assert(res <= 20)

ok, err = pcall(fdp.consume_integer)
assert(ok == false)
assert(err ~= nil)

-- luzer.FuzzedDataProvider.consume_integers()
fdp = luzer.FuzzedDataProvider("AB")
assert(type(fdp.consume_integers) == "function")

local min = 1
local max = 6
res = fdp:consume_integers(1, min, max)
assert(type(res) == "table")
assert(type(res[1]) == "number")
assert(res[1] <= max, res[1])
assert(res[1] >= min, res[1])
assert(res[2] == nil)

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

-- luzer._set_custom_mutator()
--[[
local magic_number = 51
local custom_mutator = function() return magic_number end
assert(luzer_custom_mutator == nil)
luzer._set_custom_mutator(custom_mutator)
assert(luzer_custom_mutator ~= nil)
assert(type(luzer_custom_mutator) == "function")
assert(luzer_custom_mutator() == magic_number)
luzer_custom_mutator = nil -- Clean up.

-- luzer._mutate()
local mutator_data
local function custom_mutator(data, size, max_size, seed)
    assert(type(data) == "string")
    assert(#data ~= 0)
    assert(type(size) == "number")
    assert(size == #buf)
    assert(type(max_size) == "number")
    assert(type(seed) == "number")
    mutator_data = data
    return data
end
luzer._set_custom_mutator(custom_mutator)
assert(luzer_custom_mutator ~= nil)
local buf = "luzer"
local size = #buf
local max_size = #buf
local seed = math.random(1, 10)
--luzer._mutate(buf, size, max_size, seed)
--assert(mutator_data == buf)
luzer_custom_mutator = nil -- Clean up.
]]

print("Success!")
