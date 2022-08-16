package.cpath = "./?.so"
local luzer = require("libluzer")

-- luzer.version
local version = luzer.VERSION
assert(type(version) == "string")

-- luzer.FuzzedDataProvider
local fdp = luzer.FuzzedDataProvider

assert(type(fdp.consume_string) == "function")
local res = fdp.consume_string()
assert(type(res) == "string")
assert(res == "string")

assert(type(fdp.consume_boolean) == "function")
res = fdp.consume_boolean()
assert(type(res) == "boolean")
assert(res == true)

assert(type(fdp.consume_booleans) == "function")
res = fdp.consume_booleans()
assert(type(res) == "table")
--assert(res[1] == true)
--assert(res[2] == false)

assert(type(fdp.consume_number) == "function")
res = fdp.consume_number()
assert(type(res) == "number")
assert(res == 300)

assert(type(fdp.consume_numbers) == "function")
res = fdp.consume_numbers()
assert(type(res) == "table")
--assert(res[1] == 200)
--assert(res[2] == 400)

assert(type(fdp.consume_integer) == "function")
res = fdp.consume_integer()
assert(type(res) == "number")
assert(res == 300)

assert(type(fdp.consume_integers) == "function")
res = fdp.consume_integers()
assert(type(res) == "table")
--assert(res[1] == 200)
--assert(res[2] == 400)

assert(type(fdp.consume_cdata) == "function")
res = fdp.consume_cdata()
assert(res == nil)

assert(type(fdp.consume_userdata) == "function")
res = fdp.consume_userdata()
assert(res == nil)

assert(type(fdp.consume_lightuserdata) == "function")
res = fdp.consume_lightuserdata()
assert(res == nil)

assert(type(fdp.consume_remaining_as_string) == "function")
res = fdp.consume_remaining_as_string()
assert(type(res) == "string")
assert(res == "remaining")

assert(type(fdp.remaining_bytes) == "function")
res = fdp.remaining_bytes()
assert(type(res) == "number")
assert(res == 1)

print("Success!")
