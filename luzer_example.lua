local luzer = require("luzer")
local fdp = luzer.FuzzedDataProvider(10)
local math = require("math")
local lib = luzer.require_instrument("lib")

local function custom_mutator(data, max_size, seed)
    return data .. "xxx"
end

local function TestOneInput(data)
  -- The entry point for our fuzzer.
  --
  -- This is a callback that will be repeatedly invoked with different
  -- arguments after Fuzz() is called.
  --
  -- We translate the arbitrary byte string into a format our function being
  -- fuzzed can understand, then call it.
  --
  -- Args:
  --    data: string coming from the fuzzing engine.

  return
end

if #arg > 1 and arg[1] == "--no_mutator" then
    luzer.Setup(argv, TestOneInput, custom_mutator)
else
    luzer.Setup(argv, TestOneInput)
end

luzer.Fuzz()
