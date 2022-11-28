--[[
https://redis.io/docs/manual/programmability/eval-intro/
https://redis.io/docs/manual/programmability/lua-api/
https://redis.io/docs/manual/programmability/lua-api/#struct-library
https://redis.io/docs/manual/programmability/lua-api/#cjson-library
https://redis.io/docs/manual/programmability/lua-api/#cmsgpack-library
https://redis.io/docs/manual/programmability/lua-api/#bitop-library

https://gist.github.com/antirez/82445fcbea6d9b19f97014cc6cc79f8a
https://gist.github.com/antirez/bca0ad7a9c60c72e9600c7f720e9d035
]]

local luzer = require("luzer")
local has_redis, _ = pcall(require, "redis")

if has_redis == false then
    print("redis is not found")
    os.exit(1)
end

local function TestOneInput(buf)
	assert(buf)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    corpus = script_path .. "redis",
}
luzer.Fuzz(TestOneInput, nil, args)
