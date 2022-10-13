-- https://github.com/Zac-HD/stdlib-property-tests
-- https://github.com/Zac-HD/stdlib-property-tests/blob/master/tests/test_re_by_construction.py
-- Differential testing with re, https://luarocks.org/modules/rrt/lrexlib-posix
-- https://github.com/codenote/regfuzz

-- 6.4 – String Manipulation
-- https://www.lua.org/manual/5.3/manual.html#6.4

-- 20.2 – Patterns
-- https://www.lua.org/pil/20.2.html

-- Source code: http://www.lua.org/source/5.1/lstrlib.c.html

-- s = "Deadline is 30/05/1999, firm"
-- date = "%d%d/%d%d/%d%d%d%d"
-- print(string.sub(s, string.find(s, date)))   --> 30/05/1999

local luzer = require("luzer")

local function TestOneInput_find(buf, _size)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(5)
    local pattern  = fdp:consume_string(5)
    string.find(str, pattern)
end

local function TestOneInput_gsub(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(5)
    local pattern  = fdp:consume_string(5)
    local rep = fdp:consume_string(5)
    string.gsub(str, pattern, rep)
end

local function TestOneInput_sub(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    local pattern  = fdp:consume_string(100)
    string.sub(str, string.find(str, pattern))
end

local function TestOneInput_lower(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    string.lower(str)
end

local function TestOneInput_upper(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    string.upper(str)
end

local function TestOneInput_match(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    string.match(str)
end

local function TestOneInput_gmatch(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    string.gmatch(str)
end

local function TestOneInput_reverse(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    assert(string.reverse(string.reverse(str)) == str)
end

local function TestOneInput_format(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(100)
    local args = fdp:consume_strings(100)
    --string.format(str, table.unpack(args))
end

local function TestOneInput_len(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local len = fdp:consume_number()
    local str = fdp:consume_string(len)
    assert(#str == len)
    assert(string.len(str) == len)
end

local function TestOneInput_byte(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local b = fdp:consume_string(1)
    local char_code = string.byte(b)
    assert(type(char_code) == "number")
    local byte = string.char(char_code)
    assert(byte == b)
end

--[[
"string.rep"
"string.dump"
]]

local args = {
    max_len = 4096,
    only_ascii = 1,
}
luzer.Fuzz(TestOneInput, nil, args)

--[[
-- Tarantool
"string.ljust"
"string.rstrip"
"string.split"
"string.center"
"string.strip"
"string.endswith"
"string.hex"
"string.fromhex"
"string.startswith"
"string.rjust"
"string.lstrip"
]]
