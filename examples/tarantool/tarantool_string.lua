-- Module string
-- https://www.tarantool.io/en/doc/latest/reference/reference_lua/string/

--[[
string.ljust()		Left-justify a string
string.rjust()		Right-justify a string
string.hex()		Given a string, return hexadecimal values
string.fromhex()	Given hexadecimal values, return a string
string.startswith()	Check if a string starts with a given substring
string.endswith()	Check if a string ends with a given substring
string.lstrip()		Remove characters from the left of a string
string.rstrip()		Remove characters from the right of a string
string.split()		Split a string into a table of strings
string.strip()		Remove spaces on the left and right of a string
]]

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local b = fdp:consume_string(1)
    local char_code = string.byte(b)
    assert(type(char_code) == "number")
    local byte = string.char(char_code)
    assert(byte == b)
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local args = {
    max_len = 4096,
    artifact_prefix = "string_byte",
    max_total_time = 60,
    print_final_stats = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
