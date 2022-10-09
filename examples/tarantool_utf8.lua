local utf8 = require("utf8")
local luzer = require("luzer")

local find = string.find

-- Numbers taken from table 3-7 in
-- www.unicode.org/versions/Unicode6.2.0/UnicodeStandard-6.2.pdf
-- Find-based solution inspired by
-- http://notebook.kulchenko.com/programming/fixing-malformed-utf8-in-lua
local function is_valid_utf8(str)
  local i, len = 1, #str
  while i <= len do
    if     i == find(str, "[%z\1-\127]", i) then i = i + 1
    elseif i == find(str, "[\194-\223][\128-\191]", i) then i = i + 2
    elseif i == find(str,        "\224[\160-\191][\128-\191]", i)
        or i == find(str, "[\225-\236][\128-\191][\128-\191]", i)
        or i == find(str,        "\237[\128-\159][\128-\191]", i)
        or i == find(str, "[\238-\239][\128-\191][\128-\191]", i) then i = i + 3
    elseif i == find(str,        "\240[\144-\191][\128-\191][\128-\191]", i)
        or i == find(str, "[\241-\243][\128-\191][\128-\191][\128-\191]", i)
        or i == find(str,        "\244[\128-\143][\128-\191][\128-\191]", i) then i = i + 4
    else
      return false, i
    end
  end

  return true
end

-- check utf8 https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
-- corpus: https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt

--[[
"utf8.casecmp"
"utf8.isupper"
"utf8.next"
"utf8.lower"
"utf8.isdigit"
"utf8.isalpha"
"utf8.upper"
"utf8.sub"
"utf8.char"
"utf8.cmp"
"utf8.islower"
"utf8.len"
]]

local function TestOneInput(data)
    local ok, res = pcall(uri.parse, data)
end

local args = {
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
