-- https://github.com/Zac-HD/stdlib-property-tests
-- check utf8 https://www.cl.cam.ac.uk/~mgk25/ucs/utf8_check.c
-- corpus: https://www.cl.cam.ac.uk/~mgk25/ucs/examples/UTF-8-test.txt
-- https://git.neulandlabor.de/j3d1/json/commit/15b6421d0789a5402275358d43719f4b37979929
-- https://github.com/geoffmcl/utf8-test/tree/master/src
-- https://github.com/kikito/utf8_validator.lua/blob/master/utf8_validator.lua


-- 6.5 – UTF-8 Support
-- https://www.lua.org/manual/5.3/manual.html#6.5

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

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end
