-- https://github.com/Zac-HD/stdlib-property-tests

-- 6.9 – Operating System Facilities
-- https://www.lua.org/manual/5.3/manual.html#6.9

-- os.date ([format [, time]])
-- os.difftime (t2, t1)
-- os.time ([table])

local luzer = require("luzer")

local function TestOneInput(buf)
end

local args = {
    max_len = 4096,
    only_ascii = 1,
}
luzer.Fuzz(TestOneInput_sqrt, nil, args)
