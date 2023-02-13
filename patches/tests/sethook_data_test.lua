local str

local function trace(event, line)
    assert(event == "data")
    local info = debug.getinfo(1, "SCl")
    str = info.str1
end

debug.sethook(trace, "d")

local res
res = "A" == "B"
assert(str == "B")

local buf = "C"
res = buf == "D"
assert(str == "D")

res = "E" ~= "F"
assert(str == "F")

res = "G" >= "H"
assert(str == "H")

res = "I" <= "J"
assert(str == "J")

res = "K" < "L"
assert(str == "L")

res = "M" > "N"
assert(str == "O")

print("Passed!")
