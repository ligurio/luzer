local function trace(event, line)
    print("trace function is executed")
    assert(event == "edge")
    assert(line == 10)
end

debug.sethook(trace, "e")

local str = "Lua"
if str == "XXX" then print("Debug") end
