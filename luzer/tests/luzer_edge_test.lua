-- https://github.com/llvm-mirror/compiler-rt/tree/master/test/fuzzer

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(9)

    local b = {}
    str:gsub(".", function(c) table.insert(b, c) end)
    local count = 0
    if b[1] == "a" then count = count + 1 end
    if b[2] == "b" then count = count + 1 end
    if b[3] == "c" then count = count + 1 end
    if b[4] == "d" then count = count + 1 end
    if b[5] == "e" then count = count + 1 end
    if b[6] == "f" then count = count + 1 end
    if b[7] == "h" then count = count + 1 end
    if b[8] == "i" then count = count + 1 end
    if b[9] == "g" then count = count + 1 end

    if count == 9 then assert(nil) end
end

luzer.Fuzz(TestOneInput)
