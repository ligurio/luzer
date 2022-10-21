package.cpath = "./?.so"

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(4)

    local b = {}
    str:gsub(".", function(c) table.insert(b, c) end)
    local count = 0
    if b[1] == "o" then count = count + 1 end
    if b[2] == "o" then count = count + 1 end
    if b[3] == "p" then count = count + 1 end
    if b[4] == "s" then count = count + 1 end
    if count == 4 then assert() end
end

if arg[1] then
    local testcase = io.open(arg[1]):read("*all")
    TestOneInput(testcase)
    os.exit()
end

local script_path = debug.getinfo(1).source:match("@?(.*/)")

local args = {
    max_len = 1024,
    dict = script_path .. "luzer_example_basic.dict",
    print_pcs = 1,
    detect_leaks = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
