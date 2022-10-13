package.cpath = "./?.so"

local luzer = require("luzer")

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(5)

    local b = {}
    str:gsub(".", function(c) table.insert(b, c) end)
    if b[1] == 'c' then
        if b[2] == 'r' then
            if b[3] == 'a' then
                if b[4] == 's' then
                    if b[5] == 'h' then
                        assert(nil)
                    end
                end
            end
        end
    end

    return
end

local args = {
    dict = "/home/sergeyb/sources/luzer/examples/luzer_example_basic.dict",
    max_len = 1,
}
luzer.Fuzz(TestOneInput, nil, args)
