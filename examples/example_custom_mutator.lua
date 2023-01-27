local luzer = require("luzer")

local function custom_mutator(buf)
    return buf .. "A"
end

local function TestOneInput(buf)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp:consume_string(3)

    local b = {}
    str:gsub(".", function(c)
        table.insert(b, c)
    end)

    if b[1] == "A" then
        if b[2] == "A" then
            if b[3] == "A" then
                assert(nil, "assert has triggered")
            end
        end
    end
end

local args = {
    only_ascii = 1,
}

luzer.Fuzz(TestOneInput, custom_mutator, args)
