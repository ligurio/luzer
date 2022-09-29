package.cpath = "./?.so"

local luzer = require("luzer")

local function TestOneInput(buf, _size)
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
    max_len = 4096,
    only_ascii = 1,
}
luzer.Setup(TestOneInput, nil, args)
luzer.Fuzz()
