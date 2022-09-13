package.cpath = "./?.so"

local luzer = require("luzer")

local function custom_mutator(buf, _max_size, _seed)
    return buf .. "xxx"
end

local function TestOneInput(buf, _size)
    local fdp = luzer.FuzzedDataProvider(buf)
    local str = fdp.consume_string(5)

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

arg1 = {"-max_len=4096", "-only_ascii=1", "-dict=/home/sergeyb/sources/luzer/dict_example"}

local res
if #arg > 1 and arg[1] == "--no_mutator" then
    res = luzer.Setup(arg1, TestOneInput, custom_mutator)
    assert(nil)
else
    res = luzer.Setup(arg1, TestOneInput, custom_mutator)
end
assert(res == true)

luzer.Fuzz()
