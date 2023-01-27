function LLVMFuzzerCustomMutator(data, max_size, seed) -- luacheck: ignore
    assert(type(data) == "string")
    assert(data == "LUA")

    assert(type(max_size) == "number")
    assert(max_size == #data + 1)

    assert(type(seed) == "number")
    assert(seed ~= nil)
    assert(seed == 0)

    local b = {}
    data:gsub(".", function(c) table.insert(b, c) end)
    b[1] = "X"
    local buf = table.concat(b, "")

    return buf, #buf
end

function LLVMFuzzerCustomCrossOver(data1, data2, max_size, seed) -- luacheck: ignore
    assert(type(data1) == "string")
    assert(data1 == "LUA")

    assert(type(data2) == "string")
    assert(data2 == "LUA")

    assert(type(max_size) == "number")

    assert(type(seed) == "number")
    assert(seed ~= nil)

    local buf = "luzer"

    return buf, #buf
end
