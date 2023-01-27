function LLVMFuzzerCustomMutator(data, max_size, seed) -- luacheck: ignore
    return string.rep("A", #data), #data
end

function LLVMFuzzerCustomCrossOver(data1, data2, max_size, seed) -- luacheck: ignore
    return "", 0
end
