local set_seed = require("math").randomseed

function LLVMFuzzerCustomMutator(data, max_size, seed) -- luacheck: ignore
    set_seed(seed)
    return data .. "xxx", 10
end

function LLVMFuzzerCustomCrossOver(data1, data2, max_size, seed) -- luacheck: ignore
    set_seed(seed)
    return data1 .. "xxx", 10
end
