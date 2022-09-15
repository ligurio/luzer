--- Function called for each mutation.
--
-- Optional user-provided custom mutator. Mutates raw data in [data, data+size)
-- inplace. Returns the new size, which is not greater than max_size. Given the
-- same seed produces the same mutation.
--
-- @string data - the data that should be mutated.
-- @number size - size of buffer with data.
-- @number max_size - the maximum size of the returned data.
-- @number random_seed - seed for random decisions.
-- @return size, a new size, which is not greater then max_size.
--
-- @function LLVMFuzzerCustomMutator
function LLVMFuzzerCustomMutator(data, size, max_size, seed) -- luacheck: ignore
    -- If you want to make any random decisions within the mutator, you must
    -- base them on the provided seed.
    require("math").randomseed(seed)

    assert(#data == size)
    local msg = ("data %s, size %s, max_size %s, seed %s"):format(data, size, max_size, seed)
    print(msg)

    return size
end

--- Function called for each mutation.
--
-- libFuzzer-provided function to be used inside LLVMFuzzerCustomMutator.
-- Mutates raw data in [data, data+size) inplace. Returns the new size, which
-- is not greater than max_size.
--
-- @string data
-- @number size
-- @number max_size
--
-- @function LLVMFuzzerMutate
function LLVMFuzzerMutate(data, size, max_size) -- luacheck: ignore
    print(data, size, max_size)
    return size
end
