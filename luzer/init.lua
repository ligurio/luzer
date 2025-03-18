local ok, luzer_impl = pcall(require, "luzer_impl")
if not ok then
    error(("error on loading luzer_impl: %s"):format(luzer_impl))
end

local function starts_with(str, prefix)
    return string.sub(str, 1, string.len(prefix)) == prefix
end

-- The fuzzing test based on LibFuzzer optionally accept a number
-- of flags and zero or more paths to corpus directories as
-- command line arguments:
-- ./fuzzer [-flag1=val1 [-flag2=val2 ...] ] [dir1 [dir2 ...] ]
--
-- 1. https://llvm.org/docs/LibFuzzer.html#options
local function parse_flag(str)
    local flag_name, flag_val = string.match(str, "-([%l%p]+)=(%w+)")
    if not flag_name or
       not flag_val then
        error(("bad flag: %s"):format(str))
    end
    return flag_name, flag_val
end

local function build_flags(arg, func_args)
    local flags = {}
    for _, arg_str in ipairs(arg) do
        local name, value
        if starts_with(arg_str, "-") then
            name, value = parse_flag(arg_str)
        else
            name, value = "corpus", arg_str
        end
        flags[name] = value
    end

    for flag_name, flag_val in pairs(func_args) do
        if not flags[flag_name] then
            flags[flag_name] = flag_val
        end
    end

    return flags
end

local function Fuzz(test_one_input, custom_mutator, func_args)
    local flags = build_flags(arg, func_args)
    luzer_impl.Fuzz(test_one_input, custom_mutator, flags)
end

return {
    Fuzz = Fuzz,
    FuzzedDataProvider = luzer_impl.FuzzedDataProvider,

    _LLVM_VERSION = luzer_impl._LLVM_VERSION,
    _LUA_VERSION = luzer_impl._LUA_VERSION,
    _LUZER_VERSION = luzer_impl._LUZER_VERSION,

    _set_custom_mutator = luzer_impl._set_custom_mutator,
    _mutate = luzer_impl._mutate,
}
