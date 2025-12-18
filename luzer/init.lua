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
    local flag_name, flag_val = string.match(str, "-([%w_]+)=(.+)")
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
        -- XXX: Ignore the symbol `--` because in the OSS Fuzz it
        -- is followed by libFuzzer arguments.
        if starts_with(arg_str, "-") then
            if arg_str ~= "--" then
                name, value = parse_flag(arg_str)
            end
        else
            name, value = "corpus", arg_str
        end
        if name and value then
            flags[name] = value
        end
    end

    for flag_name, flag_val in pairs(func_args) do
        if not flags[flag_name] then
            flags[flag_name] = flag_val
        end
    end

    return flags
end

local function progname(argv)
    -- arg[-1] is guaranteed to be not nil.
    local idx = -2
    while argv[idx] do
        idx = idx - 1
    end
    return argv[idx + 1]
end

local function Fuzz(test_one_input, custom_mutator, func_args)
    if custom_mutator ~= nil and
       type(custom_mutator) ~= "function"
    then
        error("custom_mutator must be a function")
    end
    local luzer_args = func_args or {}
    if type(luzer_args) ~= "table" then
        error("args is not a table")
    end
    local flags = build_flags(arg, luzer_args)
    local test_path = arg[0]
    local lua_bin = progname(arg)
    local test_cmd = ("%s %s"):format(lua_bin, test_path)
    luzer_impl.Fuzz(test_one_input, custom_mutator, flags, test_cmd)
end

return {
    Fuzz = Fuzz,
    FuzzedDataProvider = luzer_impl.FuzzedDataProvider,
    path = luzer_impl.path,

    _internal = {
        LLVM_VERSION = luzer_impl._LLVM_VERSION,
        LUA_VERSION = luzer_impl._LUA_VERSION,
        LUZER_VERSION = luzer_impl._LUZER_VERSION,

        set_custom_mutator = luzer_impl._set_custom_mutator,
        mutate = luzer_impl._mutate,
        parse_flag = parse_flag,
    }
}
