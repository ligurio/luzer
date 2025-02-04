local ok, luzer_impl = pcall(require, "luzer_impl")
if not ok then
    error(("error on loading luzer_impl: %s"):format(luzer_impl))
end

return {
    Fuzz = luzer_impl.Fuzz,
    FuzzedDataProvider = luzer_impl.FuzzedDataProvider,

    _LLVM_VERSION = luzer_impl._LLVM_VERSION,
    _LUA_VERSION = luzer_impl._LUA_VERSION,
    _LUZER_VERSION = luzer_impl._LUZER_VERSION,

    _set_custom_mutator = luzer_impl._set_custom_mutator,
    _mutate = luzer_impl._mutate,
}
