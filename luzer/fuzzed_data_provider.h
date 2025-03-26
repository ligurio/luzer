#ifndef LUZER_FUZZED_DATA_PROVIDER_H_
#define LUZER_FUZZED_DATA_PROVIDER_H_

#ifdef __cplusplus
extern "C" {
#endif
	void fdp_metatable_init(lua_State *L);
	int luaL_fuzzed_data_provider(lua_State *L);
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // LUZER_FUZZED_DATA_PROVIDER_H_
