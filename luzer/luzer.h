#ifndef LUZER_MACROS_H_
#define LUZER_MACROS_H_

#ifdef __cplusplus
extern "C" {
#endif
	int luaL_mutate(lua_State *L);
	lua_State * get_global_lua_stack();
#ifdef __cplusplus
} /* extern "C" */
#endif

#endif  // LUZER_MACROS_H_
