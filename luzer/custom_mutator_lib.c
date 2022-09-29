#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <lua.h>
#include <lauxlib.h>

#include "luzer.h"

#ifdef __cplusplus
extern "C" {
#endif
int luaL_error(lua_State *L, const char *fmt, ...);
#ifdef __cplusplus
} /* extern "C" */
#endif

size_t
LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
						size_t max_size, unsigned int seed)
{
	lua_State *L = get_global_lua_stack();
	lua_pushstring(L, (char *)data);
	lua_pushinteger(L, size);
	lua_pushinteger(L, max_size);
	lua_pushinteger(L, seed);
	luaL_mutate(L);

	size_t sz = lua_objlen(L, -1);
	if (sz > max_size)
		luaL_error(L, "The size of mutated data cannot be larger than a max_size.");
	const char *buf = lua_tostring(L, -1);
	free(data);
	data = (uint8_t *)buf;

	return sz;
}
