#include <stdio.h>
#include <stdint.h>
#include <lua.h>

#include "luzer.h"

size_t
LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
						size_t max_size, unsigned int seed)
{
	printf("LLVMFuzzerCustomMutator\n");
	lua_State *L = get_global_lua_stack();
	lua_pushstring(L, (char *)data);
	lua_pushinteger(L, size);
	lua_pushinteger(L, max_size);
	lua_pushinteger(L, seed);

	return luaL_mutate(L);
}
