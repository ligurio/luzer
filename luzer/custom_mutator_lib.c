#include <stdio.h>
#include <stdint.h>
#include <lua.h>

#include "macros.h"
#include "luzer.h"

size_t
LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
						size_t max_size, unsigned int seed)
{
	//lua_State *L = get_global_lua_stack();
	printf("LLVMFuzzerCustomMutator\n");
	//return luaL_mutate(L, data, size, max_size, seed);
	return 0;
}
