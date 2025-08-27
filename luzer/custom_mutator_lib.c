/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2025, Sergey Bronnikov
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include "lua.h"
#include "lauxlib.h"

#include "luzer.h"

#if LUA_VERSION_NUM == 501
#define lua_rawlen(L, i) lua_objlen((L), (i))
#endif

size_t
LLVMFuzzerCustomMutator(uint8_t* data, size_t size,
						size_t max_size, unsigned int seed)
{
	lua_State *L = get_global_lua_state();
	lua_pushlstring(L, (char *)data, size);
	lua_pushinteger(L, max_size);
	lua_pushinteger(L, seed);
	luaL_mutate(L);

	size_t sz = lua_rawlen(L, -1);
	if (sz > max_size)
		luaL_error(L, "The size of mutated data cannot be larger than a max_size.");
	const char *buf = lua_tostring(L, -1);
	free(data);
	data = (uint8_t *)buf;

	return sz;
}
