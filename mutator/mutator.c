/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2023, Sergey Bronnikov
 */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static const char *script_default = "./mutator.lua";

static size_t
luaL_custom_mutator(lua_State* L, const char *path, const char *func_name,
					uint8_t *data, size_t size,
					size_t max_size, unsigned int seed)
{
	luaL_dofile(L, path);
	lua_getglobal(L, func_name);
	if (!lua_isfunction(L, -1))
		luaL_error(L, "'%s' is not a function", func_name);
	lua_pushlstring(L, (const char*)data, size);
	lua_pushinteger(L, max_size);
	lua_pushinteger(L, seed);
	/* do the call (3 arguments, 2 results) */
	if (lua_pcall(L, 3, 2, 0) != 0)
		luaL_error(L, "error running function '%s': %s",
				   func_name, lua_tostring(L, -1));

	if (!lua_isnumber(L, -1)) {
		luaL_error(L, "'%s' must return a number", func_name);
	}
	size_t ret_size = lua_tonumber(L, -1) - 1;
	lua_pop(L, 1);

	if (!lua_isstring(L, -1)) {
		luaL_error(L, "'%s' must return a string", func_name);
	}
	const char *res = lua_tolstring(L, -1, &ret_size);
	lua_pop(L, 1);

	*data = *res;

	return ret_size;
}

size_t
LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                        size_t MaxSize, unsigned int Seed)
{
	const char *script_env = "LIBFUZZER_LUA_SCRIPT";
	const char *script_func = "LLVMFuzzerCustomMutator";
	const char *script_path = getenv(script_env) ? : script_default;

	if (access(script_path, F_OK) != 0) {
		fprintf(stderr, "Script (%s) is not accessible.\n", script_path);
		_exit(1);
	}

	lua_State* L = luaL_newstate();
	if (!L) {
		fprintf(stderr, "Unable to create Lua state.\n");
		abort();
	}
	luaL_openlibs(L);
	size_t ret_size = luaL_custom_mutator(L, script_path, script_func,
										  Data, Size, MaxSize, Seed);
	lua_close(L);

	return ret_size;
}
