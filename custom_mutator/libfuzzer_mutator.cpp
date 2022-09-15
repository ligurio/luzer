#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char *script_env = "LIBFUZZER_MUTATOR_LUA_SCRIPT";
static const char *script_default = "./libfuzzer_mutator.lua";
static const char *script_func = "LLVMFuzzerCustomMutator";

static size_t custom_mutator(uint8_t *Data, size_t Size,
				     size_t MaxSize, unsigned int Seed) {
	const char *script_path = getenv(script_env) ? : script_default;
	if (!script_path) {
		fprintf(stderr, "LIBFUZZER_MUTATOR_LUA_SCRIPT is not specified.\n");
		return -1;
	}
	/* TODO: make sure file specified by LIBFUZZER_MUTATOR_LUA_SCRIPT is exist */
	lua_State* L = luaL_newstate();
	if (!L) {
		fprintf(stderr, "Unable to create Lua state.\n");
		return -1;
	}
	luaL_openlibs(L);
	luaL_dofile(L, script_path);
	lua_getglobal(L, script_func);
	int rc = lua_isfunction(L, -1);
	if (rc != 1) {
		fprintf(stderr, "'%s' is not a Lua function.\n", script_func);
		return -1;
	}
	lua_pushlstring(L, (const char*)Data, Size);
	lua_pushinteger(L, Size);
	lua_pushinteger(L, MaxSize);
	lua_pushinteger(L, Seed);
	const int num_args = 4;
	const int num_return_values = 1;
	lua_call(L, num_args, num_return_values);
	rc = lua_isnumber(L, 1);
	if (rc != 1) {
		fprintf(stderr, "'%s' returns a value that is not an integer.\n", script_func);
		return -1;
	}
	const int size = lua_tointeger(L, 1);
	lua_pop(L, 1);
	lua_close(L);

	return size;
}

size_t LLVMFuzzerCustomMutator(uint8_t *Data, size_t Size,
                               size_t MaxSize, unsigned int Seed) {
	return custom_mutator(Data, Size, MaxSize, Seed);
}

#ifndef CUSTOM_MUTATOR

int main() {
    uint8_t Data[] = { 'H', 'i', ',', 'L', 'i', 'b', 'f', 'u', 'z', 'z', 'e', 'r' };
	size_t Size = 12;
	size_t MaxSize = 13;
	size_t Seed = 98;
	size_t res = custom_mutator(Data, Size, MaxSize, Seed);
	fprintf(stdout, "DEBUG: result %zu\n", res);

	return 0;
}

#endif // CUSTOM_MUTATOR
