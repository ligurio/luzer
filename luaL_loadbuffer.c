/*
 * https://github.com/ouspg/libfuzzerfication/blob/master/stubs/lua/lua-fuzzer.c
 * https://github.com/google/oss-fuzz/blob/master/projects/lua/fuzz_lua.c
 *
 * https://github.com/squeek502/fuzzing-lua/blob/master/src/llex_helper.c
 * https://github.com/squeek502/fuzzing-lua/blob/master/fuzz/fuzz_llex.cc
 *
 * https://github.com/tarantool/tarantool/commit/0a8d9bca190093b6ac9b1a35d0bb8b1f78d96a35#diff-245097b92eb89f1b85e51c6eb09303108fd34c04529b4e7090b50455eccce322
 *
 * https://www.lua.org/pil/24.1.html
 * https://www.lua.org/source/5.1/lua.c.html
 */

#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    lua_State *L = luaL_newstate();
	if (L == NULL) {
		return -1;
	}
    luaL_openlibs(L);
    int status = luaL_loadbuffer(L, (const char *)data, size, "fuzz_test");
    if (status) {
        goto lua_exit;
    }
    int result = lua_pcall(L, 0, LUA_MULTRET, 0);
    if (result) {
        goto lua_exit;
    }

lua_exit:
    lua_pop(L, 1);
    lua_close(L);

    return 0;
}

#ifdef CUSTOM_MUTATOR

#include "libfuzzer_mutator.cpp"

#endif // CUSTOM_MUTATOR
