#include <stdlib.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

#define MESSAGE "Hello, Lua!"

static int
say_hello(lua_State *L) {
	luaL_checkstring(L, 1);
	size_t len;
	const char *buf = lua_tolstring(L, 1, &len);
	if (strncmp(buf, MESSAGE, sizeof(MESSAGE)) == 0) {
		fprintf(stderr, "Crash!\n");
		abort();
	}

    return 1;
}

static const struct luaL_Reg functions [] = {
    { "say_hello", say_hello },
    { NULL, NULL }
};

int luaopen_hello(lua_State *L) {
    luaL_register(L, "hello", functions);
    return 1;
}
