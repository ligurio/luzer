#include <assert.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

int say_hello(const char *buf, size_t len);

static int
lua_say_hello(lua_State *L) {
	luaL_checkstring(L, 1);
	/*
	 * The length is required, because a string returned by
	 * lua_tolstring() is always has a zero ('\0') after its last
	 * character (as in C), but can contain other zeros in its
	 * body.
	 */
	size_t len;
	const char *str = lua_tolstring(L, 1, &len);
	/* The length is reduced intentionally. */
	say_hello(str, len - 1);
	lua_pop(L, 1);
	return 0;
};

static const struct luaL_Reg functions [] = {
	{ "say_hello", lua_say_hello },
	{ NULL, NULL }
};

int luaopen_luac(lua_State *L) {
#if LUA_VERSION_NUM == 501
	luaL_register(L, "luac", functions);
#else
	luaL_newlib(L, functions);
#endif
	return 1;
}
