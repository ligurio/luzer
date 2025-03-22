#include <assert.h>
#include <string.h>

#include "lua.h"
#include "lauxlib.h"

int say_hello(const char *buf, size_t len);

static int
lua_say_hello(lua_State *L) {
	size_t len;
	/*
	 * The length is required, because a string returned by
	 * lua_tolstring() is always has a zero ('\0') after its last
	 * character (as in C), but can contain other zeros in its
	 * body.
	 */
	const char *str = luaL_checklstring(L, 1, &len);
	say_hello(str, len);
	lua_pop(L, 1);
	return 0;
};

static const struct luaL_Reg functions [] = {
	{ "say_hello", lua_say_hello },
	{ NULL, NULL }
};

#define _lib_name_cat(name) luaopen_ ## name
#define build_lib_name(name) _lib_name_cat(name)
#define lib_name build_lib_name(LIB_NAME)

int lib_name(lua_State *L) {
#if LUA_VERSION_NUM == 501
	luaL_register(L, "luac", functions);
#else
	luaL_newlib(L, functions);
#endif
	return 1;
}
