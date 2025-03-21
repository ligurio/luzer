#include "lua.h"
#include "lauxlib.h"

int say_hello(const char *buf);

static int
lua_say_hello(lua_State *L) {
	luaL_checkstring(L, 1);
	size_t len;
	const char *buf = lua_tolstring(L, 1, &len);
	say_hello(buf);
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
