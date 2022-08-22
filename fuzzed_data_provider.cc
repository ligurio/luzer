#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include "FuzzedDataProvider.h"

/*
void lua_consume_bool() {
	const uint8_t *data = {};
	size_t size = 1;
	FuzzedDataProvider* fdp = new FuzzedDataProvider(data, size);
	bool a = fdp->ConsumeBool();
	printf("%i\n", a);
}
*/

static int
luaL_consume_boolean(lua_State *L)
{
	const uint8_t *data = {};
	size_t size = 1;
	FuzzedDataProvider* fdp = new FuzzedDataProvider(data, size);
	bool a = fdp->ConsumeBool();
	printf("%i\n", a);
    lua_pushboolean(L, 1);
    return 1;
}
