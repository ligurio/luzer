#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <float.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzed_data_provider.h"
#include "macros.h"

/*
 * A convenience wrapper turning the raw fuzzer input bytes into Lua primitive
 * types. The methods behave similarly to math.random(), with all returned
 * values depending deterministically on the fuzzer input for the current run.
 */

static FuzzedDataProvider *fdp = NULL;

/* Consumes a string from the fuzzer input. */
static int
luaL_consume_string(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument max_length");

	/*
	if (lua_gettop(L) != 1)
		luaL_error(L, "max_length is not a number");

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "max_length is not a number");
	*/

	size_t max_length = lua_tonumber(L, -1);
	lua_pop(L, -1);

	std::string str = fdp->ConsumeRandomLengthString(max_length);
	const char *cstr = str.c_str();
    lua_pushstring(L, cstr);

    return 1;
}

/* Consumes a table with specified number of strings from the fuzzer input. */
static int
luaL_consume_strings(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument count");

	if (lua_type(L, -2) != LUA_TNUMBER)
		luaL_error(L, "bad argument max_length");

	size_t count = lua_tonumber(L, -1);
	lua_pop(L, -1);

	size_t max_length = lua_tonumber(L, -1);
	lua_pop(L, -1);

	std::string str;
	const char *cstr;

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
		str = fdp->ConsumeRandomLengthString(max_length);
		cstr = str.c_str();
		if (strlen(cstr) == 0)
			break;
		lua_pushnumber(L, i);
		lua_pushstring(L, cstr);
		lua_settable(L, -3);
	}

    return 1;
}

/* Consumes a boolean from the fuzzer input. */
static int
luaL_consume_boolean(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	bool b = fdp->ConsumeBool();
    lua_pushboolean(L, (int)b);

    return 1;
}

/* Consumes a table with specified number of booleans from the fuzzer input. */
static int
luaL_consume_booleans(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument count");

	size_t count = lua_tonumber(L, -1);
	lua_pop(L, -1);

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
		bool b = fdp->ConsumeBool();
		lua_pushnumber(L, i);
		lua_pushboolean(L, (int)b);
		lua_settable(L, -3);
	}

    return 1;
}

/* Consumes a float from the fuzzer input. */
static int
luaL_consume_number(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument min");

	if (lua_type(L, -2) != LUA_TNUMBER)
		luaL_error(L, "bad argument max");

	double max = lua_tonumber(L, -1);
	double min = lua_tonumber(L, -2);

	lua_settop(L, 0);

	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	auto number = fdp->ConsumeFloatingPointInRange(min, max);
    lua_pushnumber(L, number);

    return 1;
}

static int
luaL_consume_numbers(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument min");

	if (lua_type(L, -2) != LUA_TNUMBER)
		luaL_error(L, "bad argument max");

	if (lua_type(L, -3) != LUA_TNUMBER)
		luaL_error(L, "bad argument count");

	double min = lua_tonumber(L, -1);
	lua_pop(L, -1);

	double max = lua_tonumber(L, -1);
	lua_pop(L, -1);

	size_t count = lua_tonumber(L, -1);
	lua_pop(L, -1);

	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
	    auto number = fdp->ConsumeFloatingPointInRange(min, max);
		lua_pushnumber(L, i);
		lua_pushnumber(L, number);
		lua_settable(L, -3);
	}

    return 1;
}

/* Consumes an arbitrary int or an int between min and max from the fuzzer
   input. */
static int
luaL_consume_integer(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument min");

	if (lua_type(L, -2) != LUA_TNUMBER)
		luaL_error(L, "bad argument max");

	int max = lua_tonumber(L, -1);
	int min = lua_tonumber(L, -2);

	lua_settop(L, 0);

	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	auto number = fdp->ConsumeIntegralInRange(min, max);
    lua_pushnumber(L, number);

    return 1;
}

/* Consumes an int array from the fuzzer input. */
static int
luaL_consume_integers(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (lua_type(L, -1) != LUA_TNUMBER)
		luaL_error(L, "bad argument min");

	if (lua_type(L, -2) != LUA_TNUMBER)
		luaL_error(L, "bad argument max");

	if (lua_type(L, -3) != LUA_TNUMBER)
		luaL_error(L, "bad argument count");

	size_t count = lua_tonumber(L, -1);
	lua_pop(L, -1);

	int max = lua_tonumber(L, -1);
	lua_pop(L, -1);

	int min = lua_tonumber(L, -1);
	lua_pop(L, -1);

	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
	    auto number = fdp->ConsumeIntegralInRange(min, max);
		lua_pushnumber(L, i);
		lua_pushinteger(L, number);
		lua_settable(L, -3);
	}

	return 1;
}

static int
luaL_consume_probability(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	auto probability = fdp->ConsumeFloatingPointInRange(0.0, 1.0);
    lua_pushnumber(L, probability);

    return 1;
}

/* Returns the number of unconsumed bytes in the fuzzer input. */
static int
luaL_remaining_bytes(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	size_t sz = fdp->remaining_bytes();
    lua_pushnumber(L, sz);

    return 1;
}

/* A useful tool for generating various types of data from the arbitrary bytes
 * produced by the fuzzer.
 */
static const struct {
    char name[30];
    lua_CFunction func;
} FuzzedDataProvider_functions[] = {
	{ "consume_string", luaL_consume_string },
	{ "consume_strings", luaL_consume_strings },
	{ "consume_boolean", luaL_consume_boolean },
	{ "consume_booleans", luaL_consume_booleans },
	{ "consume_number", luaL_consume_number },
	{ "consume_numbers", luaL_consume_numbers },
	{ "consume_integer", luaL_consume_integer },
	{ "consume_integers", luaL_consume_integers },
	{ "consume_probability", luaL_consume_probability },
	{ "remaining_bytes", luaL_remaining_bytes },
};

int
luaL_fuzzed_data_provider(lua_State *L)
{
	if (lua_gettop(L) != 1)
		luaL_error(L, "FuzzedDataProvider accepts a buffer.");

	const char *data = luaL_checkstring(L, 1);
	size_t size = strlen(data);
	fdp = new FuzzedDataProvider((const unsigned char *)data, size);
	size_t n = sizeof(FuzzedDataProvider_functions)/
			   sizeof(FuzzedDataProvider_functions[0]);
	lua_createtable(L, 0, n);
    for (int i = 0; FuzzedDataProvider_functions[i].name[0]; i++) {
        lua_pushstring(L, FuzzedDataProvider_functions[i].name);
        lua_pushcfunction(L, FuzzedDataProvider_functions[i].func);
		lua_settable(L, -3);
    }

    return 1;
}
