#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <float.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzed_data_provider.h"
#include "macros.h"

#define FDP_META "fdp_meta"

/*
 * A convenience wrapper turning the raw fuzzer input bytes into Lua primitive
 * types. The methods behave similarly to math.random(), with all returned
 * values depending deterministically on the fuzzer input for the current run.
 */

typedef struct {
	FuzzedDataProvider *fdp;
} lua_userdata_t;

/* Consumes a string from the fuzzer input. */
static int
luaL_consume_string(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	size_t max_length = luaL_checkinteger(L, 2);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_string(max_length)");

	std::string str = lfdp->fdp->ConsumeRandomLengthString(max_length);
	const char *cstr = str.c_str();
    lua_pushstring(L, cstr);

    return 1;
}

/* Consumes a table with specified number of strings from the fuzzer input. */
static int
luaL_consume_strings(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_strings(count, max_length)");
	size_t count = luaL_checkinteger(L, 2);
	size_t max_length = luaL_checkinteger(L, 3);

	std::string str;
	const char *cstr;

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
		str = lfdp->fdp->ConsumeRandomLengthString(max_length);
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
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_boolean()");

	bool b = lfdp->fdp->ConsumeBool();
    lua_pushboolean(L, (int)b);

    return 1;
}

/* Consumes a table with specified number of booleans from the fuzzer input. */
static int
luaL_consume_booleans(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_booleans(count)");
	int count = luaL_checkinteger(L, 2);

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
		bool b = lfdp->fdp->ConsumeBool();
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
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_number(min, max)");
	double min = luaL_checknumber(L, 2);
	double max = luaL_checknumber(L, 3);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	auto number = lfdp->fdp->ConsumeFloatingPointInRange(min, max);
    lua_pushnumber(L, number);

    return 1;
}

/* Consumes a table with specified number of numbers from the fuzzer input. */
static int
luaL_consume_numbers(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_numbers(count, min, max)");
	int count = luaL_checkinteger(L, 2);
	double min = luaL_checkinteger(L, 3);
	double max = luaL_checkinteger(L, 4);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_newtable(L);
	for (int i = 1; i <= count; i++) {
	    auto number = lfdp->fdp->ConsumeFloatingPointInRange(min, max);
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
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_integer(min, max)");
	int min = luaL_checkinteger(L, 2);
	int max = luaL_checkinteger(L, 3);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	auto number = lfdp->fdp->ConsumeIntegralInRange(min, max);
    lua_pushnumber(L, number);

    return 1;
}

/* Consumes an int array from the fuzzer input. */
static int
luaL_consume_integers(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_integers(count, min, max)");
	int count = luaL_checkinteger(L, 2);
	int min = luaL_checkinteger(L, 3);
	int max = luaL_checkinteger(L, 4);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
	    auto number = lfdp->fdp->ConsumeIntegralInRange(min, max);
		lua_pushnumber(L, i);
		lua_pushinteger(L, number);
		lua_settable(L, -3);
	}

	return 1;
}

static int
luaL_consume_probability(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:consume_probability()");

	auto probability = lfdp->fdp->ConsumeFloatingPointInRange(0.0, 1.0);
    lua_pushnumber(L, probability);

    return 1;
}

/* Returns the number of unconsumed bytes in the fuzzer input. */
static int
luaL_remaining_bytes(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	if (!lfdp)
		luaL_error(L, "Usage: <FuzzedDataProvider>:remaining_bytes()");

	size_t sz = lfdp->fdp->remaining_bytes();
    lua_pushnumber(L, sz);

    return 1;
}

static int close(lua_State *L) {
/*
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_META);
	FuzzedDataProvider fdp = lfdp->fdp;
	delete fdp;
*/
	return 0;
}

static int tostring(lua_State *L) {
	lua_pushstring(L, "FuzzedDataProvider");
	return 1;
}

const luaL_Reg methods[] =
{
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
	{ "__gc", close },
	{ "__tostring", tostring },
	{ NULL, NULL }
};

int
luaL_fuzzed_data_provider(lua_State *L)
{
	int index = lua_gettop(L);
	if (index != 1)
		luaL_error(L, "Usage: luzer.FuzzedDataProvider(string)");

	const char *data = luaL_checkstring(L, 1);
	size_t size = strlen(data);

	luaL_newmetatable(L, "sshmeta");
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
	luaL_register(L, NULL, methods);

	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t*)lua_newuserdata(L, sizeof(*lfdp));
	FuzzedDataProvider *fdp = new FuzzedDataProvider((const unsigned char *)data, size);
	lfdp->fdp = fdp;

	luaL_getmetatable(L, "sshmeta");
	lua_setmetatable(L, -2);

	return 1;
}
