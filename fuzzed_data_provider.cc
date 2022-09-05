#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzed_data_provider.h"
#include "macros.h"

/*
 * A convenience wrapper turning the raw fuzzer input bytes into Lua primitive
 * types. The methods behave similarly to math.random(), with all returned
 * values depending deterministically on the fuzzer input for the current run.
 *
 * https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
 */

/* TODO: it should be gc'ed, otherwise it is not thread-safe  */
static FuzzedDataProvider *fdp = NULL;

/*
static int
luaL_min_max(lua_State *L, size_t *min, size_t *max)
{
	// nil or max/min
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "max is not a number");
	*max = lua_tonumber(L, -1);
	lua_pop(L, -1);

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "min is not a number");
	*min = lua_tonumber(L, -1);
	lua_pop(L, -1);

	printf("%zu %zu\n", *min, *max);

    return 0;
}
*/

/*
 * TODO: Unicode, 6.5 – UTF-8 Support
 * https://www.lua.org/manual/5.4/manual.html
 */

/* Consumes a string from the fuzzer input. */
static int
luaL_consume_string(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "max_length is not a number");
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

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "size is not a number");
	size_t size = lua_tonumber(L, -1);
	lua_pop(L, -1);

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "max_length is not a number");
	size_t max_length = lua_tonumber(L, -1);
	lua_pop(L, -1);

	std::string str;
	const char *cstr;

	lua_newtable(L);
	for (int i = 1; i <= (int)size; i++) {
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

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "size is not a number");
	size_t size = lua_tonumber(L, -1);
	lua_pop(L, -1);

	lua_newtable(L);
	for (int i = 1; i <= (int)size; i++) {
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

	//size_t min, max;
	//luaL_min_max(L, &min, &max);

	/*
	template <typename T> integer = fdp->ConsumeIntegralInRange(min, max);
    lua_pushnumber(L, cstr);

	template <typename T> T ConsumeFloatingPoint();
	template <typename T> T ConsumeIntegral();
	*/

    lua_pushnumber(L, 300);

    return 1;
}

static int
luaL_consume_numbers(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "size is not a number");
	size_t size = lua_tonumber(L, -1);
	lua_pop(L, -1);

	lua_newtable(L);
	for (int i = 1; i <= (int)size; i++) {
		lua_pushnumber(L, i);
		lua_pushnumber(L, 1);
		lua_settable(L, -3);
	}
	// If there's no input data left, returns |min|. Note that
	// |min| must be less than or equal to |max|.
  	// template <typename T> T ConsumeFloatingPointInRange(T min, T max);

    return 1;
}

/* Consumes an arbitrary int or an int between min and max from the fuzzer
   input. */
static int
luaL_consume_integer(lua_State *L)
{
	/* input: nil or max/min */
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	//size_t min, max;
	//luaL_min_max(L, &min, &max);

  	// template <typename T> T ConsumeIntegral();
    lua_pushinteger(L, 300);
    return 1;
}

/* Consumes an int array from the fuzzer input. */
static int
luaL_consume_integers(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	if (!(lua_isnumber(L, -1) == 1))
		luaL_error(L, "size is not a number");
	size_t size = lua_tonumber(L, -1);
	lua_pop(L, -1);

	lua_newtable(L);
	for (int i = 1; i <= (int)size; i++) {
		lua_pushnumber(L, i);
		lua_pushinteger(L, 1);
		lua_settable(L, -3);
	}

  	// template <typename T> T ConsumeIntegralInRange(T min, T max);

	return 1;
}

// 0 <= return value <= 1.
static int
luaL_consume_probability(lua_State *L)
{
	if (!fdp)
		luaL_error(L, "FuzzedDataProvider is not initialized");

	// template <typename T> T ConsumeProbability();
	//T probability = fdp->ConsumeProbability();
    lua_pushnumber(L, 1);

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
