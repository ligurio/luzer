/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2025, Sergey Bronnikov
 */

#ifdef __cplusplus
extern "C" {
#endif
#include "lua.h"
#include "lauxlib.h"
#include "lualib.h"
#include <float.h>

int table_nkeys(lua_State *L, int idx);

#ifdef __cplusplus
} /* extern "C" */
#endif
#include <fuzzer/FuzzedDataProvider.h>

#include "fuzzed_data_provider.h"
#include "macros.h"

/**
 * Unique name for userdata metatables.
 */
#define FDP_LUA_UDATA_NAME	"fdp"

/*
 * A convenience wrapper turning the raw fuzzer input bytes into Lua primitive
 * types. The methods behave similarly to math.random(), with all returned
 * values depending deterministically on the fuzzer input for the current run.
 */

typedef struct {
	FuzzedDataProvider *fdp;
} lua_userdata_t;

/* Consumes a string from the fuzzer input. */
NO_SANITIZE static int
luaL_consume_string(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	size_t max_length = luaL_checkinteger(L, 2);

	std::string str = lfdp->fdp->ConsumeRandomLengthString(max_length);
	const char *cstr = str.c_str();
	lua_pushlstring(L, cstr, str.length());

	return 1;
}

/* Consumes a table with specified number of strings from the fuzzer input. */
NO_SANITIZE static int
luaL_consume_strings(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	size_t count = luaL_checkinteger(L, 2);
	size_t max_length = luaL_checkinteger(L, 3);

	lua_newtable(L);
	for (int i = 1; i <= (int)count; i++) {
		std::string str = lfdp->fdp->ConsumeRandomLengthString(max_length);
		const char *cstr = str.c_str();
		lua_pushnumber(L, i);
		lua_pushlstring(L, cstr, str.length());
		lua_settable(L, -3);
	}

	return 1;
}

/* Consumes a boolean from the fuzzer input. */
NO_SANITIZE static int
luaL_consume_boolean(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	bool b = lfdp->fdp->ConsumeBool();
	lua_pushboolean(L, (int)b);

	return 1;
}

/* Consumes a table with specified number of booleans from the fuzzer input. */
NO_SANITIZE static int
luaL_consume_booleans(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
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
NO_SANITIZE static int
luaL_consume_number(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	lua_Number min = luaL_checknumber(L, 2);
	lua_Number max = luaL_checknumber(L, 3);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_Number number = lfdp->fdp->ConsumeFloatingPointInRange(min, max);
	lua_pushnumber(L, number);

	return 1;
}

/* Consumes a table with specified number of numbers from the fuzzer input. */
NO_SANITIZE static int
luaL_consume_numbers(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	lua_Number min = luaL_checkinteger(L, 2);
	lua_Number max = luaL_checkinteger(L, 3);
	lua_Integer count = luaL_checkinteger(L, 4);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_newtable(L);
	for (lua_Integer i = 1; i <= count; i++) {
		lua_Number number = lfdp->fdp->ConsumeFloatingPointInRange(min, max);
		lua_pushnumber(L, i);
		lua_pushnumber(L, number);
		lua_settable(L, -3);
	}

	return 1;
}

/* Consumes an arbitrary int or an int between min and max from the fuzzer
   input. */
NO_SANITIZE static int
luaL_consume_integer(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	lua_Integer min = luaL_checkinteger(L, 2);
	lua_Integer max = luaL_checkinteger(L, 3);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_Integer number = lfdp->fdp->ConsumeIntegralInRange(min, max);
	lua_pushinteger(L, number);

	return 1;
}

/* Consumes an int array from the fuzzer input. */
NO_SANITIZE static int
luaL_consume_integers(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	lua_Integer min = luaL_checkinteger(L, 2);
	lua_Integer max = luaL_checkinteger(L, 3);
	int count = luaL_checkinteger(L, 4);
	if (min > max)
		luaL_error(L, "min must be less than or equal to max");

	lua_newtable(L);
	for (lua_Integer i = 1; i <= (lua_Integer)count; i++) {
		lua_Integer number = lfdp->fdp->ConsumeIntegralInRange(min, max);
		lua_pushnumber(L, i);
		lua_pushinteger(L, number);
		lua_settable(L, -3);
	}

	return 1;
}

NO_SANITIZE static int
luaL_consume_probability(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	auto probability = lfdp->fdp->ConsumeFloatingPointInRange(0.0, 1.0);
	lua_pushnumber(L, probability);

	return 1;
}

/* Returns the number of unconsumed bytes in the fuzzer input. */
NO_SANITIZE static int
luaL_remaining_bytes(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	size_t sz = lfdp->fdp->remaining_bytes();
	lua_pushnumber(L, sz);

	return 1;
}

/* Returns a random element of the specified array. */
NO_SANITIZE static int
luaL_oneof(lua_State *L)
{
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	luaL_checktype(L, 2, LUA_TTABLE);

	int len = 0;
#if LUA_VERSION_NUM == 501
	len = table_nkeys(L, 2);
#else
	len = lua_rawlen(L, 2);
#endif
	if (len == 0) {
		lua_pushnil(L);
		return 1;
	}
	int idx = lfdp->fdp->ConsumeIntegralInRange(1, len);
	lua_pushinteger(L, idx);
	lua_gettable(L, -2);
	lua_pushinteger(L, idx);

	return 2;
}

NO_SANITIZE static int close(lua_State *L) {
	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t *)luaL_checkudata(L, 1, FDP_LUA_UDATA_NAME);
	delete lfdp->fdp;

	return 0;
}

NO_SANITIZE static int tostring(lua_State *L) {
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
	{ "oneof", luaL_oneof },
	{ "__gc", close },
	{ "__tostring", tostring },
	{ NULL, NULL }
};

/*
 * Create the metatable once on the luzer loading to be more GC and JIT
 * friendly. `luaL_fuzzed_data_provider()` is called in the loop inside
 * `LLVMFuzzerRunDriver()`.
 */
NO_SANITIZE void
fdp_metatable_init(lua_State *L)
{
	luaL_newmetatable(L, FDP_LUA_UDATA_NAME);
	lua_pushvalue(L, -1);
	lua_setfield(L, -2, "__index");
#if LUA_VERSION_NUM == 501
	luaL_register(L, NULL, methods);
#else
	luaL_setfuncs(L, methods, 0);
#endif
	lua_pop(L, 1); /* Remove the metatable from the stack. */
}

NO_SANITIZE int
luaL_fuzzed_data_provider(lua_State *L)
{
	int index = lua_gettop(L);
	if (index != 1)
		luaL_error(L, "Usage: luzer.FuzzedDataProvider(string)");

	/*
	 * The function `luaL_checklstring()` uses `lua_tolstring()`
	 * to get its result, the resulting string can contain zeros
	 * in its body.
	 */
	size_t size;
	const char *data = luaL_checklstring(L, 1, &size);

	lua_userdata_t *lfdp;
	lfdp = (lua_userdata_t*)lua_newuserdata(L, sizeof(*lfdp));
	FuzzedDataProvider *fdp = new FuzzedDataProvider((const unsigned char *)data, size);
	lfdp->fdp = fdp;

	luaL_getmetatable(L, FDP_LUA_UDATA_NAME);
	lua_setmetatable(L, -2);

	return 1;
}
