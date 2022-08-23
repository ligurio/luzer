#ifndef LUZER_FUZZED_DATA_PROVIDER_H_
#define LUZER_FUZZED_DATA_PROVIDER_H_

int luaL_consume_string(lua_State *L);
int luaL_consume_strings(lua_State *L);
int luaL_consume_boolean(lua_State *L);
int luaL_consume_booleans(lua_State *L);
int luaL_consume_number(lua_State *L);
int luaL_consume_numbers_in_range(lua_State *L);
int luaL_consume_numbers(lua_State *L);
int luaL_consume_integer(lua_State *L);
int luaL_consume_integers_in_range(lua_State *L);
int luaL_consume_integers(lua_State *L);
int luaL_consume_cdata(lua_State *L);
int luaL_consume_userdata(lua_State *L);
int luaL_consume_lightuserdata(lua_State *L);
int luaL_consume_remaining_as_string(lua_State *L);
int luaL_consume_probability(lua_State *L);
/* Consumes the remaining fuzzer input as a byte array. */
int luaL_consume_remaining_bytes(lua_State *L);
/* Returns the number of unconsumed bytes in the fuzzer input. */
int luaL_remaining_bytes(lua_State *L);
int luaL_pick_value_in_table(lua_State *L);

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
	{ "consume_number", luaL_consume_number }, // lua_Number
	{ "consume_numbers", luaL_consume_numbers }, // lua_Number
	{ "consume_numbers_in_range", luaL_consume_numbers_in_range },
	{ "consume_integer", luaL_consume_integer }, // lua_Integer
	{ "consume_integers", luaL_consume_integers },
	{ "consume_integers_in_range", luaL_consume_integers_in_range },
	{ "consume_cdata", luaL_consume_cdata },
	{ "consume_userdata", luaL_consume_userdata }, // https://www.lua.org/pil/28.1.html
	{ "consume_lightuserdata", luaL_consume_lightuserdata }, // https://www.lua.org/pil/28.5.html
	{ "consume_remaining_as_string", luaL_consume_remaining_as_string },
	{ "consume_probability", luaL_consume_probability },
	{ "consume_remaining_bytes", luaL_consume_remaining_bytes },
	{ "remaining_bytes", luaL_remaining_bytes },
	{ "pick_value_in_table", luaL_pick_value_in_table },
};

#endif  // LUZER_FUZZED_DATA_PROVIDER_H_
