#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <iostream>

#include "FuzzedDataProvider.h"

#include "fuzzed_data_provider.h"

static FuzzedDataProvider *fdp = NULL;

/*
 * TODO:
 * byte	consumeByte()	Consumes a byte from the fuzzer input.
 * byte	consumeByte(byte min, byte max)	Consumes a byte between min and max from the fuzzer input.
 * byte[]	consumeBytes(int maxLength)	Consumes a byte array from the fuzzer input.
 * char	consumeChar()	Consumes a char from the fuzzer input.
 * char	consumeChar(char min, char max)	Consumes a char between min and max from the fuzzer input.
 *
 * TODO: Unicode, 6.5 – UTF-8 Support
 * https://www.lua.org/manual/5.4/manual.html
*/

/* Consumes an ASCII-only String from the fuzzer input. */
static int
luaL_consume_string(lua_State *L)
{
	/* input: maxLength */
  	// std::string ConsumeBytesAsString(size_t num_bytes);
  	// std::string ConsumeRandomLengthString(size_t max_length);
	// std::string ConsumeRandomLengthString();
    lua_pushstring(L, "string");
    return 1;
}

static int
luaL_consume_strings(lua_State *L)
{
    lua_pushstring(L, "string");
    return 1;
}

/* Consumes a boolean from the fuzzer input. */
static int
luaL_consume_boolean(lua_State *L)
{
	if (!fdp)
		assert(0);
	bool v = fdp->ConsumeBool();
    lua_pushboolean(L, (int)v);
    return 1;
}

/* Consumes a boolean array from the fuzzer input. */
static int
luaL_consume_booleans(lua_State *L)
{
	/* input: int maxLength */
	if (!fdp)
		assert(0);
    /* TODO: accepts a number of elements */
    lua_newtable(L);
    lua_pushnumber(L, 1);
    lua_pushboolean(L, 0);
    lua_settable(L, -3);
    lua_pushnumber(L, 2);
    lua_pushboolean(L, 1);
    lua_settable(L, -3);
    return 1;
}

/* Consumes an int from the fuzzer input. */
static int
luaL_consume_number(lua_State *L)
{
	// template <typename T> T ConsumeFloatingPoint();
  	// template <typename T> T ConsumeIntegral();
    lua_pushnumber(L, 300);
    return 1;
}

static int
luaL_consume_numbers(lua_State *L)
{
	// TODO: luaL_consume_numbers_in_range(lua_State *L)
    /* TODO: test me */
  	// template <typename T> T ConsumeFloatingPointInRange(T min, T max);
    /* input: accepts a number of elements */
    lua_newtable(L);
    lua_pushnumber(L, 1);
    lua_pushnumber(L, 400);
    lua_settable(L, -3);
    lua_pushnumber(L, 2);
    lua_pushnumber(L, 200);
    lua_settable(L, -3);
    return 1;
}

/* Consumes an arbitrary int or an int between min and max from the fuzzer
   input. */
static int
luaL_consume_integer(lua_State *L)
{
	/* input: nil or max/min */
  	// template <typename T> T ConsumeIntegral();
    lua_pushinteger(L, 300);
    return 1;
}

/* Consumes an int array from the fuzzer input. */
static int
luaL_consume_integers(lua_State *L)
{
	/* input: max, min, maxLength */
	// TODO: luaL_consume_integers_in_range(lua_State *L)
  	// template <typename T> T ConsumeIntegralInRange(T min, T max);
    /* TODO: accepts a number of elements */
    lua_newtable(L);
    lua_pushnumber(L, 1);
    lua_pushinteger(L, 230);
    lua_settable(L, -3);
    lua_pushnumber(L, 2);
    lua_pushinteger(L, 430);
    lua_settable(L, -3);
    return 1;
}

/*
static int
luaL_consume_cdata(lua_State *L)
{
    return 0;
}

static int
luaL_consume_userdata(lua_State *L)
{
    return 0;
}

static int
luaL_consume_lightuserdata(lua_State *L)
{
    return 0;
}
*/

static int
luaL_consume_remaining_as_string(lua_State *L)
{
  	// std::string ConsumeRemainingBytesAsString();
	std::vector<int> vi;
	for(int i : vi) 
		std::cout << "i = " << i << std::endl;
	for (auto & element : vi) 
		std::cout << element << " ";
    lua_pushstring(L, "remaining");
    return 1;
}

// 0 <= return value <= 1.
static int
luaL_consume_probability(lua_State *L)
{
	if (!fdp)
		assert(0);
	// template <typename T> T ConsumeProbability();
    /* TODO: test me */
    lua_pushnumber(L, 1);
    return 1;
}

// TODO:
// template <typename T> std::vector<T> ConsumeBytes(size_t num_bytes);

/* Consumes the remaining fuzzer input as a byte array. */
static int
luaL_consume_remaining_bytes(lua_State *L)
{
	// template <typename T> std::vector<T> ConsumeRemainingBytes();
    lua_pushnumber(L, 1);
    return 1;
}

/* Returns the number of unconsumed bytes in the fuzzer input. */
static int
luaL_remaining_bytes(lua_State *L)
{
	if (!fdp)
		assert(0);
	size_t sz = fdp->remaining_bytes();
    lua_pushnumber(L, sz);
    return 1;
}

// TODO: 
// Writes data to the given destination and returns number of bytes written.
//size_t ConsumeData(void *destination, size_t num_bytes);

static int
luaL_pick_value_in_table(lua_State *L)
{
	// template <typename T, size_t size> T PickValueInArray(const T (&array)[size]);
	// template <typename T, size_t size> T PickValueInArray(const std::array<T, size> &array);
	// template <typename T> T PickValueInArray(std::initializer_list<const T> list);
    /* TODO: test me */
    /* TODO: Given a list, pick a random value */
    return 0;
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
	{ "consume_number", luaL_consume_number }, // lua_Number
	{ "consume_numbers", luaL_consume_numbers }, // lua_Number
	{ "consume_integer", luaL_consume_integer }, // lua_Integer
	{ "consume_integers", luaL_consume_integers },
	//{ "consume_cdata", luaL_consume_cdata },
	//{ "consume_userdata", luaL_consume_userdata }, // https://www.lua.org/pil/28.1.html
	//{ "consume_lightuserdata", luaL_consume_lightuserdata }, // https://www.lua.org/pil/28.5.html
	{ "consume_remaining_as_string", luaL_consume_remaining_as_string },
	{ "consume_remaining_bytes", luaL_consume_remaining_bytes },
	{ "consume_probability", luaL_consume_probability },
	{ "remaining_bytes", luaL_remaining_bytes },
	{ "pick_value_in_table", luaL_pick_value_in_table },
};

int
luaL_fuzzed_data_provider(lua_State *L)
{
	/* FIXME: FuzzedDataProvider accepts a buffer and a number of bytes. */
	const char *data = NULL;
	data = luaL_checkstring(L, 1);
	if (!data) {
		lua_pushstring(L, "Wrong FuzzedDataProvider() arguments.");
		lua_error(L);
		unreachable();
		return 0;
	}
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
