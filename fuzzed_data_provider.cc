#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>

#include <fuzzer/FuzzedDataProvider.h>

#include <iostream>

/*
 * TODO:
 * string   consumeString(int maxLength)	Consumes an ASCII-only String from the fuzzer input.
 * boolean	 consumeBoolean()	Consumes a boolean from the fuzzer input.
 * boolean[]	consumeBooleans(int maxLength)	Consumes a boolean array from the fuzzer input.
 * byte	consumeByte()	Consumes a byte from the fuzzer input.
 * byte	consumeByte(byte min, byte max)	Consumes a byte between min and max from the fuzzer input.
 * byte[]	consumeBytes(int maxLength)	Consumes a byte array from the fuzzer input.
 * char	consumeChar()	Consumes a char from the fuzzer input.
 * char	consumeChar(char min, char max)	Consumes a char between min and max from the fuzzer input.
 * int	    consumeInt()	Consumes an int from the fuzzer input.
 * int	    consumeInt(int min, int max)	Consumes an int between min and max from the fuzzer input.
 * int[]	consumeInts(int maxLength)	Consumes an int array from the fuzzer input.
 * java.lang.String	consumeRemainingAsString()	Consumes the remaining fuzzer input as an ASCII-only String.
 *
 * TODO: Unicode, 6.5 – UTF-8 Support
 * https://www.lua.org/manual/5.4/manual.html
*/

extern "C" int
luaL_consume_string(lua_State *L)
{
  	// std::string ConsumeBytesAsString(size_t num_bytes);
  	// std::string ConsumeRandomLengthString(size_t max_length);
	// std::string ConsumeRandomLengthString();
    lua_pushstring(L, "string");
    return 1;
}

extern "C" int
luaL_consume_strings(lua_State *L)
{
    lua_pushstring(L, "string");
    return 1;
}

extern "C" int
luaL_consume_boolean(lua_State *L)
{
	// bool ConsumeBool();
	/*
	const uint8_t *data = {};
	size_t size = 1;
	FuzzedDataProvider* fdp = new FuzzedDataProvider(data, size);
	bool a = fdp->ConsumeBool();
	printf("%i\n", a);
	*/
    lua_pushboolean(L, 1);
    return 1;
}

extern "C" int
luaL_consume_booleans(lua_State *L)
{
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

extern "C" int
luaL_consume_number(lua_State *L)
{
	// template <typename T> T ConsumeFloatingPoint();
  	// template <typename T> T ConsumeIntegral();
    lua_pushnumber(L, 300);
    return 1;
}

extern "C" int
luaL_consume_numbers_in_range(lua_State *L)
{
    /* TODO: test me */
  	// template <typename T> T ConsumeFloatingPointInRange(T min, T max);
    lua_pushnumber(L, 300);
    return 1;
}

extern "C" int
luaL_consume_numbers(lua_State *L)
{
    /* TODO: accepts a number of elements */
    lua_newtable(L);
    lua_pushnumber(L, 1);
    lua_pushnumber(L, 400);
    lua_settable(L, -3);
    lua_pushnumber(L, 2);
    lua_pushnumber(L, 200);
    lua_settable(L, -3);
    return 1;
}

extern "C" int
luaL_consume_integer(lua_State *L)
{
  	// template <typename T> T ConsumeIntegral();
    lua_pushinteger(L, 300);
    return 1;
}

extern "C" int
luaL_consume_integers_in_range(lua_State *L)
{
    /* TODO: test me */
    lua_pushinteger(L, 300);
    return 1;
}

extern "C" int
luaL_consume_integers(lua_State *L)
{
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

extern "C" int
luaL_consume_cdata(lua_State *L)
{
    return 0;
}

extern "C" int
luaL_consume_userdata(lua_State *L)
{
    return 0;
}

extern "C" int
luaL_consume_lightuserdata(lua_State *L)
{
    return 0;
}

extern "C" int
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
extern "C" int
luaL_consume_probability(lua_State *L)
{
	// template <typename T> T ConsumeProbability();
    /* TODO: test me */
    lua_pushnumber(L, 1);
    return 1;
}

// TODO:
// template <typename T> std::vector<T> ConsumeBytes(size_t num_bytes);

/* Consumes the remaining fuzzer input as a byte array. */
extern "C" int
luaL_consume_remaining_bytes(lua_State *L)
{
	// template <typename T> std::vector<T> ConsumeRemainingBytes();
    lua_pushnumber(L, 1);
    return 1;
}

/* Returns the number of unconsumed bytes in the fuzzer input. */
extern "C" int
luaL_remaining_bytes(lua_State *L)
{
	// Reports the remaining bytes available for fuzzed input.
	// size_t remaining_bytes() { return remaining_bytes_; }
    lua_pushnumber(L, 1);
    return 1;
}

// TODO: 
// Writes data to the given destination and returns number of bytes written.
//size_t ConsumeData(void *destination, size_t num_bytes);

extern "C" int
luaL_pick_value_in_table(lua_State *L)
{
	// template <typename T, size_t size> T PickValueInArray(const T (&array)[size]);
	// template <typename T, size_t size> T PickValueInArray(const std::array<T, size> &array);
	// template <typename T> T PickValueInArray(std::initializer_list<const T> list);
    /* TODO: test me */
    /* TODO: Given a list, pick a random value */
    return 0;
}
