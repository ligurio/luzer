#include "lua.h"
#include "lauxlib.h"
// #include <fuzzer/FuzzedDataProvider.h>

#define LUZER_VERSION "0.1.0"

/*
 * A convenience wrapper turning the raw fuzzer input bytes into Lua primitive
 * types. The methods behave similarly to math.random(), with all returned
 * values depending deterministically on the fuzzer input for the current run.
 *
 * https://github.com/llvm/llvm-project/blob/main/compiler-rt/include/fuzzer/FuzzedDataProvider.h
 * https://github.com/google/atheris#fuzzeddataprovider
 * https://github.com/google/fuzzing/blob/master/docs/split-inputs.md
 * https://codeintelligencetesting.github.io/jazzer-api/com/code_intelligence/jazzer/api/FuzzedDataProvider.html
*/

static int
luaL_consume_string(lua_State *L)
{
    lua_pushstring(L, "string");
    return 1;
}

static int
luaL_consume_boolean(lua_State *L)
{
    lua_pushboolean(L, 1);
    return 1;
}

static int
luaL_consume_booleans(lua_State *L)
{
    lua_newtable(L);
    lua_pushboolean(L, 1);
    lua_pushboolean(L, 0);
    lua_rawset(L, -3);
    return 1;
}

static int
luaL_consume_number(lua_State *L)
{
    lua_pushnumber(L, 300);
    return 1;
}

static int
luaL_consume_numbers(lua_State *L)
{
    lua_newtable(L);
    lua_pushnumber(L, 200);
    lua_pushnumber(L, 400);
    lua_rawset(L, -3);
    return 1;
}

static int
luaL_consume_integer(lua_State *L)
{
    lua_pushinteger(L, 300);
    return 1;
}

static int
luaL_consume_integers(lua_State *L)
{
    lua_newtable(L);
    lua_pushinteger(L, 200);
    lua_pushinteger(L, 400);
    lua_rawset(L, -3);
    return 1;
}

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

static int
luaL_consume_remaining_as_string(lua_State *L)
{
    lua_pushstring(L, "remaining");
    return 1;
}

static int
luaL_remaining_bytes(lua_State *L)
{
    lua_pushnumber(L, 1);
    return 1;
}

/*
 * Setup(args, test_one_input, internal_libfuzzer=None)
 *
 * args: A table of strings: the process arguments to pass to the fuzzer,
 * typically sys.argv. This argument list may be modified in-place, to remove
 * arguments consumed by the fuzzer. See the LibFuzzer docs for a list of such
 * options.
 *
 * test_one_input: your fuzzer's entry point. Must take a single bytes
 * argument. This will be repeatedly invoked with a single bytes container.
 *
 * internal_libfuzzer: Indicates whether libfuzzer will be provided by atheris
 * or by an external library. If unspecified, luzer will determine this
 * automatically. If fuzzing pure Lua, leave this as True.
 */
static int
luaL_setup(lua_State *L)
{

    return 0;
}

/*
 * Fuzz()
 *
 * This starts the fuzzer. You must have called Setup() before calling this
 * function. This function does not return.
 *
 * In many cases Setup() and Fuzz() could be combined into a single function,
 * but they are separated because you may want the fuzzer to consume the
 * command-line arguments it handles before passing any remaining arguments to
 * another setup function.
 */
static int
luaL_fuzz(lua_State *L)
{
    return 0;
}

static const struct luaL_Reg Module[] = {
	{ "Setup", luaL_setup },
	{ "Fuzz", luaL_fuzz },
	{ NULL, NULL }
};

/* A useful tool for generating various types of data from the arbitrary bytes
 * produced by the fuzzer.
 */
static const struct {
    char name[32];
    lua_CFunction func;
} FuzzedDataProvider_functions[] = {
	{"consume_string", luaL_consume_string},
	{"consume_boolean", luaL_consume_boolean},
	{"consume_booleans", luaL_consume_booleans},
	{"consume_number", luaL_consume_number}, // lua_Number
	{"consume_numbers", luaL_consume_numbers},
	{"consume_integer", luaL_consume_integer}, // lua_Integer
	{"consume_integers", luaL_consume_integers},
	{"consume_cdata", luaL_consume_cdata},
	{"consume_userdata", luaL_consume_userdata}, // https://www.lua.org/pil/28.1.html
	{"consume_lightuserdata", luaL_consume_lightuserdata}, // https://www.lua.org/pil/28.5.html
	{"consume_remaining_as_string", luaL_consume_remaining_as_string},
	{"remaining_bytes", luaL_remaining_bytes},
};

/*
string   consumeString(int maxLength)	Consumes an ASCII-only String from the fuzzer input.
boolean	 consumeBoolean()	Consumes a boolean from the fuzzer input.
boolean[]	consumeBooleans(int maxLength)	Consumes a boolean array from the fuzzer input.
byte	consumeByte()	Consumes a byte from the fuzzer input.
byte	consumeByte(byte min, byte max)	Consumes a byte between min and max from the fuzzer input.
byte[]	consumeBytes(int maxLength)	Consumes a byte array from the fuzzer input.
char	consumeChar()	Consumes a char from the fuzzer input.
char	consumeChar(char min, char max)	Consumes a char between min and max from the fuzzer input.
int	    consumeInt()	Consumes an int from the fuzzer input.
int	    consumeInt(int min, int max)	Consumes an int between min and max from the fuzzer input.
int[]	consumeInts(int maxLength)	Consumes an int array from the fuzzer input.
java.lang.String	consumeRemainingAsString()	Consumes the remaining fuzzer input as an ASCII-only String.
byte[]	consumeRemainingAsBytes()	Consumes the remaining fuzzer input as a byte array.
int	remainingBytes()	Returns the number of unconsumed bytes in the fuzzer input.
*/

int luaopen_libluzer(lua_State *L)
{
    luaL_register(L, "luzer", Module);

    lua_pushstring(L, "VERSION");
    lua_pushstring(L, LUZER_VERSION);
    lua_rawset(L, -3);

    lua_pushliteral(L, "FuzzedDataProvider");
    lua_newtable(L);

    for (int i = 0; FuzzedDataProvider_functions[i].name[0]; i++) {
        lua_pushstring(L, FuzzedDataProvider_functions[i].name);
        lua_pushcfunction(L, FuzzedDataProvider_functions[i].func);
        lua_rawset(L, -3);
    }
    lua_rawset(L, -3);

    return 1;
}
