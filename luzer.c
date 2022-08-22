#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <assert.h>

//#include "FuzzedDataProvider.h"

#define LUZER_VERSION "0.1.0"

/*
 * https://releases.llvm.org/8.0.0/tools/clang/docs/SanitizerCoverage.html
 * https://chromium.googlesource.com/chromiumos/third_party/compiler-rt/+/google/stable/include/sanitizer/common_interface_defs.h
 * https://github.com/llvm-mirror/llvm/blob/master/lib/Transforms/Instrumentation/SanitizerCoverage.cpp
 *
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

static int
luaL_consume_number(lua_State *L)
{
    lua_pushnumber(L, 300);
    return 1;
}

static int
luaL_consume_numbers_in_range(lua_State *L)
{
    /* TODO: test me */
    lua_pushnumber(L, 300);
    return 1;
}

static int
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

static int
luaL_consume_integer(lua_State *L)
{
    lua_pushinteger(L, 300);
    return 1;
}

static int
luaL_consume_integers_in_range(lua_State *L)
{
    /* TODO: test me */
    lua_pushinteger(L, 300);
    return 1;
}

static int
luaL_consume_integers(lua_State *L)
{
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
luaL_consume_probability(lua_State *L)
{
    /* TODO: test me */
    lua_pushnumber(L, 1);
    return 1;
}

/* Consumes the remaining fuzzer input as a byte array. */
static int
luaL_consume_remaining_bytes(lua_State *L)
{
    lua_pushnumber(L, 1);
    return 1;
}

/* Returns the number of unconsumed bytes in the fuzzer input. */
static int
luaL_remaining_bytes(lua_State *L)
{
    lua_pushnumber(L, 1);
    return 1;
}

static int
luaL_pick_value_in_table(lua_State *L)
{
    /* TODO: test me */
    /* TODO: Given a list, pick a random value */
    return 0;
}

/*
 * Setup(args, test_one_input, internal_libfuzzer=None)
 *
 * args: A table of strings: the process arguments to pass to the fuzzer,
 * typically `argv`. This argument list may be modified in-place, to remove
 * arguments consumed by the fuzzer. See the LibFuzzer docs for a list of such
 * options.
 *
 * test_one_input: your fuzzer's entry point. Must take a single bytes
 * argument. This will be repeatedly invoked with a single bytes container.
 *
 * internal_libfuzzer: Indicates whether libfuzzer will be provided by luzer or
 * by an external library. If unspecified, luzer will determine this
 * automatically. If fuzzing pure Lua, leave this as True.
 */
static int
l_setup(lua_State *L)
{
	/* argv */
	if (!lua_istable(L, 1)) {
		assert(0);
	}
	if (lua_isfunction(L, 2) != 1) {
		assert(0);
	}
	/*
	 * TODO:
	extern "C" int LLVMFuzzerInitialize(int *argc, char ***argv) {
	  return 0;
	}
	*/
	/* Optional function */
	if (lua_isfunction(L, 3) != 1) {
	}
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
l_fuzz(lua_State *L)
{
    /* TODO: calls LibFuzzer's Fuzz() function */
	// LLVMFuzzerTestOneInput
    return 0;
}

static int
l_require_instrument(lua_State *L)
{
    /* TODO: wraps "require()" and remember instrumented modules */
    return 0;
}

static int
l_custom_mutator(lua_State *L)
{
    /* TODO: process data, max_size, seed */
    return 0;
}

/* A useful tool for generating various types of data from the arbitrary bytes
 * produced by the fuzzer.
 */
static const struct {
    char name[30];
    lua_CFunction func;
} FuzzedDataProvider_functions[] = {
	{"consume_string", luaL_consume_string},
	{"consume_boolean", luaL_consume_boolean},
	{"consume_booleans", luaL_consume_booleans},
	{"consume_number", luaL_consume_number}, // lua_Number
	{"consume_numbers", luaL_consume_numbers}, // lua_Number
	{"consume_numbers_in_range", luaL_consume_numbers_in_range},
	{"consume_integer", luaL_consume_integer}, // lua_Integer
	{"consume_integers", luaL_consume_integers},
	{"consume_integers_in_range", luaL_consume_integers_in_range},
	{"consume_cdata", luaL_consume_cdata},
	{"consume_userdata", luaL_consume_userdata}, // https://www.lua.org/pil/28.1.html
	{"consume_lightuserdata", luaL_consume_lightuserdata}, // https://www.lua.org/pil/28.5.html
	{"consume_remaining_as_string", luaL_consume_remaining_as_string},
	{"consume_probability", luaL_consume_probability},
	{"consume_remaining_bytes", luaL_consume_remaining_bytes},
	{"remaining_bytes", luaL_remaining_bytes},
	{"pick_value_in_table", luaL_pick_value_in_table},
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

TODO: Unicode, 6.5 – UTF-8 Support
https://www.lua.org/manual/5.4/manual.html
*/

static int
l_fuzzed_data_provider(lua_State *L)
{
	/* TODO: FuzzedDataProvider accepts a number of bytes */
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

static const struct luaL_Reg Module[] = {
	{ "Setup", l_setup },
	{ "Fuzz", l_fuzz },
	{ "FuzzedDataProvider", l_fuzzed_data_provider },
	{ "Mutate", l_custom_mutator },
	{ "require_instrument", l_require_instrument },
	{ NULL, NULL }
};

int luaopen_luzer(lua_State *L)
{
    luaL_register(L, "luzer", Module);

    lua_pushliteral(L, "VERSION");
    lua_createtable(L, 0, 3);
    lua_pushstring(L, "LUZER");
    lua_pushstring(L, LUZER_VERSION);
    lua_rawset(L, -3);
    lua_pushstring(L, "LUA");
    lua_pushstring(L, LUA_RELEASE);
    lua_rawset(L, -3);
    lua_pushstring(L, "LLVM");
    lua_pushstring(L, "13.0.1"); /* FIXME */
    lua_rawset(L, -3);
    lua_rawset(L, -3);

    return 1;
}
