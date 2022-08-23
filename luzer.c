#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <assert.h>

#include "fuzzed_data_provider.h"

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
	// tracer https://github.com/mpeterv/cluacov/blob/master/src/cluacov/deepactivelines.c
	/*
	int main(int argc, char *argv[]) {
		return LLVMFuzzerRunDriver(&argc, &argv, &LLVMFuzzerTestOneInput);
	}
	*/

    return 0;
}

static int
l_require_instrument(lua_State *L)
{
    /* TODO: wraps "require()" and remember instrumented modules */
    const char *module_name = lua_tostring(L, 1);
    lua_pushstring(L, module_name);
    lua_call(L, 1, LUA_MULTRET);
    /* TODO: check result of lua_call ^^^^ */
    printf("module name is %s\n", module_name);
    return 1;
}

static int
l_custom_mutator(lua_State *L)
{
    /* TODO: process data, max_size, seed */
    return 0;
}

int
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
#if LUA_VERSION_NUM == 501
	luaL_register(L, "luzer", Module);
#else
	luaL_newlib(L, Module);
#endif

/*
	luaL_setfuncs(L, mcch_funcs, 0);
	lua_pushvalue(L, -1);
	lua_setglobal(L, LUA_MCCHLIBNAME);
*/

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
