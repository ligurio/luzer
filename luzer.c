#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stddef.h>

#include "fuzzed_data_provider.h"
#include "macros.h"

#define LUZER_VERSION "0.1.0"

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
luaL_setup(lua_State *L)
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

int LLVMFuzzerTestOneInput(const uint8_t *Data, size_t Size) {
/*
  if (size > 0 && data[0] == 'H')
    if (size > 1 && data[1] == 'I')
       if (size > 2 && data[2] == '!')
       __builtin_trap();
*/
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
/*
	int argc = 0;
	(char *)argv[5];
    argv[0]="prog_name.exe";
    argv[1]="-c";
    argv[2]="4";
    argv[3]="sTriNg";
    argc=4;
	return LLVMFuzzerRunDriver(NULL, NULL, &LLVMFuzzerTestOneInput);
*/
	return 0;
}

static int
luaL_require_instrument(lua_State *L)
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
luaL_custom_mutator(lua_State *L)
{
    /* TODO: process data, max_size and a seed */
    return 0;
}

static const struct luaL_Reg Module[] = {
	{ "Setup", luaL_setup },
	{ "Fuzz", luaL_fuzz },
	{ "FuzzedDataProvider", luaL_fuzzed_data_provider },
	{ "Mutate", luaL_custom_mutator },
	{ "require_instrument", luaL_require_instrument },
	{ NULL, NULL }
};

int luaopen_luzer(lua_State *L)
{
#if LUA_VERSION_NUM == 501
	luaL_register(L, "luzer", Module);
#else
	luaL_newlib(L, Module);
#endif
    lua_pushliteral(L, "VERSION");
    lua_createtable(L, 0, 3);
    lua_pushstring(L, "LUZER");
    lua_pushstring(L, LUZER_VERSION);
    lua_rawset(L, -3);
    lua_pushstring(L, "LUA");
    lua_pushstring(L, LUA_RELEASE);
    lua_rawset(L, -3);
    lua_pushstring(L, "LLVM");
    lua_pushstring(L, "13.0.1"); /* FIXME: set a real LLVM version */
    lua_rawset(L, -3);
    lua_rawset(L, -3);

    return 1;
}
