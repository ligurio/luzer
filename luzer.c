/*
 * TODO:
 * - переданные аргументы передавать в LLVMFuzzerRunDriver()
 * - трейсинг
 * - ??? доделать require_instrument()
 * - исправить передачу аргументов в FuzzedDataProvider
 *
 * - сделать возможность передавать корпус в таблице-массиве
 * - сделать возможность передавать словарь
 */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "tracer.h"
#include "version.h"

#define LUZER_VERSION "0.1.0"
#define TEST_ONE_INPUT_FUNC "luzer_test_one_input"
#define CUSTOM_MUTATOR_FUNC "luzer_custom_mutator"

static lua_State *LL;

static int argc;
static char **argv;

// See GracefulExit() in trash/atheris/src/native/util.cc
static void sig_handler(int sig)
{
	exit(0);
}

#ifdef __cplusplus
extern "C" {
#endif
typedef int (*UserCb)(const uint8_t* Data, size_t Size);
int LLVMFuzzerRunDriver(int* argc, char*** argv,
                        int (*UserCb)(const uint8_t* Data, size_t Size));

// Sets the callback to be called right before death on error.
// Passing 0 will unset the callback.
// Called in libfuzzer_driver.cpp.
void __sanitizer_set_death_callback(void (*callback)())
{
}

// Suppress libFuzzer warnings about missing sanitizer methods in non-sanitizer
// builds.
int __sanitizer_acquire_crash_state()
{
	return 1;
}

// Print the stack trace leading to this call. Useful for debugging user code.
// TODO
// https://github.com/keplerproject/lua-compat-5.2/blob/master/c-api/compat-5.2.c#L229
// http://www.lua.org/manual/5.2/manual.html#luaL_traceback
void __sanitizer_print_stack_trace()
{
}
#ifdef __cplusplus
} /* extern "C" */
#endif

NO_SANITIZE static size_t
custom_mutator(uint8_t *Data, size_t Size, size_t MaxSize, unsigned int Seed)
{
	if (!LL)
		luaL_error(LL, "Lua stack is not initialized.");

	lua_getglobal(LL, CUSTOM_MUTATOR_FUNC);
	if (lua_isfunction(LL, -1) != 1) {
		lua_settop(LL, 0);
		luaL_error(LL, "no luzer_custom_mutator is defined");
	}
	lua_pushstring(LL, (const char *)Data);
	lua_pushnumber(LL, Size);
	lua_pushnumber(LL, MaxSize);
	lua_pushnumber(LL, Seed);
	lua_call(LL, 4, 1);

	// TODO: "The mutated data cannot be larger than max_size."
	int rc = 0;
	if (lua_isnumber(LL, -1) == 1)
		rc = lua_tonumber(LL, -1);
	lua_pop(LL, -1);

	return rc;
}

NO_SANITIZE static int
luaL_test_one_input(lua_State *L, const uint8_t* data, size_t size)
{
	if (!L)
		luaL_error(L, "Lua stack is not initialized.");

	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		luaL_error(L, "no luzer_test_one_input is defined");
		lua_settop(L, 0);
	}
	lua_pushstring(L, (const char *)data);
	lua_pushnumber(L, size);
	lua_call(L, 2, 1);

	int rc = 0;
	if (lua_isnumber(L, 1) == 1)
		rc = lua_tonumber(L, 1);
	lua_settop(L, 0);

	return rc;
}

NO_SANITIZE int
TestOneInput(const uint8_t* data, size_t size) {
	return luaL_test_one_input(LL, data, size);
}

NO_SANITIZE static int
luaL_setup(lua_State *L)
{
	// Argument: libfuzzer arguments.
	if (!lua_istable(L, 1))
		luaL_error(L, "arg is not a table");

	argc = lua_objlen(L, 1);
    argv = malloc((argc + 1) * sizeof(char*));
    lua_pushnil(L);
    int i = 0;
	// FIXME: first argument is ignored.
    while (lua_next(L, 1) != 0) {
        const char *arg = luaL_checkstring(L, -1);
        lua_pop(L, 1);
        argv[i] = malloc(sizeof(arg));
        argv[i] = (char*)arg;
        i++;
    }
    argv[i] = NULL;
	lua_remove(L, 1);

	// Argument: test_one_input.
	if (lua_isfunction(L, 1) != 1)
		luaL_error(L, "test_one_input is not a Lua function.");

	lua_setglobal(L, TEST_ONE_INPUT_FUNC);

	// Argument: custom_mutator.
	if (lua_gettop(L) != 0) {
		if (lua_isfunction(L, -1) != 1)
			luaL_error(L, "custom_mutator is not a Lua function.");
		lua_setglobal(L, CUSTOM_MUTATOR_FUNC);
	}

	// TODO: trash/atheris/src/native/core.cc
	// TODO: __sanitizer_cov_8bit_counters_init(1, 10000);
	// TODO: __sanitizer_cov_pcs_init

	// Setup Lua.
    luaL_openlibs(L);

	// Hook is called when the interpreter calls a function and when the
	// interpreter is about to start the execution of a new line of code, or
	// when it jumps back in the code (even to the same line).
    lua_sethook(L, hook, LUA_MASKCALL | LUA_MASKLINE, 0);
	lua_pushboolean(L, 1);

	// Set signal handler.
    struct sigaction act;
    act.sa_handler = sig_handler;
    sigaction(SIGINT, &act, NULL);

    return 1;
}

NO_SANITIZE static int
luaL_fuzz(lua_State *L)
{
	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		luaL_error(L, "test_one_input is not defined");
	}
	lua_pop(L, -1);

	LL = L;

    return LLVMFuzzerRunDriver(&argc, &argv, &TestOneInput);
}

NO_SANITIZE static int
luaL_require_instrument(lua_State *L)
{
	if (lua_gettop(L) != 1)
		luaL_error(L, "require_instrument requires module name");

	if (lua_isstring(L, -1) != 1)
		luaL_error(L, "require_instrument: bad argument (string expected)");

	const char *module_name = luaL_checkstring(L, -1);
	lua_getglobal(L, "require");
	lua_insert(L, -2);
	lua_call(L, 1, 1);
	printf("instrumented: %s\n", module_name);

	return 1;
}

NO_SANITIZE static int
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
    lua_pushliteral(L, "_VERSION");
    lua_createtable(L, 0, 3);
    lua_pushstring(L, "LUZER");
    lua_pushstring(L, LUZER_VERSION);
    lua_rawset(L, -3);
    lua_pushstring(L, "LUA");
    lua_pushstring(L, LUA_RELEASE);
    lua_rawset(L, -3);
    lua_pushstring(L, "LLVM");
    lua_pushstring(L, llvm_version_string());
    lua_rawset(L, -3);
    lua_rawset(L, -3);

    return 1;
}
