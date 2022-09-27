#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>

#include <dlfcn.h>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "tracer.h"
#include "version.h"
#include "luzer.h"

#define TEST_ONE_INPUT_FUNC "luzer_test_one_input"
#define CUSTOM_MUTATOR_FUNC "luzer_custom_mutator"
#define CUSTOM_MUTATOR_LIB "./libcustom_mutator.so.1"
#define DEBUG_HOOK_FUNC "luzer_custom_hook"

static lua_State *LL;

void
set_global_lua_stack(lua_State *L)
{
	LL = L;
}

lua_State *
get_global_lua_stack()
{
	if (!LL)
		luaL_error(LL, "Lua stack is not initialized.");

	return LL;
}

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

NO_SANITIZE static int
luaL_mutate(lua_State *L)
{
	int index = lua_gettop(L);
	if (index != 4) {
		lua_pop(L, index);
		luaL_error(L, "required arguments: data, size, max_size, seed");
	}

	lua_getglobal(L, CUSTOM_MUTATOR_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		lua_pop(L, 1);
		luaL_error(L, "no luzer_custom_mutator is defined");
	}
	lua_call(L, 4, 1);

	/*
	if (sizeof(data) > max_size)
		luaL_error(L, "The mutated data cannot be larger than max_size.");
	*/

	if (lua_isstring(L, -1) != 1) {
		lua_pop(L, -1);
		luaL_error(L, "_mutate() must return a string");
	}

	return 1;
}

NO_SANITIZE static int
luaL_set_custom_mutator(lua_State *L)
{
	if (lua_isfunction(L, -1) != 1)
		luaL_error(L, "custom_mutator is not a Lua function.");

	lua_setglobal(L, CUSTOM_MUTATOR_FUNC);

	return 0;
}

NO_SANITIZE static int
luaL_test_one_input(lua_State *L, const uint8_t* data, size_t size)
{
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
	lua_State *L = get_global_lua_stack();
	return luaL_test_one_input(L, data, size);
}

NO_SANITIZE static int
luaL_setup(lua_State *L)
{
	// Argument: libfuzzer arguments.
	if (!lua_istable(L, 1))
		luaL_error(L, "arg is not a table");

#if LUA_VERSION_NUM == 501
	argc = lua_objlen(L, 1);
#else
	argc = lua_rawlen(L, 1);
#endif
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
	if (lua_isfunction(L, 1) == 1) {
		luaL_set_custom_mutator(L);
		void* custom_mutator_lib = dlopen(CUSTOM_MUTATOR_LIB, RTLD_LAZY);
		if (!custom_mutator_lib)
			unreachable();
			//luaL_error(L, "Shared library ./libcustom_mutator.so.1 is not available.");
		void* sym = dlsym(custom_mutator_lib, "LLVMFuzzerCustomMutator");
		if (!sym)
			unreachable();
			//luaL_error(L, "Symbol LLVMFuzzerCustomMutator is not available.");
		dlclose(custom_mutator_lib);
	}

	// TODO: trash/atheris/src/native/core.cc
	// TODO: __sanitizer_cov_8bit_counters_init(1, 10000);
	// TODO: __sanitizer_cov_pcs_init

	// Setup Lua.
	luaL_openlibs(L);

	// TODO: detect installed hook function with lua_gethook()

	// Hook is called when the interpreter calls a function and when the
	// interpreter is about to start the execution of a new line of code, or
	// when it jumps back in the code (even to the same line).
	// https://www.lua.org/pil/23.2.html
	lua_sethook(L, debug_hook, LUA_MASKCALL | LUA_MASKLINE, 0);
	lua_pushboolean(L, 1);

	// Set signal handler.
	struct sigaction act;
	act.sa_handler = sig_handler;
	sigaction(SIGINT, &act, NULL);

	return 1;
}

NO_SANITIZE static int
luaL_cleanup(lua_State *L)
{
	lua_sethook(L, debug_hook, 0, 0);
	lua_pushnil(L);
	lua_setglobal(L, TEST_ONE_INPUT_FUNC);
	lua_pushnil(L);
	lua_setglobal(L, DEBUG_HOOK_FUNC);
	lua_pushnil(L);
	lua_setglobal(L, CUSTOM_MUTATOR_FUNC);

	return 0;
}

NO_SANITIZE static int
luaL_fuzz(lua_State *L)
{
	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		luaL_error(L, "test_one_input is not defined");
	}
	lua_pop(L, -1);

	set_global_lua_stack(L);
	int rc = LLVMFuzzerRunDriver(&argc, &argv, &TestOneInput);
	luaL_cleanup(L);

	lua_pushnumber(L, rc);

	return 1;
}

static const struct luaL_Reg Module[] = {
	{ "Setup", luaL_setup },
	{ "Fuzz", luaL_fuzz },
	{ "FuzzedDataProvider", luaL_fuzzed_data_provider },
	{ "_set_custom_mutator", luaL_set_custom_mutator },
	{ "_mutate", luaL_mutate },
	{ NULL, NULL }
};

int luaopen_luzer(lua_State *L)
{
#if LUA_VERSION_NUM == 501
	luaL_register(L, "luzer", Module);
#else
	luaL_newlib(L, Module);
#endif
	lua_pushliteral(L, "_COPYRIGHT");
	lua_pushliteral(L, "Copyright (C) 2020-2022 Sergey Bronnikov");
	lua_settable(L, -3);
	lua_pushliteral(L, "_DESCRIPTION");
	lua_pushliteral(L, "A coverage-guided, native Lua fuzzer");
	lua_settable(L, -3);
	lua_pushliteral(L, "_VERSION");

	char version[50];
	snprintf(version, sizeof(version), "luzer %s, LLVM %s, %s",
			 luzer_version_string(),
			 llvm_version_string(),
			 LUA_RELEASE);
	lua_pushstring(L, version);
	lua_rawset(L, -3);

	return 1;
}
