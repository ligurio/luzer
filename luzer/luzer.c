#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stdlib.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "tracer.h"
#include "version.h"
#include "luzer.h"

#define TEST_ONE_INPUT_FUNC "luzer_test_one_input"
#define CUSTOM_MUTATOR_FUNC "luzer_custom_mutator"
#define CUSTOM_MUTATOR_LIB "libcustom_mutator.so.1"
#define DEBUG_HOOK_FUNC "luzer_custom_hook"

static lua_State *LL;

static void
set_global_lua_stack(lua_State *L)
{
	LL = L;
}

lua_State *
get_global_lua_stack(void)
{
	if (!LL)
		luaL_error(LL, "Lua stack is not initialized.");

	return LL;
}

#if LUA_VERSION_NUM < 502
static int luaL_traceback(lua_State *L) {
	lua_getfield(L, LUA_GLOBALSINDEX, "debug");
	if (!lua_istable(L, -1)) {
		lua_pop(L, 1);
		return 1;
	}
	lua_getfield(L, -1, "traceback");
	if (!lua_isfunction(L, -1)) {
		lua_pop(L, 2);
		return 1;
	}
	lua_pushvalue(L, 1);
	lua_pushinteger(L, 2);
	lua_call(L, 2, 1);
	fprintf(stderr, "%s\n", lua_tostring(L, -1));
	return 1;
}
#endif

#ifdef __cplusplus
extern "C" {
#endif
typedef int (*UserCb)(const uint8_t* Data, size_t Size);
int LLVMFuzzerRunDriver(int* argc, char*** argv,
						int (*UserCb)(const uint8_t* Data, size_t Size));

// Sets the callback to be called right before death on error.
// Passing 0 will unset the callback.
// Called in libfuzzer_driver.cpp.
void __sanitizer_set_death_callback(void (*callback)(void))
{
	/* cleanup(); */
}

// Suppress libFuzzer warnings about missing sanitizer methods in non-sanitizer
// builds.
int __sanitizer_acquire_crash_state(void)
{
	return 1;
}

// Print the stack trace leading to this call. Useful for debugging user code.
// https://github.com/keplerproject/lua-compat-5.2/blob/master/c-api/compat-5.2.c#L229
// http://www.lua.org/manual/5.2/manual.html#luaL_traceback
// https://www.lua.org/manual/5.3/manual.html#luaL_traceback
void __sanitizer_print_stack_trace(void)
{
	lua_State *L = get_global_lua_stack();
#if LUA_VERSION_NUM < 502
	luaL_traceback(L);
#else
	luaL_traceback(L, NULL, "traceback", 3);
#endif
}
#ifdef __cplusplus
} /* extern "C" */
#endif

// See GracefulExit() in trash/atheris/src/native/util.cc
static void sig_handler(int sig)
{
	switch (sig) {
	case SIGINT:
		exit(0);
		break;
	case SIGSEGV:
		__sanitizer_print_stack_trace();
		break;
	}
}

NO_SANITIZE int
luaL_mutate(lua_State *L)
{
	int index = lua_gettop(L);
	if (index != 4) {
		luaL_error(L, "required arguments: data, size, max_size, seed");
	}
	lua_getglobal(L, CUSTOM_MUTATOR_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		luaL_error(L, "no luzer_custom_mutator is defined");
	}
	lua_insert(L, 5);
	lua_call(L, 6, 1);

	if (lua_isstring(L, -1) != 1) {
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
luaL_test_one_input(lua_State *L)
{
	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		lua_settop(L, 0);
		luaL_error(L, "no luzer_test_one_input is defined");
	}
	lua_insert(L, -3);
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
	char *buf = calloc(size + 1, sizeof(char));
	memcpy(buf, data, size);
	buf[size] = '\0';
	lua_pushstring(L, buf);
	lua_pushnumber(L, size);
	int rc = luaL_test_one_input(L);
	free(buf);

	return rc;
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
	if (lua_istable(L, -1) == 0) {
		luaL_error(L, "opts is not a table");
	}
	lua_pushnil(L);

	int argc = 0;
	char **argv = malloc(1 * sizeof(char*));
	if (!argv)
		luaL_error(L, "not enough memory");
	while (lua_next(L, -2) != 0) {
		char **argvp = realloc(argv, sizeof(char*) * (argc + 1));
		if (argvp == NULL) {
			free(argv);
			luaL_error(L, "not enough memory");
		}
		const char *key = lua_tostring(L, -2);
		const char *value = lua_tostring(L, -1);
		char *arg = (char *)value;
		if (strcmp(key, "corpus"))	{
			size_t arg_str_size = strlen(key) + strlen(value) + 3;
			arg = malloc(arg_str_size);
			snprintf(arg, arg_str_size, "-%s=%s", key, value);
		}
		argvp[argc] = arg;
		lua_pop(L, 1);
		argc++;
		argv = argvp;
	}
	if (argc == 0) {
		argv[argc] = "";
		argc++;
	}
	argv[argc] = NULL;
	lua_pop(L, 1);

#ifdef DEBUG
	char **p = argv;
	while(*p++) {
		if (*p)
			printf("DEBUG: libFuzzer arg '%s'\n", *p);
	}
#endif /* DEBUG */

	if (!lua_isnil(L, -1)) {
		if (lua_isfunction(L, -1) == 1) {
			luaL_set_custom_mutator(L);
			char *lua_cpath = getenv("LUA_CPATH");
			if (!lua_cpath)
				lua_cpath = "./";
#define DEBUG 1
#ifdef DEBUG
			/* printf("LUA_CPATH: %s\n", lua_cpath); */
			char *cpath;
			char so_path[PATH_MAX];
			while ((cpath = strsep(&lua_cpath, ";")) != NULL) {
				/* printf("path = %s\n", cpath); */
				char *dir = dirname(cpath);
				/* printf("dirname of path = %s\n", dir); */
				snprintf(so_path, PATH_MAX, "%s/%s", dir, CUSTOM_MUTATOR_LIB);
				if (access(so_path, F_OK) == 0) {
					printf("Found path %s\n", so_path);
					break;
				}
			}
#endif /* DEBUG */
			void* custom_mutator_lib = dlopen(so_path, RTLD_LAZY);
			if (!custom_mutator_lib)
				luaL_error(L, "shared library libcustom_mutator.so.1 is not available");
			void* custom_mutator = dlsym(custom_mutator_lib, "LLVMFuzzerCustomMutator");
			if (!custom_mutator)
				luaL_error(L, "loading library is failed");
			dlclose(custom_mutator_lib);
		}
	} else
		lua_pop(L, 1);

	if (lua_isfunction(L, -1) != 1) {
		printf("test_one_input %s\n", lua_typename(L, lua_type(L, -1)));
		luaL_error(L, "test_one_input is not a Lua function.");
	}
	lua_setglobal(L, TEST_ONE_INPUT_FUNC);

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

	struct sigaction act;
	act.sa_handler = sig_handler;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);

	////////////////////////////////////////////////////////
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
