/*
 * TODO:
 * - сделать возможность передавать корпус в таблице-массиве
 * - сделать возможность передавать словарь
 * - переданные аргументы передавать в LLVMFuzzerRunDriver()
 * - трейсинг
 */

#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <signal.h>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "tracer.h"

#define LUZER_VERSION "0.1.0"
#define TEST_ONE_INPUT_FUNC "test_one_input"

void sig_handler(int sig) {
    exit(0);
}

typedef int (*UserCb)(const uint8_t* Data, size_t Size);

lua_State *LL;

#ifdef __cplusplus
extern "C" {
#endif
int LLVMFuzzerRunDriver(int* argc, char*** argv,
                        int (*UserCb)(const uint8_t* Data, size_t Size));
// Sets the callback to be called right before death on error.
// Passing 0 will unset the callback.
// Called in libfuzzer_driver.cpp.
void __sanitizer_set_death_callback(void (*callback)()) {}

// Suppress libFuzzer warnings about missing sanitizer methods in non-sanitizer
// builds.
int __sanitizer_acquire_crash_state() {
	return 1;
}

// Print the stack trace leading to this call. Useful for debugging user code.
// TODO
// https://github.com/keplerproject/lua-compat-5.2/blob/master/c-api/compat-5.2.c#L229
// http://www.lua.org/manual/5.2/manual.html#luaL_traceback
void __sanitizer_print_stack_trace() {
}
#ifdef __cplusplus
} /* extern "C" */
#endif

NO_SANITIZE static int
luaL_test_one_input(lua_State *L, const uint8_t* data, size_t size)
{
	if (!L)
		luaL_error(L, "Lua stack is not initialized.");

	lua_pushstring(L, (const char *)data);
	lua_pushnumber(L, size);
	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	int rc = lua_isfunction(L, -1);
	if (rc != 1)
		luaL_error(L, "not a function");

	lua_insert(L, -3);
	rc = lua_isfunction(L, -3);
	if (rc != 1)
		luaL_error(L, "not a function");

	lua_call(L, 2, 1);

	rc = 0;
	if (lua_isnumber(L, 1) == 1)
		rc = lua_tonumber(L, 1);
	lua_pop(L, 1);

	return rc;
}

NO_SANITIZE
int TestOneInput(const uint8_t* data, size_t size) {
	return luaL_test_one_input(LL, data, size);
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
NO_SANITIZE static int
luaL_setup(lua_State *L)
{
	if (!(lua_gettop(L) <= 3))
		luaL_error(L, "Wrong number of arguments in the Setup() function.");

	/* Set signal handler. */
    struct sigaction act;
    act.sa_handler = sig_handler;
    sigaction(SIGINT, &act, NULL);

	/* Process arguments. */
	if (!lua_istable(L, 1)) {
		luaL_error(L, "not a table");
	}
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        const char *arg = luaL_checkstring(L, -1);
        lua_pop(L, 1);
        printf("Arg: %s\n", arg);
    }
	lua_remove(L, 1);

	/* Process 'test_one_input' function. */
	if (lua_isfunction(L, 1) != 1)
		luaL_error(L, "'test_one_input' is not a function");

	lua_setglobal(L, TEST_ONE_INPUT_FUNC);

	/* Setup Lua. */
    luaL_openlibs(L);
    lua_sethook(L, hook, LUA_MASKLINE, 0);

	LL = L;
	/* LLVMFuzzerInitialize(int *argc, char ***argv); */
	lua_pushboolean(L, 1);

    return 1;
}

char **new_argv(int count, ...)
{
    va_list args;
    int i;
    char **argv = malloc((count+1) * sizeof(char*));
    char *temp;
    va_start(args, count);
    for (i = 0; i < count; i++) {
        temp = va_arg(args, char*);
        argv[i] = malloc(sizeof(temp));
        argv[i] = temp;
    }
    argv[i] = NULL;
    va_end(args);
    return argv;
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
 *
 * If the fuzz target returns -1 on a given input, Fuzz() will not add that
 * input top the corpus, regardless of what coverage it triggers.
 */
NO_SANITIZE static int
luaL_fuzz(lua_State *L)
{
	int argc = 1;
    char **argv = new_argv(4, "is");
    return LLVMFuzzerRunDriver(&argc, &argv, &TestOneInput);
}

NO_SANITIZE static int
luaL_require_instrument(lua_State *L)
{
	const char *module_name = luaL_checkstring(L, -1);
	printf("Instrumented Lua module: %s\n", module_name);
	lua_getglobal(L, "require");
	lua_insert(L, -2);
	lua_call(L, 1, 1);

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
