/*
 * TODO:
 *
 * - сделать возможность передавать корпус в таблице-массиве
 * - сделать возможность передавать словарь
 * - поставлять словари для стандартной библиотеки lua 5.1, lua 5.2, lua 5.3,
 *   lua 5.4, tarantool
 * - добавить regfuzz https://github.com/ShikChen/regfuzz
 * - пример для фаззинга С библиотеки с помощью FFI
 *		 Basic library, which includes the coroutine sub-library
 *		 Modules library
 *		 String manipulation
 *		 Table manipulation
 *		 Math library
 *		 File Input and output
 *		 Operating system facilities
 *		 Debug facilities
 *
 *   _VERSION
 *   package.loaded
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
#define TEST_ONE_INPUT "test_one_input"

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
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);

// Called before a comparison instruction if exactly one of the arguments is constant.
// Arg1 and Arg2 are arguments of the comparison, Arg1 is a compile-time constant.
// These callbacks are emitted by -fsanitize-coverage=trace-cmp since 2017-08-11.
void __sanitizer_cov_trace_const_cmp1(uint8_t Arg1, uint8_t Arg2);
void __sanitizer_cov_trace_const_cmp2(uint16_t Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_const_cmp4(uint32_t Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_const_cmp8(uint64_t Arg1, uint64_t Arg2);

// Called before a comparison instruction.
// Arg1 and Arg2 are arguments of the comparison.
void __sanitizer_cov_trace_cmp1(uint8_t Arg1, uint8_t Arg2);
void __sanitizer_cov_trace_cmp2(uint16_t Arg1, uint16_t Arg2);
void __sanitizer_cov_trace_cmp4(uint32_t Arg1, uint32_t Arg2);
void __sanitizer_cov_trace_cmp8(uint64_t Arg1, uint64_t Arg2);

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
// Jagger: Dump a Lua stack trace on timeouts.
void __sanitizer_print_stack_trace() {
	// TODO
	// 5.2+ luaL_traceback(L, L, lua_tostring(L, 1), 1);
	// http://www.lua.org/manual/5.3/manual.html#luaL_traceback
	// https://github.com/keplerproject/lua-compat-5.2/blob/master/c-api/compat-5.2.c#L229
	// debug.traceback()
	printf("[DEBUG] Hello, everyone!\n");
}
#ifdef __cplusplus
} /* extern "C" */
#endif

NO_SANITIZE static int
luaL_test_one_input(lua_State *L, const uint8_t* data, size_t size)
{
	if (!L)
		luaL_error(L, "not a Lua stack");

    //printf("[DEBUG] Running TestOneInput()\n");
    //printf("[DEBUG] data %s, size %zu\n", data, size);
	lua_pushstring(L, (const char *)data);
	lua_pushnumber(L, size);
	lua_getglobal(L, TEST_ONE_INPUT);
	int rc = lua_isfunction(L, -1);
	if (rc != 1)
		luaL_error(L, "not a function");
	//printf("[DEBUG] lua_gettop() %d\n", lua_gettop(L));
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
	/* TODO: see trash/atheris/src/native/core.cc */

	/* see trash/atheris/src/native/core.cc */
	/* TODO
	 *
  struct CounterAndPcTableRange alloc = AllocateCountersAndPcs();
  if (alloc.counters_start && alloc.counters_end) {
    __sanitizer_cov_8bit_counters_init(alloc.counters_start,
                                       alloc.counters_end);
  }
  if (alloc.pctable_start && alloc.pctable_end) {
    __sanitizer_cov_pcs_init(alloc.pctable_start, alloc.pctable_end);
  }
  */
  /* TODO: set exception handlers */

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
    struct sigaction act;
    act.sa_handler = sig_handler;
    sigaction(SIGINT, &act, NULL);

	printf("[DEBUG] Running Setup()\n");

	/* Process arguments. */
	if (!lua_istable(L, 1)) {
		luaL_error(L, "not a table");
	}
    lua_pushnil(L);
    while (lua_next(L, 1) != 0) {
        const char *arg = luaL_checkstring(L, -1);
        lua_pop(L, 1);
        printf("[DEBUG] arg: %s\n", arg);
    }
	lua_remove(L, 1);

	/* Process 'test_one_input' function. */
	if (lua_isfunction(L, 1) != 1)
		luaL_error(L, "'test_one_input' is not a function");

	lua_setglobal(L, TEST_ONE_INPUT);

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
	printf("[DEBUG] Running Fuzz()\n");
	int argc = 1;
    char **argv = new_argv(4, "is");
    return LLVMFuzzerRunDriver(&argc, &argv, &TestOneInput);
}

NO_SANITIZE static int
luaL_require_instrument(lua_State *L)
{
	const char *module_name = luaL_checkstring(L, -1);
	printf("[DEBUG] require_instrument(): %s\n", module_name);
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
