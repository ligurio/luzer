#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>

#include "fuzzed_data_provider.h"
#include "macros.h"
#include "tracer.h"

#define LUZER_VERSION "0.1.0"

typedef int (*UserCb)(const uint8_t* Data, size_t Size);

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
int __sanitizer_acquire_crash_state() { return 1; }

// Print the stack trace leading to this call. Useful for debugging user code.
// Jagger: Dump a Lua stack trace on timeouts.
void __sanitizer_print_stack_trace() {
	// TODO
	printf("Hello, everyone!\n");
}
#ifdef __cplusplus
} /* extern "C" */
#endif

NO_SANITIZE
int TestOneInput(const uint8_t* data, size_t size) {
	/* TODO: see trash/atheris/src/native/core.cc */
	/* TODO: execute Lua function TestOneInput() with proposed data and size */
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
luaL_setup(lua_State *L)
{
	/* argv */
	/*
	if (!lua_istable(L, 1)) {
		assert(0);
	}
	if (lua_isfunction(L, 2) != 1) {
		assert(0);
	}
	*/
    luaL_openlibs(L);
    lua_sethook(L, hook, LUA_MASKLINE, 0);
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
 */
static int
luaL_fuzz(lua_State *L)
{
	int argc = 1;
    char **argv = new_argv(4, "is");

    return LLVMFuzzerRunDriver(&argc, &argv, &TestOneInput);
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
