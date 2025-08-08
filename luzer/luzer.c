/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2025, Sergey Bronnikov
 */

#define _GNU_SOURCE
#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"
#ifdef LUA_HAS_JIT
#include "luajit.h"
#endif /* LUA_HAS_JIT */
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <signal.h>
#include <string.h>
#include <dlfcn.h>
#include <libgen.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef __linux__
#include <linux/limits.h>
#else
#include <limits.h>
#endif

#include "fuzzed_data_provider.h"
#include "counters.h"
#include "compat.h"
#include "macros.h"
#include "tracer.h"
#include "config.h"
#include "luzer.h"

#define TEST_ONE_INPUT_FUNC "luzer_test_one_input"
#define CUSTOM_MUTATOR_FUNC "luzer_custom_mutator"
#define CUSTOM_MUTATOR_LIB "libcustom_mutator.so"
#define DEBUG_HOOK_FUNC "luzer_custom_hook"

static lua_State *LL;
static int jit_status = 0;

int internal_hook_disabled = 0;

#define LUA_SETHOOK(lua_state, hook, mask, count) \
	do { \
		if (!internal_hook_disabled) \
			lua_sethook((lua_state), (hook), (mask), (count)); \
	} while(0)

NO_SANITIZE static void
set_global_lua_state(lua_State *L)
{
	LL = L;
}

NO_SANITIZE lua_State *
get_global_lua_state(void)
{
	if (!LL) {
		fprintf(stderr, "Lua state is not initialized.\n");
		abort();
	}

	return LL;
}

#ifdef __cplusplus
extern "C" {
#endif
typedef int (*UserCb)(const uint8_t* Data, size_t Size);
int LLVMFuzzerRunDriver(int* argc, char*** argv,
                        int (*UserCb)(const uint8_t* Data, size_t Size));
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);

// [pcs_beg, pcs_end) is an array of ptr-sized integers representing
// pairs [PC, PCFlags] for every instrumented block in the current DSO.
// Capture this array in order to read the PCs and their Flags.
// The number of PCs and PCFlags for a given DSO is the same as the number
// of 8-bit counters (-fsanitize-coverage=inline-8bit-counters), or
// boolean flags (-fsanitize-coverage=inline=bool-flags), or trace_pc_guard
// callbacks (-fsanitize-coverage=trace-pc-guard).
// A PCFlags describes the basic block:
//  * bit0: 1 if the block is the function entry block, 0 otherwise.
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);

/**
 * Sets the callback to be called right before death on error.
 * Passing 0 will unset the callback. Called in libfuzzer_driver.cpp.
 */
NO_SANITIZE void
__sanitizer_set_death_callback(void (*callback)(void))
{
	/* cleanup(); */
}

/**
 * Suppress libFuzzer warnings about missing sanitizer methods in non-sanitizer
 * builds.
 */
NO_SANITIZE int
__sanitizer_acquire_crash_state(void)
{
	return 1;
}

/**
 * Print a Lua stack trace leading to this call.
 * Useful for debugging user code.
 * See http://www.lua.org/manual/5.2/manual.html#luaL_traceback
 */
NO_SANITIZE void
__sanitizer_print_stack_trace(void)
{
	lua_State *L = get_global_lua_state();
	lua_State *L1 = luaL_newstate();
	luaL_traceback(L, L1, "traceback", 3);
	lua_close(L1);
}
#ifdef __cplusplus
} /* extern "C" */
#endif

NO_SANITIZE const char *
get_libFuzzer_symbols_location(void) {
	Dl_info dl_info;
	if (!dladdr((void*)&LLVMFuzzerRunDriver, &dl_info)) {
		return "<Not a shared object>";
	}
	return (dl_info.dli_fname);
}

NO_SANITIZE const char *
get_coverage_symbols_location(void) {
	Dl_info dl_info;
	if (!dladdr((void*)&__sanitizer_cov_8bit_counters_init, &dl_info)) {
		return "<Not a shared object>";
	}
	return (dl_info.dli_fname);
}

const char *dso_path_lf_asan;
const char *dso_path_lf_ubsan;
const char *dso_path_libcustom_mutator;
/* struct paths luzer_paths; */

NO_SANITIZE static int
search_module_path(char *so_path, const char *so_name, size_t len) {
	/* Create a copy, because `strsep()` below mutates a string. */
	char *lua_cpath = strdup(getenv("LUA_CPATH"));
	if (!lua_cpath)
		lua_cpath = "./";
	char *stringp = lua_cpath;
	int rc = -1;
	char *cpath = NULL;
	while ((cpath = strsep(&stringp, ";")) != NULL) {
		const char *dir = dirname(cpath);
		snprintf(so_path, len, "%s/%s", dir, so_name);
		if (access(so_path, F_OK) == 0) {
			rc = 0;
			strcpy(so_path, cpath);
			free(lua_cpath);
			break;
		}
	}
	return rc;
}

NO_SANITIZE void
init(void)
{
	if (!&LLVMFuzzerRunDriver) {
		printf("LLVMFuzzerRunDriver symbol not found. This means "
        "you had an old version of Clang installed when you built luzer.\n");
        /* TODO: exit */
        assert(NULL);
	}

	if (strcmp(get_coverage_symbols_location(), get_libFuzzer_symbols_location()) != 0) {
        fprintf(stderr,
        "WARNING: Coverage symbols are being provided by a library other than "
        "libFuzzer. This will result in a broken Lua code coverage and "
        "severely impacted native extension code coverage. Symbols are coming "
        "from this library: %s\n", get_coverage_symbols_location());
	}

	char path[PATH_MAX];
	int rc = search_module_path(path, CUSTOM_MUTATOR_LIB, PATH_MAX);
	if (rc) {
		fprintf(stderr, "%s is not found\n", CUSTOM_MUTATOR_LIB);
		return;
	}
	char *base_so_path = realpath((const char *)&path, NULL);
	if (!base_so_path)
		perror("realpath");
	memset(&path, 0, PATH_MAX);

	snprintf(path, PATH_MAX, "%s/%s", base_so_path, CUSTOM_MUTATOR_LIB);
	dso_path_libcustom_mutator = strdup(path);
	if (access(dso_path_libcustom_mutator, F_OK))
		perror("access");

	snprintf(path, PATH_MAX, "%s/%s", base_so_path, dso_asan_string());
	dso_path_lf_asan = strdup(path);
	if (access(dso_path_lf_asan, F_OK))
		perror("access");

	snprintf(path, PATH_MAX, "%s/%s", base_so_path, dso_ubsan_string());
	dso_path_lf_ubsan = strdup(path);
	if (access(dso_path_lf_ubsan, F_OK))
		perror("access");

	free(base_so_path);
}

NO_SANITIZE static void
sig_handler(int sig)
{
	switch (sig) {
	case SIGINT:
		exit(0);
	case SIGSEGV:
		__sanitizer_print_stack_trace();
		_exit(139);
	}
}

/* Returns the current status of the JIT compiler. */
NO_SANITIZE static int
luajit_has_enabled_jit(lua_State *L)
{
#if defined(LUA_HAS_JIT)
	lua_getglobal(L, "jit");
	lua_getfield(L, -1, "status");
	/*
	 * `jit.status()` returns the current status of the JIT
	 * compiler. The first result is either true or false if the
	 * JIT compiler is turned on or off. The remaining results are
	 * strings for CPU-specific features and enabled optimizations.
	 * The remaining results are not interested, we discard them.
	 */
	lua_pcall(L, 0, 1, 0);
	return lua_toboolean(L, -1);
#else
	return 0;
#endif
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
	lua_insert(L, -2);
	lua_call(L, 1, 1);

	int rc = 0;
	if (lua_isnumber(L, 1) == 1)
		rc = lua_tonumber(L, 1);
	lua_settop(L, 0);

	return rc;
}

NO_SANITIZE int
TestOneInput(const uint8_t* data, size_t size) {
	const counter_and_pc_table_range alloc = allocate_counters_and_pcs();
	if (alloc.counters_start && alloc.counters_end) {
		__sanitizer_cov_8bit_counters_init(alloc.counters_start,
										   alloc.counters_end);
	}
	if (alloc.pctable_start && alloc.pctable_end) {
		__sanitizer_cov_pcs_init(alloc.pctable_start, alloc.pctable_end);
	}

	lua_State *L = get_global_lua_state();

	char *buf = malloc(size + 1 * sizeof(*buf));
	if (!buf) {
		perror("malloc");
		exit(EXIT_FAILURE);
	}
	memcpy(buf, data, size);
	buf[size] = '\0';

#if defined(LUA_HAS_JIT) && defined(LUAJIT_FRIENDLY_MODE)
	if (jit_status) {
		if (!luaJIT_setmode(L, 0, LUAJIT_MODE_ON))
			luaL_error(L, "cannot turn a JIT compiler on");
		lua_pushlstring(L, buf, size);
		/* Returned value is not handled. */
		luaL_test_one_input(L);
		if (!luaJIT_setmode(L, 0, LUAJIT_MODE_OFF))
			luaL_error(L, "cannot turn a JIT compiler off");
	}
#endif /* LUA_HAS_JIT && LUAJIT_FRIENDLY_MODE */

	/**
	 * Enable debug hook.
	 *
	 * Hook is called when the Lua interpreter calls a function
	 * and when the interpreter is about to start the execution
	 * of a new line of code, or when it jumps back in the code
	 * (even to the same line).
	 * https://www.lua.org/pil/23.2.html
	 */
	LUA_SETHOOK(L, debug_hook, LUA_MASKCALL | LUA_MASKLINE, 0);

	lua_pushlstring(L, buf, size);
	int rc = luaL_test_one_input(L);
	free(buf);

	/* Disable debug hook. */
	LUA_SETHOOK(L, debug_hook, 0, 0);

	return rc;
}

NO_SANITIZE static int
luaL_cleanup(lua_State *L)
{
	lua_pushnil(L);
	lua_setglobal(L, TEST_ONE_INPUT_FUNC);
	lua_pushnil(L);
	lua_setglobal(L, DEBUG_HOOK_FUNC);
	lua_pushnil(L);
	lua_setglobal(L, CUSTOM_MUTATOR_FUNC);
	return 0;
}

NO_SANITIZE static int
luaL_path(lua_State *L) {
	lua_createtable(L, 0, 3);

	lua_pushstring(L, "asan");
	lua_pushstring(L, dso_path_lf_asan);
	lua_settable(L, -3);

	lua_pushstring(L, "ubsan");
	lua_pushstring(L, dso_path_lf_ubsan);
	lua_settable(L, -3);

	return 1;
}

/**
 * We couldn't define custom mutator function in a compile-time,
 * so we define it in runtime - when user has specified a Lua
 * function with custom mutator. LibFuzzer uses custom mutator
 * defined by user when a function LLVMFuzzerCustomMutator has been defined.
 * We define that function in a shared library and preload it when
 * user defines a Lua function with custom mutator.
 * LLVMFuzzerCustomMutator executes a Lua function, mutates portion of data
 * and returns it back to LibFuzzer. Shared library is located
 * at the same directory where the main shared library with luzer's
 * implementation is placed. To search it's location we search
 * shared library CUSTOM_MUTATOR_LIB in directories listed in
 * environment variable LUA_CPATH.
 */
NO_SANITIZE static int
load_custom_mutator_lib(const char *so_path) {
	int rc;
	void *custom_mutator_lib = dlopen(so_path, RTLD_LAZY);
	if (!custom_mutator_lib) {
		DEBUG_PRINT("dlopen");
		return -1;
	}
	const void *custom_mutator = dlsym(custom_mutator_lib, "LLVMFuzzerCustomMutator");
	if (!custom_mutator) {
		DEBUG_PRINT("dlsym");
		return -1;
	}
	rc = dlclose(custom_mutator_lib);
	if (rc) {
		DEBUG_PRINT("dlclose");
		return -1;
	}
	return 0;
}

/* Find amount of fields in the table on the top of the stack. */
NO_SANITIZE int
table_nkeys(lua_State *L, int idx)
{
	int len = 0;
	/* Push starting `nil` for iterations. */
	lua_pushnil(L);
	while (lua_next(L, idx) != 0) {
		/*
		 * Remove `value` from the stack. Keeps `key` for
		 * the next iteration.
		 */
		lua_pop(L, 1);
		len++;
	}
	return len;
}

NO_SANITIZE static void
free_argv(int argc, char **argv)
{
	/* Free allocated argv strings and the buffer. */
	for (int i = 0; i < argc; i++)
		free(argv[i]);
	free(argv);
}

NO_SANITIZE static int
luaL_fuzz(lua_State *L)
{
	const char *str = luaL_checkstring(L, -1);
	lua_pop(L, 1);
	char *argv_0 = strdup(str);
	if (lua_istable(L, -1) == 0) {
		luaL_error(L, "opts is not a table");
	}
	/* 0 element -- test name. Last -- ending NULL. */
	int argc = table_nkeys(L, -2) + 1;
	char **argv = malloc((argc + 1) * sizeof(*argv));
	if (!argv)
		luaL_error(L, "not enough memory");

	argv[0] = argv_0;
	const char *corpus_path = NULL;

	/* First key to start iteration. */
	lua_pushnil(L);
	int n_arg = 1;
	while (lua_next(L, -2) != 0) {
		const char *key = lua_tostring(L, -2);
		const char *value = lua_tostring(L, -1);
		if (strcmp(key, "corpus") == 0) {
			corpus_path = strdup(value);
			lua_pop(L, 1);
			continue;
		}
		/*
		 * Lua debug hook is used for code instrumentation, but it
		 * is also used by luacov. Only one hook can be enabled at
		 * the same time, so we disable our own hook for
		 * instrumentation to allow luacov work.
		 */
		if ((strcmp(key, "runs") == 0) &&
		    (atoi(value) == 1)) {
				internal_hook_disabled = 1;
				fprintf(stderr, "INFO: Lua debug hook is disabled.\n");
		}
		size_t arg_len = strlen(key) + strlen(value) + 3;
		char *arg = malloc(arg_len * sizeof(*arg));
		if (!arg)
			luaL_error(L, "not enough memory");
		snprintf(arg, arg_len, "-%s=%s", key, value);
		argv[n_arg++] = arg;
		lua_pop(L, 1);
	}

	if (corpus_path) {
		argv[argc-1] = (char*)corpus_path;
	}
	argv[argc] = NULL;
	lua_pop(L, 1);

#ifdef DEBUG
	char **p = argv;
	while(*p++) {
		if (*p)
			DEBUG_PRINT("libFuzzer arg - '%s'\n", *p);
	}
#endif /* DEBUG */

	/* Processing a function with custom mutator. */
	if (!lua_isnil(L, -1) && (lua_isfunction(L, -1) == 1)) {
			if (load_custom_mutator_lib(dso_path_libcustom_mutator)) {
				free_argv(argc, argv);
				luaL_error(L, "function LLVMFuzzerCustomMutator is not available");
			}
			luaL_set_custom_mutator(L);
	} else {
		lua_pop(L, 1);
	}

	/* Processing a function LLVMFuzzerTestOneInput. */
	if (lua_isfunction(L, -1) != 1) {
		free_argv(argc, argv);
		luaL_error(L, "test_one_input is not a Lua function");
	}
	lua_setglobal(L, TEST_ONE_INPUT_FUNC);

	lua_pushboolean(L, 1);

	struct sigaction act;
	act.sa_handler = sig_handler;
	sigaction(SIGINT, &act, NULL);
	sigaction(SIGSEGV, &act, NULL);

	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	if (lua_isfunction(L, -1) != 1) {
		free_argv(argc, argv);
		luaL_error(L, "test_one_input is not defined");
	}
	lua_pop(L, -1);

	jit_status = luajit_has_enabled_jit(L);
	set_global_lua_state(L);
	int rc = LLVMFuzzerRunDriver(&argc, &argv, &TestOneInput);

	free_argv(argc, argv);
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

NO_SANITIZE int
luaopen_luzer_impl(lua_State *L)
{
	init();

#if LUA_VERSION_NUM == 501
	luaL_register(L, "luzer_impl", Module);
#else
	luaL_newlib(L, Module);
#endif
	lua_pushliteral(L, "_LUZER_VERSION");
	lua_pushstring(L, luzer_version_string());
	lua_rawset(L, -3);

	lua_pushliteral(L, "_LLVM_VERSION");
	lua_pushstring(L, llvm_version_string());
	lua_rawset(L, -3);

	lua_pushliteral(L, "_LUA_VERSION");
	lua_pushstring(L, LUA_RELEASE);
	lua_rawset(L, -3);

	lua_pushliteral(L, "path");
	luaL_path(L);
	lua_rawset(L, -3);

	fdp_metatable_init(L);

	return 1;
}
