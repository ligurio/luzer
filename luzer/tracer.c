/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2023, Sergey Bronnikov
 */

/**
 * SanitizerCoverage
 * https://clang.llvm.org/docs/SanitizerCoverage.html
 *
 * SanCov: Above and Below the Sanitizer Interface
 * https://calabi-yau.space/blog/sanitizer-coverage-interface.html
 *
 * Jazzer:
 * jazzer/src/main/native/com/code_intelligence/jazzer/driver/coverage_tracker.cpp
 * jazzer/src/main/native/com/code_intelligence/jazzer/jazzer_preload.c
 *
 * Atheris:
 * atheris/src/native/core.cc
 * atheris/src/native/counters.cc
 */

#include <lua.h>
#include <stdint.h>
#include <string.h> /* strlen */

#include "counters.h"
#include "macros.h"

/**
 * From afl-python
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */
#define LHASH_INIT       0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x)    h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

NO_SANITIZE void
_trace_branch(uint64_t idx)
{
	increment_counter(idx);
}

NO_SANITIZE static inline unsigned int
lhash(const char *key, size_t offset)
{
	const char *const last = &key[strlen(key) - 1];
	uint32_t h = LHASH_INIT;
	while (key <= last)               LHASH_NEXT(*key++);
	for (; offset != 0; offset >>= 8) LHASH_NEXT(offset);
	return h;
}

/**
 * luzer gathers coverage using a debug hook, and patches coroutine
 * library to set it on created threads when under standard Lua, where each
 * coroutine has its own hook. If a coroutine is created using Lua C API
 * or before the monkey-patching, this wrapper should be applied to the
 * main function of the coroutine. Under LuaJIT this function is redundant,
 * as there is only one, global debug hook.
 *
 * https://github.com/lunarmodules/luacov/blob/master/src/luacov/runner.lua#L102-L117
 * https://github.com/lunarmodules/luacov/blob/78f3d5058c65f9712e6c50a0072ad8160db4d00e/src/luacov/runner.lua#L439-L450
 */
NO_SANITIZE void
debug_hook(lua_State *L, lua_Debug *ar)
{
	lua_getinfo(L, "Sln", ar);
	if (ar && ar->source && ar->currentline) {
		const unsigned int new_location = lhash(ar->source, ar->currentline);
		_trace_branch(new_location);
	}
}

/**
 * this one is used before we allocate counters to get general idea
 * about how much of them do we need for interpreted code
 */
NO_SANITIZE void
collector_debug_hook(lua_State *L, lua_Debug *ar)
{
	lua_getinfo(L, "Sln", ar);
	if (ar && ar->source && ar->currentline) {
		reserve_counter();
	}
}

