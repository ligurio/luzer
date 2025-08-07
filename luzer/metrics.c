#include <stdio.h>
#include <string.h>
#include "metrics.h"

static struct metrics metrics = { 0 };

static void
jit_attach(lua_State *L, void *func, const char *event)
{
	lua_getglobal(L, "jit");
	lua_getfield(L, -1, "attach");
	lua_pushcfunction(L, (lua_CFunction)func);
	if (event != NULL) {
		lua_pushstring(L, event);
	} else {
		lua_pushnil(L);
	}
	lua_call(L, 2, 0);
}

/**
 * When a trace is being recorded.
 *
 * Arguments: tr, func, pc, depth, callee.
 */
static int
record_cb(lua_State *L) {
	metrics.jit_trace_record_num++;
	return 0;
}

/**
 * When a function has been compiled to bytecode.
 *
 * Arguments: func.
 */
static int
bc_cb(lua_State *L) {
	metrics.bc_num++;
	return 0;
}

/**
 * When a trace exits through a side exit.
 *
 * Arguments: tr, ex, ngpr, nfpr, ... .
 */
static int
texit_cb(lua_State *L) {
	metrics.texit_num++;
	return 0;
}

/**
 * When trace recording starts, stops or aborts.
 *
 * Arguments: what, tr, func, pc, otr, oex.
 */
static int
trace_cb(lua_State *L) {
	const char *what = lua_tostring(L, 1);
	if (strcmp(what, "abort") == 0) {
		metrics.jit_trace_abort_num++;
	}
	return 0;
}

void
metrics_print(void)
{
	if (!metrics.use_luajit_hooks) {
		printf("LuaJIT metrics disabled.\n");
		return;
	}
#if defined(LUA_HAS_JIT) && defined(LUAJIT_FRIENDLY_MODE)
	printf("Total number of recorded traces: %zu\n",
		metrics.jit_trace_record_num);
	printf("Total number of aborted traces: %zu\n",
		metrics.jit_trace_abort_num);
	printf("Total number of exited traces: %zu\n",
		metrics.texit_num);
	printf("Total number of parsed functions: %zu\n",
		metrics.bc_num);
#endif /* LUA_HAS_JIT && LUAJIT_FRIENDLY_MODE */
}

void
metrics_use_luajit_hooks(void) {
	metrics.use_luajit_hooks = true;
}

void
metrics_enable_luajit_hooks(lua_State *L)
{
	if (!metrics.use_luajit_hooks)
		return;
	jit_attach(L, (void *)bc_cb, "bc");
	jit_attach(L, (void *)record_cb, "record");
	jit_attach(L, (void *)texit_cb, "texit");
	jit_attach(L, (void *)trace_cb, "trace");
}

void
metrics_disable_luajit_hooks(lua_State *L)
{
	if (!metrics.use_luajit_hooks)
		return;
	jit_attach(L, (void *)bc_cb, NULL);
	jit_attach(L, (void *)record_cb, NULL);
	jit_attach(L, (void *)texit_cb, NULL);
	jit_attach(L, (void *)trace_cb, NULL);
}
