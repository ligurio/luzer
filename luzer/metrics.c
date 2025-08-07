#define UNUSED __attribute__((unused))

#include <stdio.h>
#include <string.h>
#include "metrics.h"

#define PERCENTAGE(value, total) (((float)value / total) * 100.0)

static struct metrics metrics;

UNUSED static void
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
	if (lua_pcall(L, 2, 0, 0)) {
		const char *msg = lua_tostring(L, -1);
		fprintf(stderr, "ERR: %s\n", msg);
		lua_error(L);
	}
}

/**
 * When a trace is being recorded.
 *
 * Arguments: tr, func, pc, depth, callee.
 */
UNUSED static int
record_cb(lua_State *L) {
	if (!metrics.is_trace_record) {
		metrics.jit_trace_record++;
		metrics.is_trace_record = true;
	}
	return 0;
}

/**
 * When a function has been compiled to bytecode.
 *
 * Arguments: func.
 */
UNUSED static int
bc_cb(lua_State *L) {
	if (!metrics.is_bc) {
		metrics.bc_num++;
		metrics.is_bc = true;
	}
	return 0;
}

/**
 * When a trace exits through a side exit.
 *
 * Arguments: tr, ex, ngpr, nfpr, ... .
 */
UNUSED static int
texit_cb(lua_State *L) {
	if (!metrics.is_texit) {
		metrics.texit_num++;
		metrics.is_texit = true;
	}
	return 0;
}

/**
 * When trace recording starts, stops or aborts.
 *
 * Arguments: what, tr, func, pc, otr, oex.
 */
UNUSED static int
trace_cb(lua_State *L) {
	const char *what = lua_tostring(L, 1);
	if (strcmp(what, "abort") == 0 && !metrics.is_trace_abort) {
		metrics.jit_trace_abort++;
		metrics.is_trace_abort = true;
	}
	if (strcmp(what, "start") == 0 && !metrics.is_trace_start) {
		metrics.jit_trace_start++;
		metrics.is_trace_start = true;
	}
	if (strcmp(what, "stop") == 0 && !metrics.is_trace_stop) {
		metrics.jit_trace_stop++;
		metrics.is_trace_stop = true;
	}
	return 0;
}

void
metrics_print(void)
{
	if (metrics.total_num == 0)
		return;

	printf("Total number of samples: %zu\n", metrics.total_num);
#if defined(LUA_HAS_JIT) && defined(LUAJIT_FRIENDLY_MODE)
	printf("Total number of samples with recorded traces: %zu (%.1f%%)\n",
		metrics.jit_trace_record,
		PERCENTAGE(metrics.jit_trace_record, metrics.total_num));
	printf("Total number of samples with started traces: %zu (%.1f%%)\n",
		metrics.jit_trace_start,
		PERCENTAGE(metrics.jit_trace_start, metrics.total_num));
	printf("Total number of samples with stopped traces: %zu (%.1f%%)\n",
		metrics.jit_trace_stop,
		PERCENTAGE(metrics.jit_trace_stop, metrics.total_num));
	printf("Total number of samples with aborted traces: %zu (%.1f%%)\n",
		metrics.jit_trace_abort,
		PERCENTAGE(metrics.jit_trace_abort, metrics.total_num));
	printf("Total number of samples with exited traces: %zu (%.1f%%)\n",
		metrics.texit_num,
		PERCENTAGE(metrics.texit_num, metrics.total_num));
	printf("Total number of samples with functions compiled to bytecode: %zu (%.1f%%)\n",
		metrics.bc_num,
		PERCENTAGE(metrics.bc_num, metrics.total_num));
#endif /* LUA_HAS_JIT && LUAJIT_FRIENDLY_MODE */
}

void
metrics_increment_num_samples(void)
{
	metrics.total_num++;
}

UNUSED static inline void
reset_lj_metrics(struct metrics *metrics)
{
	metrics->is_trace_start = false;
	metrics->is_trace_stop = false;
	metrics->is_trace_abort = false;
	metrics->is_trace_record = false;
	metrics->is_bc = false;
	metrics->is_texit = false;
}

UNUSED void
metrics_enable(lua_State *L)
{
	reset_lj_metrics(&metrics);
	jit_attach(L, (void *)bc_cb, "bc");
	jit_attach(L, (void *)record_cb, "record");
	jit_attach(L, (void *)texit_cb, "texit");
	jit_attach(L, (void *)trace_cb, "trace");
}

UNUSED void
metrics_disable(lua_State *L)
{
	jit_attach(L, (void *)bc_cb, NULL);
	jit_attach(L, (void *)record_cb, NULL);
	jit_attach(L, (void *)texit_cb, NULL);
	jit_attach(L, (void *)trace_cb, NULL);
}
