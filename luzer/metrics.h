#ifndef LUZER_METRICS_H_
#define LUZER_METRICS_H_

#include <stdbool.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

struct metrics {
	bool use_luajit_hooks;
	size_t jit_trace_record_num;
	size_t jit_trace_abort_num;
	size_t bc_num;
	size_t texit_num;
};

void
metrics_use_luajit_hooks(void);

void
metrics_enable_luajit_hooks(lua_State *L);

void
metrics_disable_luajit_hooks(lua_State *L);

void
metrics_print(void);

#endif  // LUZER_METRICS_H_
