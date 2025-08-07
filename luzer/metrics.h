#ifndef LUZER_METRICS_H_
#define LUZER_METRICS_H_

#include <stdbool.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

struct metrics {
	/* Per test run. */
	size_t total_num;
	size_t jit_trace_record;
	size_t jit_trace_abort;
	size_t jit_trace_start;
	size_t jit_trace_stop;
	size_t bc_num;
	size_t texit_num;

	/* Per test sample. */
	bool is_trace_abort;
	bool is_trace_start;
	bool is_trace_stop;
	bool is_trace_record;
	bool is_bc;
	bool is_texit;
};

void
metrics_enable(lua_State *L);

void
metrics_disable(lua_State *L);

void
metrics_print(void);

void
metrics_increment_num_samples(void);

#endif  // LUZER_METRICS_H_
