/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2025, Sergey Bronnikov
 */

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <unistd.h>
#include <sys/mman.h>

#include "counters.h"
#include "macros.h"

#ifdef __cplusplus
extern "C" {
#endif
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);
#ifdef __cplusplus
} /* extern "C" */
#endif

static const size_t kDefaultNumCounters = 1 << 20;

// Number of counters and pctable entries that are allocated. Counter indices
// are folded into this range by increment_counter.
size_t max_counters = 0;
// Counter Allocations. These are allocated once, before __sanitize_... are
// called and can only be deallocated by test_only_reset_counters.
unsigned char* counters = NULL;
struct PCTableEntry* pctable = NULL;

NO_SANITIZE void
test_only_reset_counters(void) {
	if (counters) {
		munmap(counters, max_counters);
		counters = NULL;
	}
	if (pctable) {
		munmap(pctable, max_counters * sizeof(struct PCTableEntry));
		pctable = NULL;
	}
	max_counters = 0;
}

NO_SANITIZE void
increment_counter(size_t index)
{
	if (counters != NULL && pctable != NULL) {
		// `counters` is an allocation of length `max_counters`. The index is a
		// hash of source:line from the debug hook, so it is folded into range
		// here; distinct lines may collide, trading resolution for a fixed
		// memory ceiling.
		counters[index % max_counters]++;
	}
}

NO_SANITIZE void
set_max_counters(size_t max)
{
	if (counters != NULL && pctable != NULL) {
		fprintf(stderr, "Internal error: attempt to set max number of counters after "
						"counters were passed to the sanitizer!\n");
		_exit(1);
	}
	if (max < 1)
		_exit(1);

	max_counters = max;
}

NO_SANITIZE size_t
get_max_counters(void)
{
	return max_counters;
}

NO_SANITIZE counter_and_pc_table_range
allocate_counters_and_pcs(void) {
	if (max_counters < 1) {
		set_max_counters(kDefaultNumCounters);
	}
	if (counters != NULL && pctable != NULL) {
		// The allocation was handed to libFuzzer on an earlier call.
		return (counter_and_pc_table_range){NULL, NULL, NULL, NULL};
	}
	// We mmap memory for pctable and counters, instead of std::vector, ensuring
	// that there is no initialization. The untouched memory will only cost
	// virtual memory, which is cheap.
	counters = (unsigned char*)(
		mmap(NULL, max_counters, PROT_READ | PROT_WRITE,
			 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
	if (counters == MAP_FAILED) {
		fprintf(stderr, "Internal error: Failed to mmap counters.\n");
		_exit(1);
	}
	pctable = (struct PCTableEntry*)(
		mmap(NULL, max_counters * sizeof(struct PCTableEntry),
			 PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
	if (pctable == MAP_FAILED) {
		fprintf(stderr, "Internal error: Failed to mmap the PC table.\n");
		munmap(counters, max_counters);
		counters = NULL;
		_exit(1);
	}

	// The debug hook addresses counters by a hash of source:line, so every
	// bucket is live from the first execution: there is no reservation phase
	// whose growth a registered range could follow. The whole allocation is
	// handed to libFuzzer at once.
	//
	// The PC table goes with it. libFuzzer maps counters to PCs (the `cov:`
	// statistic, -print_pcs, -print_funcs, -print_coverage) only while the
	// number of registered counters equals the number of registered PC
	// entries across all modules; registering counters alone would switch
	// that off for native modules too. Lua lines have no machine address, so
	// the entries stay zero, PC 0 with no function-entry flag, as in Atheris.
	// They are never written, so the table costs virtual memory only. Since
	// every PC is zero, those reports cannot name Lua source lines; the
	// fuzzer is guided by the counter values alone.
	return (counter_and_pc_table_range){
		.counters_start = counters,
		.counters_end = counters + max_counters,
		.pctable_start = (unsigned char*)pctable,
		.pctable_end = (unsigned char*)(pctable + max_counters)
	};
}
