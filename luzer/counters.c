/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright 2022-2023, Sergey Bronnikov
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

// Number of counters requested by Lua instrumentation.
size_t counter_index = 0;
// Number of counters given to Libfuzzer.
size_t counter_index_registered = 0;
// Maximum number of counters and pctable entries that may be reserved and also
// the number that are allocated.
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
		munmap(pctable, max_counters);
		pctable = NULL;
	}
	max_counters = 0;
	counter_index = 0;
	counter_index_registered = 0;
}

NO_SANITIZE size_t
reserve_counters(size_t amount) {
	int ret = counter_index;
	counter_index += amount;
	return ret;
}

NO_SANITIZE size_t
reserve_counter(void)
{
	return counter_index++;
}

NO_SANITIZE void
increment_counter(size_t index)
{
	if (counters != NULL) {
		// Global array `counters` is an allocation of length `max_counters`.
                // But we use only registered amount of them.
                // If we reserve more than the allocated number of counters, we'll wrap
                // around and overload old counters, trading away fuzzing quality
                // for limits on memory usage.
		counters[index % counter_index_registered]++;
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
	if (counter_index < counter_index_registered) {
		fprintf(stderr, "Internal error: The counter index is "
						"greater than the number of counters registered.\n");
		_exit(1);
	}
	// Allocate memory.
	if (counters == NULL || pctable == NULL) {
		// We mmap memory for pctable and counters, instead of std::vector, ensuring
		// that there is no initialization. The untouched memory will only cost
		// virtual memory, which is cheap.
		counters = (unsigned char*)(
			mmap(NULL, max_counters, PROT_READ | PROT_WRITE,
				 MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
			pctable = (struct PCTableEntry*)(
					  mmap(NULL, max_counters * sizeof(struct PCTableEntry),
						   PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
		if (counters == MAP_FAILED || pctable == MAP_FAILED) {
			fprintf(stderr, "Internal error: Failed to mmap counters.\n");
			_exit(1);
		}
	}

	const size_t next_index = MIN(counter_index, max_counters);
	if (counter_index_registered >= next_index) {
		// There are no counters to pass. Perhaps because we've reserved more than
		// max_counters, or because no counters have been reserved since this was
		// last called.
		counter_index_registered = counter_index;
		return (counter_and_pc_table_range){NULL, NULL, NULL, NULL};
	} else {
		counter_and_pc_table_range ranges = {
			.counters_start = counters + counter_index_registered,
			.counters_end = counters + next_index,
			.pctable_start = (uint8_t*)(pctable + counter_index_registered),
			.pctable_end = (uint8_t*)(pctable + next_index)
		};
		counter_index_registered = counter_index;
		return ranges;
	}
}
