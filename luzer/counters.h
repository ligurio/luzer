#ifndef LUZER_COUNTERS_H_
#define LUZER_COUNTERS_H_
#include <stddef.h>

struct PCTableEntry {
	void* pc;
	long flags;
};

// Sets the global number of counters.
// Must not be called after InitializeCountersWithLLVM is called.
void set_max_counters(size_t max);

// Returns the maximum number of allocatable luzer counters. If more than this
// many counters are reserved, luzer reuses counters, lowering fuzz quality.
size_t get_max_counters(void);

// Returns a new counter index.
size_t reserve_counter(void);
// Reserves a number of counters with contiguous indices, and returns the first
// index.
size_t reserve_counters(size_t amount);

// Increments a counter at the given index. If more than the maximum number of
// counters has been reserved, reuse counters.
void increment_counter(size_t index);

typedef struct counter_and_pc_table_range {
	unsigned char* counters_start;
	unsigned char* counters_end;
	unsigned char* pctable_start;
	unsigned char* pctable_end;
} counter_and_pc_table_range;

// Returns pointers to a range of memory for counters and another for pctable.
// The intent is for this memory to be handed to Libfuzzer. It will only be
// deallocated by test_only_reset_counters. The size of the ranges is proportional
// to the number of counters reserved, unless no new counters were reserved or
// more than max_counters were already reserved, in which case returns nullptrs.
counter_and_pc_table_range allocate_counters_and_pcs(void);

// Resets counters' state to defaults. This is not safe for use with the actual
// fuzzer as, once fuzzing begins, the fuzzer is given access to the counters'
// memory. Unless you swapped out the fuzzer and know it will not access the
// previous counters and pctable entries again, you'll probably segfault.
void test_only_reset_counters(void);

#endif  // LUZER_COUNTERS_H_
