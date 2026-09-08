#ifndef LUZER_COUNTERS_H_
#define LUZER_COUNTERS_H_

struct PCTableEntry {
	void* pc;
	long flags;
};

// Sets the global number of counters.
// Must not be called after allocate_counters_and_pcs is called.
void set_max_counters(size_t max);

// Returns the number of luzer counters. Indices at or beyond it are folded
// into range by increment_counter, so distinct locations may share a counter,
// lowering fuzz quality.
size_t get_max_counters(void);

// Increments the counter at the given index, folded modulo the maximum
// number of counters.
void increment_counter(size_t index);

typedef struct counter_and_pc_table_range {
	unsigned char* counters_start;
	unsigned char* counters_end;
	unsigned char* pctable_start;
	unsigned char* pctable_end;
} counter_and_pc_table_range;

// Returns pointers to a range of memory for counters and another for pctable.
// The intent is for this memory to be handed to Libfuzzer. It will only be
// deallocated by test_only_reset_counters. The first call returns the whole
// allocation, counters and PC table; every later call returns nullptrs.
counter_and_pc_table_range allocate_counters_and_pcs(void);

// Resets counters' state to defaults. This is not safe for use with the actual
// fuzzer as, once fuzzing begins, the fuzzer is given access to the counters'
// memory. Unless you swapped out the fuzzer and know it will not access the
// previous counters and pctable entries again, you'll probably segfault.
void test_only_reset_counters(void);

#endif  // LUZER_COUNTERS_H_
