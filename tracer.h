#ifndef LUZER_TRACER_H_
#define LUZER_TRACER_H_

void hook(lua_State *L, lua_Debug *ar);

struct PCTableEntry {
  void* pc;
  long flags;
};

// Sets the global number of counters.
// Must not be called after InitializeCountersWithLLVM is called.
// TODO(b/207008147): Expose this to Atheris users.
void SetMaxCounters(int max);

// Returns the maximum number of allocatable Atheris counters. If more than this
// many counters are reserved, Atheris reuses counters, lowering fuzz quality.
int GetMaxCounters();

// Returns a new counter index.
int ReserveCounter();
// Reserves a number of counters with contiguous indices, and returns the first
// index.
int ReserveCounters(int counters);

// Increments the counter at the given index. If more than the maximum number of
// counters has been reserved, reuse counters.
void IncrementCounter(int counter_index);

struct CounterAndPcTableRange {
	unsigned char* counters_start;
	unsigned char* counters_end;
	unsigned char* pctable_start;
	unsigned char* pctable_end;
};

// Returns pointers to a range of memory for counters and another for pctable.
// The intent is for this memory to be handed to Libfuzzer. It will only be
// deallocated by TestOnlyResetCounters. The size of the ranges is proportional
// to the number of counters reserved, unless no new counters were reserved or
// more than max_counters were already reserved, in which case returns nullptrs.
struct CounterAndPcTableRange AllocateCountersAndPcs();

// Resets counters' state to defaults. This is not safe for use with the actual
// fuzzer as, once fuzzing begins, the fuzzer is given access to the counters'
// memory. Unless you swapped out the fuzzer and know it will not access the
// previous counters and pctable entries again, you'll probably segfault.
void TestOnlyResetCounters();

#endif  // LUZER_TRACER_H_
