#include <lua.h>
#include <lauxlib.h>
#include <lualib.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

//#include "counters.h"

/* TODO void __sanitizer_cov_trace_pc()
__sanitizer_cov_trace_basic_block
*/

#include <sys/mman.h>

//#include <iostream>

#include "macros.h"

#include <stdint.h>
#include <stdio.h>
#include <sanitizer/coverage_interface.h>

// This callback is inserted by the compiler as a module constructor
// into every DSO. 'start' and 'stop' correspond to the
// beginning and end of the section with the guards for the entire
// binary (executable or DSO). The callback will be called at least
// once per DSO and may be called multiple times with the same parameters.
#ifdef __cplusplus
extern "C" {
#endif
/*
void __sanitizer_cov_trace_pc_guard_init(uint32_t *start, uint32_t *stop) {
  static uint64_t N;  // Counter for the guards.
  if (start == stop || *start) return;  // Initialize only once.
  //printf("INIT: %p %p\n", start, stop);
  for (uint32_t *x = start; x < stop; x++)
    *x = ++N;  // Guards should start from 1.
}
*/
#ifdef __cplusplus
} /* extern "C" */
#endif


// This callback is inserted by the compiler on every edge in the
// control flow (some optimizations apply).
// Typically, the compiler will emit the code like this:
//    if(*guard)
//      __sanitizer_cov_trace_pc_guard(guard);
// But for large functions it will emit a simple call:
//    __sanitizer_cov_trace_pc_guard(guard);
#ifdef __cplusplus
extern "C" {
#endif
	//int __sanitizer_cov_trace_basic_block();
/*
void __sanitizer_cov_trace_pc_guard(uint32_t *guard) {
  if (!*guard) return;  // Duplicate the guard check.
  // If you set *guard to 0 this code will not be called again for this edge.
  // Now you can get the PC and do whatever you want:
  //   store it somewhere or symbolize it and print right away.
  // The values of `*guard` are as you set them in
  // __sanitizer_cov_trace_pc_guard_init and so you can make them consecutive
  // and use them to dereference an array or a bit vector.
  void *PC = __builtin_return_address(0);
  char PcDescr[1024];
  // This function is a part of the sanitizer run-time.
  // To use it, link with AddressSanitizer or other sanitizer.
  __sanitizer_symbolize_pc(PC, "%p %F %L", PcDescr, sizeof(PcDescr));
  //printf("guard: %p %x PC %s\n", guard, *guard, PcDescr);
}
*/
#ifdef __cplusplus
} /* extern "C" */
#endif

int __sanitizer_cov_trace_basic_block(int id) {
	//printf("XXX");
	return id;
}

/*
extern "C" {
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);
}
*/

/*
void __sanitizer_cov_trace_pc()
{
	printf("0xAAAA\n");
	//printf("0x%lx\n", __builtin_return_address(0) - 5);
}
*/

/* https://clang.llvm.org/docs/SanitizerCoverage.html
 * https://chromium.googlesource.com/chromiumos/third_party/compiler-rt/+/google/stable/include/sanitizer/common_interface_defs.h
 * https://github.com/llvm-mirror/llvm/blob/master/lib/Transforms/Instrumentation/SanitizerCoverage.cpp
 */

void __sanitizer_cov_trace_const_cmp8(uint64_t arg1, uint64_t arg2);
void __sanitizer_cov_trace_cmp8(uint64_t arg1, uint64_t arg2);
void __sanitizer_weak_hook_memcmp(void* caller_pc, const void* s1,
                                  const void* s2, size_t n, int result);

/* Users need to implement a single function to capture the counters at startup. */
void __sanitizer_cov_8bit_counters_init(uint8_t* start, uint8_t* stop);
/* Users need to implement a single function to capture the PC table at startup. */
void __sanitizer_cov_pcs_init(uint8_t* pcs_beg, uint8_t* pcs_end);

/*
 * jazzer
 */
/*
inline void __attribute__((always_inline)) RecordCoverage() {
  auto return_address =
      reinterpret_cast<uintptr_t>(__builtin_return_address(0));
  auto idx = return_address & (gCoverageMap.size() - 1);
  gCoverageMap[idx]++;
}
*/

/**
 * From afl-python
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */

#define LHASH_INIT       0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x)    h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

static inline unsigned int lhash(const char *key, size_t offset) {
    const char *const last = &key[strlen(key) - 1];
    uint32_t h = LHASH_INIT;
    while (key <= last)               LHASH_NEXT(*key++);
    for (; offset != 0; offset >>= 8) LHASH_NEXT(offset);
    return h;
}

static unsigned int current_location;

/*
 * see trash/atheris/src/native/tracer.cc
 */
void hook(lua_State *L, lua_Debug *ar) {
	// SKIP? info.what == "C" then   -- is a C function?
    lua_getinfo(L, "Sl", ar);
    if (ar && ar->source && ar->currentline) {
        //const unsigned int new_location = lhash(ar->source, ar->currentline) % afl_shm_size;
        const unsigned int new_location = lhash(ar->source, ar->currentline);
        //afl_shm[current_location ^ new_location] += 1;
        current_location = new_location / 2;
    }
	//printf("%d0\n", ar->linedefined);
    __sanitizer_cov_trace_cmp8(1, 2);
	//__sanitizer_cov_trace_pc();
	__sanitizer_cov_trace_basic_block(current_location);
}

// https://stackoverflow.com/questions/12256455/print-stacktrace-from-c-code-with-embedded-lua
/*
static int traceback(lua_State *L) {
  if (!lua_isstring(L, 1))  // 'message' not a string?
    return 1;  // keep it intact
  lua_getglobal(L, "debug");
  if (!lua_istable(L, -1)) {
    lua_pop(L, 1);
    return 1;
  }
  lua_getfield(L, -1, "traceback");
  if (!lua_isfunction(L, -1)) {
    lua_pop(L, 2);
    return 1;
  }
  lua_pushvalue(L, 1);  // pass error message
  lua_pushinteger(L, 2);  // skip this function and traceback
  lua_call(L, 2, 1);  // call debug.traceback
  return 1;
}
*/

// lua_pushcfunction(L, traceback1);
/*
static int traceback1(lua_State *L) {
    lua_getglobal(L, "debug");
    lua_getfield(L, -1, "traceback");
    lua_pushvalue(L, 1);
    lua_pushinteger(L, 2);
    lua_call(L, 2, 1);
    fprintf(stderr, "%s\n", lua_tostring(L, -1));
    return 1;
}

static int traceback2(lua_State *L) {
    lua_getglobal(L, "debug");
    lua_getfield(L, -1, "traceback");
    //---------------------------
    lua_pop(L, -2); // to popup the 'debug'
    //---------------------------
    lua_pushvalue(L, 1);
    lua_pushinteger(L, 2);
    lua_call(L, 2, 1);
    fprintf(stderr, "%s\n", lua_tostring(L, -1));
    return 1;
}
*/

const int kDefaultNumCounters = 1 << 20;

// Number of counters requested by Python instrumentation.
int counter_index = 0;
// Number of counters given to Libfuzzer.
int counter_index_registered = 0;
// Maximum number of counters and pctable entries that may be reserved and also
// the number that are allocated.
int max_counters = 0;
// Counter Allocations. These are allocated once, before __sanitize_... are
// called and can only be deallocated by TestOnlyResetCounters.
unsigned char* counters = NULL;
struct PCTableEntry* pctable = NULL;

NO_SANITIZE
void TestOnlyResetCounters() {
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

NO_SANITIZE
int ReserveCounters(int counters) {
  int ret = counter_index;
  counter_index += counters;
  return ret;
}

NO_SANITIZE
int ReserveCounter() { return counter_index++; }

NO_SANITIZE
void IncrementCounter(int counter_index) {
  if (counters != NULL && pctable != NULL) {
    // `counters` is an allocation of length `max_counters`. If we reserve more
    // than the allocated number of counters, we'll wrap around and overload
    // old counters, trading away fuzzing quality for limits on memory usage.
    counters[counter_index % max_counters]++;
  }
}

NO_SANITIZE
void SetMaxCounters(int max) {
  if (counters != NULL && pctable != NULL) {
    printf("Atheris internal error: Tried to set max counters after \
            counters were passed to the sanitizer!\n");
    exit(1);
  }
  if (max < 1) exit(1);
  max_counters = max;
}

NO_SANITIZE
int GetMaxCounters() { return max_counters; }

/*
NO_SANITIZE
CounterAndPcTableRange AllocateCountersAndPcs() {
  if (max_counters < 1) {
    SetMaxCounters(kDefaultNumCounters);
  }
  if (counter_index < counter_index_registered) {
    printf("Atheris internal fatal logic error: The counter index is \
           greater than the number of counters registered.\n");
    exit(1);
  }
  // Allocate memory.
  if (counters == NULL || pctable == NULL) {
    // We mmap memory for pctable and counters, instead of std::vector, ensuring
    // that there is no initialization. The untouched memory will only cost
    // virtual memory, which is cheap.
    counters = static_cast<unsigned char*>(
        mmap(NULL, max_counters, PROT_READ | PROT_WRITE,
             MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    pctable = static_cast<PCTableEntry*>(
        mmap(NULL, max_counters * sizeof(PCTableEntry),
             PROT_READ | PROT_WRITE, MAP_ANONYMOUS | MAP_PRIVATE, -1, 0));
    if (counters == MAP_FAILED || pctable == MAP_FAILED) {
      std::cerr << "Atheris internal error: Failed to mmap counters.\n";
      exit(1);
    }
  }

  const int next_index = std::min(counter_index, max_counters);
  if (counter_index_registered >= next_index) {
    // There are no counters to pass. Perhaps because we've reserved more than
    // max_counters, or because no counters have been reserved since this was
    // last called.
    counter_index_registered = counter_index;
    return CounterAndPcTableRange{NULL, NULL, NULL, NULL};
  } else {
    CounterAndPcTableRange ranges = {
        .counters_start = counters + counter_index_registered,
        .counters_end = counters + next_index,
        .pctable_start =
            reinterpret_cast<uint8_t*>(pctable + counter_index_registered),
        .pctable_end = reinterpret_cast<uint8_t*>(pctable + next_index)};
    counter_index_registered = counter_index;
    return ranges;
  }
}
*/
