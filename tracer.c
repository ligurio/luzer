#include <stddef.h>
#include <stdint.h>

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

/**
 * From afl-python
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */
/*
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

static void hook(lua_State *L, lua_Debug *ar) {
    lua_getinfo(L, "Sl", ar);
    if (ar && ar->source && ar->currentline) {
        const unsigned int new_location = lhash(ar->source, ar->currentline) % afl_shm_size;
        afl_shm[current_location ^ new_location] += 1;
        current_location = new_location / 2;
    }
}

    luaL_openlibs(L);
    lua_sethook(L, hook, LUA_MASKLINE, 0);
*/
