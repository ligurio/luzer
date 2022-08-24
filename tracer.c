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
