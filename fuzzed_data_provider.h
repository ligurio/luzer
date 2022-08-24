#ifndef LUZER_FUZZED_DATA_PROVIDER_H_
#define LUZER_FUZZED_DATA_PROVIDER_H_

#include <assert.h>

/**
 * If control flow reaches the point of the unreachable(), the program is
 * undefined. It is useful in situations where the compiler cannot deduce
 * the unreachability of the code.
 */
#if __has_builtin(__builtin_unreachable) || defined(__GNUC__)
#  define unreachable() (assert(0), __builtin_unreachable())
#else
#  define unreachable() (assert(0))
#endif

int luaL_fuzzed_data_provider(lua_State *L);

#endif  // LUZER_FUZZED_DATA_PROVIDER_H_
