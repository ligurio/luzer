#ifndef LUZER_MACROS_H_
#define LUZER_MACROS_H_

#include <assert.h>
#include <stdbool.h>

#define UNUSED(x) (void)(x)

#ifdef DEBUG
#define DEBUG_PRINT(...) do{ fprintf( stderr, __VA_ARGS__ ); } while( false )
#else
#define DEBUG_PRINT(...) do{ } while ( false )
#endif /* DEBUG */

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))
#define MAX(X, Y) (((X) > (Y)) ? (X) : (Y))

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

#define NO_SANITIZE_ADDRESS __attribute__((no_sanitize_address))

#ifdef __has_attribute
#if __has_attribute(no_sanitize)
#define NO_SANITIZE_MEMORY __attribute__((no_sanitize("memory")))
#else
#define NO_SANITIZE_MEMORY
#endif  // __has_attribute(no_sanitize)
#else
#define NO_SANITIZE_MEMORY
#endif  // __has_attribute

/*
 * NO_SANITIZE_COVERAGE disables coverage instrumentation for
 * selected functions via the function attribute
 * __attribute__((no_sanitize("coverage"))).
 * This attribute may not be supported by other compilers,
 * so it is used together with __has_feature(coverage_sanitizer).
 * See:
 *  - https://clang.llvm.org/docs/SanitizerCoverage.html#disabling-instrumentation-with-attribute-no-sanitize-coverage
 *  - https://clang.llvm.org/docs/LanguageExtensions.html#has-feature-and-has-extension
 *
 * Support of __has_feature(coverage_sanitizer) was added
 * in Clang 13 together with no_sanitize("coverage").
 * Prior versions of Clang support coverage instrumentation,
 * but cannot be queried for support by the preprocessor.
 */
#ifdef __has_feature
#if __has_feature(coverage_sanitizer)
#define NO_SANITIZE_COVERAGE __attribute__((no_sanitize("coverage")))
#else // __has_feature(coverage_sanitizer)
#warning "compiler does not support 'coverage_sanitizer' feature"
#warning "it still may have instrumentation, but no way to exclude
#warning "certain functions found"
#warning "if you proceed, your coverage may be polluted or broken"
#define NO_SANITIZE_COVERAGE
#endif // __has_feature(coverage_sanitizer)

#else // __has_feature
#warning "compiler does not provide __has_feature,"
#warning "can't check presence of 'coverage_sanitizer' feature"
#endif // __has_feature

#define NO_SANITIZE NO_SANITIZE_ADDRESS NO_SANITIZE_MEMORY NO_SANITIZE_COVERAGE

#endif  // LUZER_MACROS_H_
