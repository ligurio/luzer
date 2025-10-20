#ifndef LUZER_TRACER_LIBFUZZER_H_
#define LUZER_TRACER_LIBFUZZER_H_

#include <stdint.h>
#include "macros.h"

NO_SANITIZE void trace_libfuzzer(uint64_t idx);

#endif // LUZER_TRACER_LIBFUZZER_H_
