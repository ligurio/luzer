#include <stdint.h>
#include <stddef.h>

#include "counters.h"
#include "macros.h"

NO_SANITIZE void
trace_libfuzzer(uint64_t idx)
{
	increment_counter(idx);
}
