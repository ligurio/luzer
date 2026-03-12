#ifndef LUZER_TRACER_AFL_H_
#define LUZER_TRACER_AFL_H_

#include "macros.h"

NO_SANITIZE int shm_init(const char *shm_env);
NO_SANITIZE int shm_deinit(void);
NO_SANITIZE void trace_afl(const unsigned int new_location);

#endif // LUZER_TRACER_AFL_H_
