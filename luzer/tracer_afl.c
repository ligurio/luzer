/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2020, Steven Johnstone
 * Copyright (c) 2025, Sergey Bronnikov
 */

#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <sys/shm.h>

#include "afl.h"
#include "macros.h"

unsigned char *afl_shm;
size_t afl_shm_size = 1 << 16;

static unsigned int current_location;

NO_SANITIZE int
shm_init(const char *shm_env) {
	const char *shm = getenv(shm_env);
	if (!shm) {
		fprintf(stderr, "afl-lua: env variable %s is not set\n", shm_env);
		return -1;
	}
	afl_shm = shmat(atoi(shm), NULL, 0);
	if (afl_shm == (void *) -1) {
		perror("shmat");
		fprintf(stderr, "afl-lua: shmat() has failed (%s)\n", strerror(errno));
		return -1;
	}
	return 0;
}

NO_SANITIZE int
shm_deinit(void) {
	int rc = shmdt(afl_shm);
	if (rc != 0) {
		perror("shmdt");
	}
	return rc;
}

NO_SANITIZE void
trace_afl(const unsigned int new_location) {
	const unsigned int new_loc = new_location % afl_shm_size;
	afl_shm[current_location ^ new_loc] += 1;
	current_location = new_loc / 2;
}
