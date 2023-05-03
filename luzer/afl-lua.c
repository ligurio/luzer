/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2020, Steven Johnstone
 *             2022-2023, Sergey Bronnikov
 */

#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <lua.h>
#include <lualib.h>
#include <lauxlib.h>

#include <sys/shm.h>
#include <sys/wait.h>

#define FUZZ_FUNCTION_NAME "luzer_test_one_input"

// The presence of this string is enough to allow AFL fuzz to run without
// using the env variable AFL_SKIP_BIN_CHECK.
const char *SHM_ENV = "__AFL_SHM_ID";
const char *NOFORK = "AFL_NO_FORKSRV";

const int afl_read_fd = 198;
const int afl_write_fd = afl_read_fd + 1;

static unsigned char *afl_shm;
static size_t afl_shm_size = 1 << 16;

static int shm_init(void) {
	const char *shm = getenv(SHM_ENV);
	if (!shm) {
		fprintf(stderr, "Please set %s environment variable.\n", SHM_ENV);
		return -1;
	}
	afl_shm = shmat(atoi(shm), NULL, 0);
	if (afl_shm == (void*) -1) {
		fprintf(stderr, "shmat() has failed (%s).\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int fork_write(int pid) {
	const int ok = (4 == write(afl_write_fd, &pid, 4));
	assert(ok);
	return 0;
}

static int fork_read(void) {
	void *buf = NULL;
	const int ok = (4 == read(afl_read_fd, &buf, 4));
	assert(ok);
	return 0;
}

static int fork_close(void) {
	close(afl_read_fd);
	close(afl_write_fd);
	return 0;
}

static int lua_run_target(lua_State *L) {
	if (lua_pcall(L, 0, 0, 0)) {
		abort();
	}
	return 0;
}

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

static void debug_hook(lua_State *L, lua_Debug *ar) {
	lua_getinfo(L, "Sl", ar);
	if (ar && ar->source && ar->currentline) {
		const unsigned int new_location = lhash(ar->source, ar->currentline) % afl_shm_size;
		afl_shm[current_location ^ new_location] += 1;
		current_location = new_location / 2;
	}
}

int main(int argc, const char **argv) {
	if (argc == 1) {
		fprintf(stderr, "Please pass arguments.\n");
		exit(1);
	}

	int rc = shm_init();
	if (rc != 0) {
		fprintf(stderr, "shm_init() failed.\n");
		exit(1);
	}

	const char *script_path = argv[1];
	if (access(script_path, F_OK) != 0) {
		fprintf(stderr, "File (%s) does not exist.\n", script_path);
		exit(1);
	}

	lua_State *L = luaL_newstate();
	if (L == NULL) {
		fprintf(stderr, "Lua initialization failed.\n");
		exit(1);
	}
	luaL_openlibs(L);
	lua_sethook(L, debug_hook, LUA_MASKLINE, 0);
	rc = luaL_dofile(L, script_path);
	if (rc != 0) {
		fprintf(stderr, "luaL_dofile() has failed.\n");
		exit(1);
	}

	/* lua_getglobal(L, FUZZ_FUNCTION_NAME); */
	/* if (lua_isfunction(L, -1) != 1) { */
	/* 	fprintf(stderr, "fuzz() is not a Lua function.\n"); */
	/* 	exit(1); */
	/* } */

	if (getenv(NOFORK)) {
		lua_run_target(L);
		return 0;
	}

	fork_write(0); // Let AFL know we're here.

	while (1) {
		fork_read();
		pid_t child = fork();
		if (child == 0) {
			fork_close();
			lua_run_target(L);
			return 0;
		}
		fork_write(child);
		int status = 0;
		rc = wait(&status);
		fork_write(status);
	}

	return 0;
}
