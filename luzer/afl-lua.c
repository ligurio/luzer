/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2020, Steven Johnstone
 * Copyright © 2025, Sergey Bronnikov
 */

#undef NDEBUG
#include <assert.h>
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/wait.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "afl.h"

/*
 * We will communicate with the AFL forkserver over two pipes with
 * file descriptors equal to 198 and 199 (these values are
 * hardcoded by AFL). AFL specifies that the 198 pipe is for
 * reading data from the forkserver, and 199 is for writing to it.
 */
#define FORKSRV_FD 198

/*
 * The presence of this string is enough to allow AFL fuzz to run
 * without using the environment variable AFL_SKIP_BIN_CHECK.
 */
const char *SHM_ENV = "__AFL_SHM_ID";
const char *NOFORK = "AFL_NO_FORKSRV";

const int afl_read_fd = FORKSRV_FD;
const int afl_write_fd = afl_read_fd + 1;

static unsigned char *afl_shm;
static size_t afl_shm_size = 1 << 16;

static int
shm_init(void) {
	const char *shm = getenv(SHM_ENV);
	if (!shm) {
		fprintf(stderr, "%s is not set.\n", SHM_ENV);
		return -1;
	}
	afl_shm = shmat(atoi(shm), NULL, 0);
	if (afl_shm == (void*) -1) {
		fprintf(stderr, "shmat() has failed (%s).\n", strerror(errno));
		return -1;
	}
	return 0;
}

static int
fork_write(int pid) {
	int buf_sz = 4;
	(void)buf_sz;
	assert(buf_sz == write(afl_write_fd, &pid, buf_sz));
	return 0;
}

static int
fork_read(void) {
	void *buf;
	(void)buf;
	int buf_sz = 4;
	(void)buf_sz;
	assert(buf_sz == read(afl_read_fd, &buf, buf_sz));
	return 0;
}

static int
fork_close(void) {
	close(afl_read_fd);
	close(afl_write_fd);
	return 0;
}

/**
 * From afl-python
 * https://github.com/jwilk/python-afl/blob/8df6bfefac5de78761254bf5d7724e0a52d254f5/afl.pyx#L74-L87
 */
#define LHASH_INIT       0x811C9DC5
#define LHASH_MAGIC_MULT 0x01000193
#define LHASH_NEXT(x)    h = ((h ^ (unsigned char)(x)) * LHASH_MAGIC_MULT)

static inline unsigned int
lhash(const char *key, size_t offset) {
       const char *const last = &key[strlen(key) - 1];
       uint32_t h = LHASH_INIT;
       while (key <= last)
               LHASH_NEXT(*key++);
       for (; offset != 0; offset >>= 8)
               LHASH_NEXT(offset);

       return h;
}

static unsigned int current_location;

static void
debug_hook(lua_State *L, lua_Debug *ar) {
       lua_getinfo(L, "Sl", ar);
       if (ar && ar->source && ar->currentline) {
               const unsigned int new_location =
                       lhash(ar->source, ar->currentline) % afl_shm_size;
               afl_shm[current_location ^ new_location] += 1;
               current_location = new_location / 2;
       }
}

int
main(int argc, const char **argv) {
	if (argc == 1) {
		fprintf(stderr, "afl-lua: missed arguments.\n");
		exit(EXIT_FAILURE);
	}

	int rc = shm_init();
	if (rc != 0) {
		fprintf(stderr, "afl-lua: shm_init() failed.\n");
		exit(EXIT_FAILURE);
	}

	setenv(AFL_LUA_ENV, "1", 0);

	const char *script_path = argv[1];
	if (access(script_path, F_OK) != 0) {
		fprintf(stderr, "afl-lua: file (%s) does not exist.\n", script_path);
		exit(EXIT_FAILURE);
	}

	lua_State *L = luaL_newstate();
	if (L == NULL) {
		fprintf(stderr, "afl-lua: Lua initialization failed.\n");
		exit(EXIT_FAILURE);
	}
	luaL_openlibs(L);
	lua_sethook(L, debug_hook, LUA_MASKLINE, 0);

	if (getenv(NOFORK)) {
		rc = luaL_dofile(L, script_path);
		if (rc != 0) {
			const char *err_str = lua_tostring(L, 1);
			fprintf(stderr, "afl-lua: %s\n", err_str);
			lua_pop(L, 1);
			exit(EXIT_FAILURE);
		}
		return EXIT_SUCCESS;
	}

	/* Let AFL know we're here. */
	fork_write(0);

	while (1) {
		fork_read();
		pid_t child = fork();
		if (child == 0) {
			fork_close();
			rc = luaL_dofile(L, script_path);
			if (rc != 0) {
				const char *err_str = lua_tostring(L, 1);
				fprintf(stderr, "afl-lua: %s\n", err_str);
				lua_pop(L, 1);
				abort();
			}
			return EXIT_SUCCESS;
		}
		fork_write(child);
		int status = 0;
		rc = wait(&status);
		if (rc == -1) {
			perror("afl-lua");
			abort();
		}
		fork_write(status);
	}

	return EXIT_SUCCESS;
}
