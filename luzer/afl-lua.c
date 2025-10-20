/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright (c) 2020, Steven Johnstone
 * Copyright (c) 2025, Sergey Bronnikov
 */

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

#include <sys/shm.h>
#include <sys/wait.h>

#include "lua.h"
#include "lualib.h"
#include "lauxlib.h"

#include "afl.h"
#include "tracer.h"
#include "tracer_afl.h"

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
static const char *SHM_ENV = "__AFL_SHM_ID";
static const char *NOFORK = "AFL_NO_FORKSRV";

static const int afl_read_fd = FORKSRV_FD;
static const int afl_write_fd = afl_read_fd + 1;

static void
fork_write(int pid) {
	int buf_sz = 4;
	if (buf_sz != write(afl_write_fd, &pid, buf_sz)) {
		perror("write");
		abort();
	}
}

static void
fork_read(void) {
	void *buf;
	int buf_sz = 4;
	if (buf_sz != read(afl_read_fd, &buf, buf_sz)) {
		perror("read");
		abort();
	}
}

static int
fork_close(void) {
	close(afl_read_fd);
	close(afl_write_fd);
	return 0;
}

int
main(int argc, const char **argv) {
	if (argc == 1) {
		fprintf(stderr, "afl-lua: missed arguments\n");
		exit(EXIT_FAILURE);
	}

	int rc = shm_init(SHM_ENV);
	if (rc != 0) {
		fprintf(stderr, "afl-lua: shm_init() failed\n");
		exit(EXIT_FAILURE);
	}

	/* Let luzer library know we're in AFL mode. */
	setenv(AFL_LUA_ENV, "1", 0);

	const char *script_path = argv[1];
	if (access(script_path, F_OK) != 0) {
		fprintf(stderr, "afl-lua: file (%s) does not exist\n", script_path);
		exit(EXIT_FAILURE);
	}

	lua_State *L = luaL_newstate();
	if (L == NULL) {
		fprintf(stderr, "afl-lua: Lua initialization failed\n");
		exit(EXIT_FAILURE);
	}

	luaL_openlibs(L);
	lua_sethook(L, debug_hook, LUA_MASKLINE, 0);

	/*
	 * "NOFORK" is used to run AFL in persistent mode, which is
	 * an alternative to the default fork server, allowing the
	 * fuzzer to run the target program repeatedly in a single
	 * process without creating a new one each time.
	 */
	if (getenv(NOFORK)) {
		rc = luaL_dofile(L, script_path);
		if (rc != 0) {
			const char *err_str = lua_tostring(L, 1);
			fprintf(stderr, "afl-lua: %s\n", err_str);
			lua_pop(L, 1);
			exit(EXIT_FAILURE);
		}
		shm_deinit();
		return EXIT_SUCCESS;
	}

	/* Let AFL know we're here. */
	fork_write(0);

	while (1) {
		fork_read();
		pid_t child = fork();
		if (child == 0) {
			fork_close();
			/* Loads a script that executes `luzer.Fuzz()`. */
			rc = luaL_dofile(L, script_path);
			if (rc != 0) {
				const char *err_str = lua_tostring(L, 1);
				fprintf(stderr, "afl-lua: %s\n", err_str);
				lua_pop(L, 1);
				/*
				 * AFL detects a crash by recognizing that a
				 * program terminates due to a signal, such as
				 * SIGSEGV (segmentation fault) or SIGABRT (abort).
				 */
				abort();
			}
			return EXIT_SUCCESS;
		}
		fork_write(child);
		int status = 0;
		rc = wait(&status);
		if (rc == -1) {
			perror("wait");
			/*
			 * AFL detects a crash by recognizing that a
			 * program terminates due to a signal, such as
			 * SIGSEGV (segmentation fault) or SIGABRT (abort).
			 */
			abort();
		}
		fork_write(status);
	}
	lua_sethook(L, debug_hook, 0, 0);
	lua_close(L);
	shm_deinit();

	return EXIT_SUCCESS;
}
