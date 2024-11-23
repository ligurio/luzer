/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2020, Steven Johnstone
 *             2022-2024, Sergey Bronnikov
 */

#include <assert.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>

#include <lua.h>

#define AFL_LUA_FUNCTION_NAME "TestOneInput"

/*
 * We will communicate with the AFL forkserver over two pipes with
 * file descriptors of 198 and 199 (these values are hardcoded by
 * AFL). AFL specifies that the 198 pipe is for reading data from
 * the forkserver, and 199 is for writing to it.
 */
#define FORKSRV_FD 198

/*
 * The presence of this string is enough to allow AFL fuzz to run
 * without using the environment variable AFL_SKIP_BIN_CHECK.
 */
const char *NOFORK = "AFL_NO_FORKSRV";

const int afl_read_fd = FORKSRV_FD;
/* const int afl_write_fd = afl_read_fd + 1; */

int
is_afl_running(void)
{
	if ((getenv("AFL_LUA_IS_RUNNING")) ||
	    (getenv("AFL_NO_FORKSRV")))
		return 0;
	if (fcntl(afl_read_fd, F_GETFL) < 0 && errno == EBADF)
		return 1;
	return 0;
}

#define TEST_ONE_INPUT_FUNC "luzer_test_one_input"

int
luaL_run_afl(lua_State *L) {
	lua_getglobal(L, TEST_ONE_INPUT_FUNC);
	assert(lua_isfunction(L, -1) == 1);

	lua_insert(L, -2);
	lua_call(L, 1, 1);

	int rc = 0;
	if (lua_isnumber(L, 1) == 1)
		rc = lua_tonumber(L, 1);
	lua_settop(L, 0);

	return rc;
}
