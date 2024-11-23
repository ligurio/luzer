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
#include <lauxlib.h>

int
is_afl_running(void)
{
	if (getenv("AFL_LUA_IS_RUNNING"))
		return 0;
	return -1;
}
