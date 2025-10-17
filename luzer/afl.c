/*
 * SPDX-License-Identifier: MIT
 *
 * Copyright © 2020, Steven Johnstone
 * Copyright © 2025, Sergey Bronnikov
 */

#include <stdlib.h>

int
is_afl_running(void)
{
	if (getenv("AFL_LUA_IS_RUNNING"))
		return 0;
	return -1;
}
