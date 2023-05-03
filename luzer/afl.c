/*
 * SPDX-License-Identifier: ISC
 *
 * Copyright (c) 2025, Sergey Bronnikov
 */

#include <stdlib.h>
#include "afl.h"

int
is_afl_running(void)
{
	if (getenv(AFL_LUA_ENV))
		return 0;
	return -1;
}
