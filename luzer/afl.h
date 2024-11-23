#ifndef LUZER_AFL_LUA_H_
#define LUZER_AFL_LUA_H_

#define AFL_LUA_ENV "AFL_LUA_IS_RUNNING"

int is_afl_running(void);

int
is_afl_running(void)
{
	if (getenv(AFL_LUA_ENV))
		return 0;
	return -1;
}

#endif  // LUZER_AFL_LUA_H_
