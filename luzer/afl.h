#ifndef LUZER_AFL_LUA_H_
#define LUZER_AFL_LUA_H_

#define AFL_LUA_ENV "AFL_LUA_IS_RUNNING"
#define AFL_LUA_MAXINPUT 512

int is_afl_running(void);

#endif  // LUZER_AFL_LUA_H_
