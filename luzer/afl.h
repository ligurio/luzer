#ifndef LUZER_AFL_LUA_H_
#define LUZER_AFL_LUA_H_

#include <lua.h>

int luaL_run_afl(lua_State *L);

int is_afl_running(void);

#endif  // LUZER_AFL_LUA_H_
