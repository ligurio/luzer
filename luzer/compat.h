#ifndef LUZER_COMPAT_H_
#define LUZER_COMPAT_H_

void luaL_traceback(lua_State *L, lua_State *L1,
					const char *msg, int level);

#endif  // LUZER_COMPAT_H_
