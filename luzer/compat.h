#ifndef LUZER_COMPAT_H_
#define LUZER_COMPAT_H_

#if !defined(LUA_VERSION_NUM) || (LUA_VERSION_NUM == 501 && !defined(IS_LUAJIT))

void luaL_traceback(lua_State *L, lua_State *L1,
					const char *msg, int level);

#endif

#endif  // LUZER_COMPAT_H_
